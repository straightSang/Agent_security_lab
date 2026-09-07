# 모듈이름: runtime
# 역할: 유일한 실행 경계. 도구 제안이 실제 동작으로 바뀌는 단 하나의 지점
# 호출 주체: agent.py(진입점), tests/(실험 하니스)
#
# 기능 설명:
#     도구가 실행되려면 여섯 단계를 순서대로 모두 통과해야 한다. 어느 하나라도
#     거부하면 _dispatch()에 도달하지 못한다.
#
#         LLM tool proposal
#            |
#            +-- 0. MCP schema gate   노출 여부 + 인자 인터페이스 (문자열만 본다)
#            +-- 1. validation        문자열을 실체로 변환 (파일시스템에 물어본다)
#            +-- 2. ToolIntent 생성   서버가 capability/action/resource를 계산
#            +-- 3. Policy            trust·민감 리소스·범위 규칙
#            +-- 4. Authorization     이 actor가 이 리소스의 소유자·멤버인가
#            +-- 5. Approval          위험 행동에 유효한 1회용 승인이 있는가
#            |
#            +-- 6. _dispatch()       유일한 실행 지점
#
#     순서 자체가 인터페이스다. 각 단계는 앞 단계가 통과했을 때만 호출되며, 실험은
#     이 순서를 mock으로 계측해 "Policy DENY 뒤 Authorization이 0회 호출됐다"를
#     증명한다. 정책을 완화해야 하면 security/permission.py의 POLICY를 고친다.
#     _dispatch()나 execute_tool()에 if 예외를 넣는 순간 그 예외는 감사 불가능한
#     우회 경로가 된다.

from __future__ import annotations

import ast
import operator
import shlex
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from security.approval import ApprovalStore
from security.authorization import AuthorizationEngine
from security.capability import describe_intent
from security.policy import PolicyEngine
from security.provenance import Provenance
from security.tool_schema import MCP_TOOL_CATALOG, ToolProfile, validate_tool_schema
from security.types import (
    ApprovalState,
    ApprovalStatus,
    AuthorizationOutcome,
    Decision,
    RuntimeResult,
    ToolIntent,
)
from trace_logger import TraceLogger

PATH_TOOLS = {"read_file", "write_file", "list_files"}

# [계층 분리] 도구 목록의 단일 기준은 MCP schema gate이다.
#
# 이전에는 ARGUMENT_SPEC이라는 두 번째 도구 목록(validation의 중복검사로 인한)이 여기 있었고, 인자의
# 이름·타입·필수·초과를 schema gate와 똑같이 검사했다. 같은 질문에 두 곳이
# 답하면 둘이 어긋나는 순간 도달 불가 분기가 생긴다(A-01과 같은 유형의 결함).
#
# 이제 인자 인터페이스 검사는 schema gate 하나만 한다. 이 단계는 '인터페이스가 맞는가'가
# 아니라 '사용자의 모델이 쓸 수 있는 도구인가'만 확인한다.
# 즉, MCP 서버에서 해당 사용자에게 제공한 TOOL 목록에 있는 도구를 LLM이 요청한 게 맞는지 확인하는 과정이다. 두 질문의 차이는 아래
# _require_text_argument()의 주석에 적었다.
KNOWN_TOOLS = frozenset(MCP_TOOL_CATALOG)


# 함수이름: to_observation
# 인자:
#     runtime_result (Mapping): execute_tool()이 돌려준 결과 dict
# 반환값:
#     dict: 성공이면 {'status': 'success', 'data': ...},
#         실패면 {'status': ..., 'error': {'code', 'message'}}
# 기능 설명:
#     Runtime의 내부 상태와 LLM에게 보여 줄 관측값을 분리한다.
#
#     RuntimeResult에는 approval_id, schema digest 같은 보안 메타데이터가 들어
#     있다. 그대로 넘기면 내부 상태가 '모델이 본 것'이 되어 신뢰 경계가 흐려진다.
#     모델에게는 결과와 오류 코드만 준다.
def to_observation(runtime_result: Mapping[str, Any]) -> dict[str, Any]:
    if runtime_result["ok"]:
        return {"status": "success", "data": runtime_result["data"]}
    return {
        "status": runtime_result["status"],
        "error": {
            "code": runtime_result.get("error", {}).get("code"),
            "message": runtime_result.get("error", {}).get("message"),
        },
    }


# 함수이름: safe_resolve
# 인자:
#     user_path (str): 도구 인자로 들어온 경로 문자열. 신뢰하지 않는다
#     sandbox_root (Path): 이 실행이 허용된 유일한 루트
# 반환값:
#     Path: sandbox 안으로 확정된 절대 경로
#     PermissionError: 정규화 결과가 sandbox 밖을 가리킬 때 발생
# 기능 설명:
#     경로를 정규화한 뒤 sandbox 안인지 확인한다.
#
#     '..' 문자열만 막으면 심볼릭 링크로 우회된다. resolve()가 링크를 따라간
#     실제 위치를 돌려주므로 그 결과에 relative_to()를 걸어야 한다. 절대 경로가
#     들어오면 pathlib의 '/' 연산이 왼쪽을 버리는데, 이 경우도 같은 검사에서
#     걸린다.
def safe_resolve(user_path: str, sandbox_root: Path) -> Path:
    candidate = (sandbox_root / user_path).resolve()
    try:
        candidate.relative_to(sandbox_root)
    except ValueError as exc:
        raise PermissionError(f"PATH_ESCAPES_SANDBOX:{user_path}") from exc
    return candidate


# 함수이름: _require_text_argument
# 인자:
#     arguments (Mapping): 도구 인자 묶음
#     name (str): 필요한 인자 이름
# 반환값:
#     tuple[str | None, str | None]: (값, 오류 코드). 둘 중 하나만 채워진다
# 기능 설명:
#     이 단계가 자기 일을 하는 데 꼭 필요한 값이 쓸 수 있는 형태인지만 본다.
#
#     [인터페이스 검사와 다른 점]
#     schema gate는 "모델이 약속한 형태를 지켰는가"를 판정한다. 필수 인자
#     누락, 타입 불일치, 선언되지 않은 인자, 길이 초과를 본다. 
#     
#   _require_text_argument()는 
#   “지금 이 검증 함수가 문자열을 전제로 계속 실행해도 되는가?”를 검사한다.
#
#     여기는 인터페이스를 검사하지 않는다. 경로를 정규화하려면 문자열 경로가 있어야
#     하는데 없으면 정규화 자체가 불가능하다. 그 최소 전제만 확인한다. 그래서
#     오류 코드도 '인터페이스 위반'이 아니라 '이 단계가 쓸 수 없는 값'이라는 뜻의
#     ..._UNUSABLE을 쓴다. trace에서 두 종류의 거부를 구별할 수 있어야 한다.
#
#     정상 경로에서는 schema gate가 먼저 걸러 내므로 이 함수의 오류 분기에는 도달하지
#     않는다. validate_tool_call()을 단독으로 부르는 단위 검사에서만 의미가
#     있으며, 그때도 조용히 통과시키지 않고 fail closed를 유지한다.
def _require_text_argument(arguments: Mapping[str, Any], name: str) -> tuple[str | None, str | None]:
    value = arguments.get(name)
    if not isinstance(value, str):
        return None, f"{name.upper()}_ARGUMENT_UNUSABLE"
    return value, None


# 함수이름: validate_tool_call
# 인자:
#     tool_name (str): 도구 이름
#     arguments (Mapping): 도구 인자 묶음
#     sandbox_root (Path | None): 경로 결속 기준. 기본값 None이면 './sandbox'
# 반환값:
#     dict: {'allowed', 'reason', 'resolved_path', 'command_base'}
#         resolved_path는 경로 도구, command_base는 run_command일 때만 채워진다
# 기능 설명:
#     [이 단계의 유일한 책임] 문자열 인자를 뒷단계가 쓸 수 있는 실체로 바꾼다.
#
#         "data/user-001/notes.txt"  ->  정규화된 절대 경로 (심볼릭 링크 추적)
#         "cat notes.txt"            ->  command_base='cat' + 정규화된 경로
#
#     그래서 이 단계는 검사이자 변환이다. resolved_path와 command_base는
#     capability 매핑과 Policy 범위 판정의 입력이 된다. schema gate는 아무것도
#     만들지 않고 문만 여닫는다는 점이 근본적으로 다르다.
#
#     [schema gate와의 역할 분리]
#
#         schema gate   문자열만 본다. 파일시스템을 만지지 않는다.
#                       '약속한 형태인가'를 판정한다.
#         validation    파일시스템에 물어본다. resolve()로 링크를 따라간다.
#                       '이 문자열이 실제로 무엇을 가리키는가'를 확정한다.
#
#     이 분리가 왜 중요한지는 심볼릭 링크가 보여 준다. sandbox 안의 링크가
#     밖을 가리키면 문자열에는 '..'도 절대 경로도 없다. schema gate는 통과
#     시키고, 여기서만 잡힌다. 반대로 미노출 도구나 길이 초과는 여기서 볼 수
#     없고 schema gate만 잡는다. 둘은 서로를 대체하지 못한다.
#
#     알 수 없는 명령을 여기서 거부하지 않는 이유는, 문법상 유효한 제안이기
#     때문이다. 허용 여부는 정책 판단이므로 PolicyEngine이 맡는다.
def validate_tool_call(tool_name: str, arguments: Mapping[str, Any], sandbox_root: Path | None = None) -> dict[str, Any]:
    def deny(reason: str, command_base: str | None = None) -> dict[str, Any]:
        return {"allowed": False, "reason": reason, "resolved_path": None, "command_base": command_base}

    def allow(resolved_path: Path | None = None, command_base: str | None = None) -> dict[str, Any]:
        return {"allowed": True, "reason": None, "resolved_path": resolved_path, "command_base": command_base}

    if not isinstance(arguments, Mapping):
        return deny("ARGUMENTS_MUST_BE_OBJECT")
    # 존재하지 않는 도구는 정규화할 대상 자체가 없다. fail closed를 유지한다.
    if tool_name not in KNOWN_TOOLS:
        return deny(f"UNKNOWN_TOOL:{tool_name}")

    root = (sandbox_root or Path("sandbox")).resolve()
    try:
        if tool_name in PATH_TOOLS:
            raw_path, error = _require_text_argument(arguments, "path")
            if error:
                return deny(error)
            return allow(resolved_path=safe_resolve(raw_path, root))

        if tool_name != "run_command":
            # calculator, get_time은 정규화할 경로도 명령도 없다.
            return allow()

        raw_command, error = _require_text_argument(arguments, "command")
        if error:
            return deny(error)

        # shlex.split()은 쉘처럼 보이는 문자열을 실제로 실행하지 않고, 문법적으로만 분리힌디.
        parts = shlex.split(raw_command, posix=True)
        if not parts:
            return deny("EMPTY_COMMAND")

        command_base = parts[0]
        if command_base == "pwd":
            if len(parts) != 1:
                return deny("COMMAND_USAGE:pwd", command_base)
            return allow(command_base=command_base)

        if command_base == "cat":
            if len(parts) != 2:
                return deny("COMMAND_USAGE:cat <file>", command_base)
            return allow(resolved_path=safe_resolve(parts[1], root), command_base=command_base)

        if command_base == "ls":
            if len(parts) > 2:
                return deny("COMMAND_USAGE:ls [path]", command_base)
            target = parts[1] if len(parts) == 2 else "."
            return allow(resolved_path=safe_resolve(target, root), command_base=command_base)

        # 알 수 없는 명령도 문법상 제안으로는 유효하다. Policy가 이를 거부한다.
        return allow(command_base=command_base)

    except (PermissionError, ValueError) as exc:
        return deny(str(exc))


_BINARY = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul, ast.Div: operator.truediv, ast.FloorDiv: operator.floordiv, ast.Mod: operator.mod, ast.Pow: operator.pow}
_UNARY = {ast.UAdd: operator.pos, ast.USub: operator.neg}


# 함수이름: _eval_arithmetic
# 인자:
#     node (ast.AST): ast.parse(mode='eval')로 만든 구문 트리 노드
# 반환값:
#     int | float: 계산 결과
#     ValueError: 허용되지 않은 노드이거나 지수가 과도할 때 발생
# 기능 설명:
#     허용 목록에 있는 산술 연산만 직접 계산한다.
#
#     eval()은 임의 코드 실행이므로 계산기 하나 때문에 sandbox 전체가 무의미해
#     진다. 허용한 노드만 처리하고 나머지는 거부한다. 지수를 100으로 제한하는
#     것은 2**999999 같은 입력이 자원을 소진시키기 때문이다.
def _eval_arithmetic(node: ast.AST) -> int | float:
    if isinstance(node, ast.Expression):
        return _eval_arithmetic(node.body)

    if isinstance(node, ast.Constant) and type(node.value) in (int, float):
        return node.value

    if isinstance(node, ast.BinOp) and type(node.op) in _BINARY:
        left, right = _eval_arithmetic(node.left), _eval_arithmetic(node.right)

        if isinstance(node.op, ast.Pow) and abs(right) > 100:
            raise ValueError("exponent too large")

        return _BINARY[type(node.op)](left, right)

    if isinstance(node, ast.UnaryOp) and type(node.op) in _UNARY:
        return _UNARY[type(node.op)](_eval_arithmetic(node.operand))

    raise ValueError("unsupported expression")


# 함수이름: calculator
# 인자:
#     expression (str): 산술식 문자열. 최대 500자
# 반환값:
#     str: 계산 결과를 문자열로 변환한 값
#     ValueError: 길이 초과이거나 허용되지 않은 식일 때 발생
# 기능 설명:
#     mock 도구 중 하나. 안전한 산술 계산만 수행한다. 길이 제한을 먼저 거는
#     이유는 아주 긴 식이 ast.parse 단계에서 이미 자원을 소모하기 때문이다.
def calculator(expression: str) -> str:
    if len(expression) > 500:
        raise ValueError("expression too long")
    return str(_eval_arithmetic(ast.parse(expression, mode="eval")))


# 클래스이름: Runtime
# 필드:
#     sandbox_root (Path): 접근 가능한 유일한 파일 루트
#     policy (PolicyEngine): 범위, trust 규칙 판정기
#     approvals (ApprovalStore): 승인 상태 저장소
#     trace (TraceLogger): 모든 판정을 남기는 append-only 로거
#     authorizer (AuthorizationEngine): actor-resource 소유권 판정기
#     tool_profile (ToolProfile): 이 Runtime이 노출하는 도구 집합
# 메서드:
#     execute_tool(): 유일한 공개 진입점. 6단계를 순서대로 실행한다
#     _dispatch(): 실제 도구 함수 호출. 모든 관문을 통과해야 도달한다
# 기능 설명:
#     권위 있는 실행 경계. allow 판정이거나 유효한 승인이 있는 요청만 실행한다.
#
#     구성요소를 생성자에서 주입받는 이유는 실험마다 완전히 독립된 Runtime을
#     만들기 위해서다. 프로그램 전체가 같은 Runtime 객체를 쓴다면 실험끼리 승인 상태가 섞여서
#     같은 불변조건 검증이더라도 실행 순서에 따라 결과가 달라진다. 따라서 (런타임)객체 하나는 실험 하나에
#     대응하는 구조이며, 동일한 실험이더라도 재사용하지 않는다.
class Runtime:

    # 함수이름: Runtime.__init__
    # 인자:
    #     sandbox_root (Path): 파일 접근이 허용된 유일한 루트. 없으면 생성한다
    #     policy (PolicyEngine): 범위, trust 판정기
    #     approvals (ApprovalStore): 승인 저장소
    #     trace_logger (TraceLogger): 판정 기록기
    #     authorizer (AuthorizationEngine | None): 소유권 판정기.
    #         기본값 None이면 기본 엔진을 만든다
    #     tool_profile (ToolProfile): 노출할 도구 집합. 키워드 필수 인자다
    # 반환값:
    #     None: 반환값 없음. sandbox_root 디렉터리를 생성하는 부작용이 있다
    # 기능 설명:
    #     실험 하나를 위한 실행 경계를 구성한다. tool_profile에 기본값을 두지 않은 이유
    #     무엇을 노출하는지가 이 실험의 가장 중요한 조건이기 때문이다.
    def __init__(self, *, sandbox_root: Path, policy: PolicyEngine, approvals: ApprovalStore, trace_logger: TraceLogger, authorizer: AuthorizationEngine | None = None, tool_profile: ToolProfile) -> None:
        self.sandbox_root = sandbox_root.resolve()
        self.sandbox_root.mkdir(parents=True, exist_ok=True)
        self.policy = policy
        self.approvals = approvals
        self.trace = trace_logger
        self.authorizer = authorizer or AuthorizationEngine()
        self.tool_profile = tool_profile

    # 함수이름: Runtime.execute_tool
    # 인자:
    #     tool_name (str): 제안된 도구 이름. 신뢰하지 않는다
    #     arguments (Mapping): 제안된 인자. 신뢰하지 않는다
    #     call_id (str): 호출 식별자. 모든 단계 이벤트가 이 값으로 묶인다
    #     run_id (str): 실험 실행 식별자
    #     actor (str): 인증된 주체. 인증, session, test harness에서만 온다
    #     provenance (Provenance): 이 제안이 나온 입력 문맥. 호출자가 부여한다
    #     approval_id (str | None): 이미 받은 승인의 ID. 기본값 None
    #     agent_step (int | None): 몇 번째 turn인가. 감사 메타데이터. 기본값 None
    #     fixture_id (str | None): 실험 케이스 라벨. 기본값 None
    # 반환값:
    #     RuntimeResult: 성공 또는 어느 단계에서 왜 막혔는지를 담은 결과
    # 기능 설명:
    #     도구 제안 하나를 여섯 단계에 통과시킨다. 유일한 실행 경로이며 우회 경로는
    #     없다. 실패 시 end_stage를 통헤 어느 단계에서 끝났는지를 알 수 다.
    #
    #         0. schema gate    -> tool_schema     미노출 도구, 인자 인터페이스 위반
    #         1. validation     -> validation      경로 탈출, 형식 오류
    #         2. ToolIntent 생성  (실패 없음. 서버가 capability를 계산한다)
    #         3. Policy         -> policy          비신뢰 출처, 민감 리소스, 범위 밖
    #         4. Authorization  -> authorization   소유자 아님, 멤버 아님
    #         5. Approval       -> approval        승인 없음, 만료, 재사용
    #         6. dispatch       -> runtime         도구 실행 중 오류
    #
    #     actor와 provenance를 인자로 받는 이유는, 모델이 만든 문자열에서 추론하면
    #     모델이 스스로 신원과 출처를 주장할 수 있게 되기 때문이다. 거부를 예외가
    #     아니라 결과로 돌려주는 이유는, 거부도 관측 대상이기 때문이다.
    def execute_tool(self, *, tool_name: str, arguments: Mapping[str, Any], call_id: str, run_id: str, actor: str, provenance: Provenance, approval_id: str | None = None, agent_step: int | None = None, fixture_id: str | None = None) -> RuntimeResult:
        # 0. Day 9 MCP tool exposure/inputSchema gate
        schema_decision = validate_tool_schema(
            self.tool_profile, tool_name, arguments
        )
        self.trace.record_tool_schema(
            run_id,
            call_id,
            actor=actor,
            fixture_id=fixture_id,
            decision=schema_decision
        )
        schema_context = schema_decision.trace_fields()

        if not schema_decision.allowed:
            result = RuntimeResult.failure(
                "schema_denied",
                "tool_schema",
                tool_name,
                call_id,
                "MCP_TOOL_SCHEMA_DENIED",
                schema_decision.reason,
                security=schema_context
            )
            self.trace.record_early_result(
                run_id,
                call_id,
                actor=actor,
                fixture_id=fixture_id,
                result=result
            )
            return result

        # 1. 기존 Runtime Validation
        validation = validate_tool_call(tool_name, arguments, self.sandbox_root)

        if not validation["allowed"]:
            result = RuntimeResult.failure("validation_failed", "validation", tool_name, call_id, "INVALID_ARGUMENT", validation["reason"], security=schema_context)
            self.trace.record_validation(run_id, tool_name, call_id, provenance, validation, result, actor=actor, agent_step=agent_step, fixture_id=fixture_id)

            return result

        self.trace.record_validation(
            run_id,
            tool_name,
            call_id,
            provenance,
            validation,
            actor=actor,
            agent_step=agent_step,
            fixture_id=fixture_id,
        )

        capability, action, resource = describe_intent(tool_name, arguments, validation, self.sandbox_root)

        # 2. Generate ToolIntent
        intent = ToolIntent(run_id=run_id, call_id=call_id, actor=actor, tool_name=tool_name, arguments=dict(arguments), provenance=provenance, capability=capability, action=action, resource=resource, agent_step=agent_step, fixture_id=fixture_id)

        self.trace.record_intent(intent)

        # 3. Policy Decision
        decision = self.policy.evaluate(intent)

        self.trace.record_policy(intent, decision)

        if decision.outcome is Decision.DENY:
            result = RuntimeResult.failure("denied", "policy", tool_name, call_id, "POLICY_DENIED", decision.reason, security={**schema_context, **decision.trace_fields()})

            self.trace.record_result(intent, result)

            return result

        # Policy: 일반 규칙. Authorization: 이 actor가 해당 자원에 접근 할 수 있고, 해당 도구를 사용할 수 있는지.
        authorization = self.authorizer.authorize(intent)

        # 4. Authorization
        self.trace.record_authorization(intent, authorization)
        security_context = {
            **schema_context,
            **decision.trace_fields(),
            **authorization.trace_fields()
        }

        # 1) DENY
        if authorization.outcome is AuthorizationOutcome.DENY:

            result = RuntimeResult.failure(
                "forbidden", "authorization", tool_name, call_id,
                "FORBIDDEN", authorization.reason, security=security_context
            )
            self.trace.record_result(intent, result)
            return result

        # ALLOW 요청은 ApprovalStore를 조회할 이유가 없다. 쓰기처럼 정책이
        # APPROVAL_REQUIRED를 반환한 경우에만 승인 상태를 읽는다.
        approval_state = ApprovalState(None, ApprovalStatus.NOT_REQUIRED)

        # 2) APPROVAL_REQUIRED
        # [A-04] Day 9까지 이 구간은 동일한 조건의 if 블록 두 개로 나뉘어 있었다. 이를 하나로
        # 합치고 내부를 세 단계로 명시한다. 
        if decision.outcome is Decision.APPROVAL_REQUIRED:

            # (a) 제출된 approval ID가 이 intent에 대해 유효한 승인인지 확인한다.
            approval_state = self.approvals.resolve(approval_id)
            usable = (
                approval_state.status is ApprovalStatus.APPROVED
                and approval_state.intent_fingerprint == intent.fingerprint()
            )

            if not usable:
                # [A-10] 이전에는 여기서 RuntimeError를 던져 trace에 아무 사건도
                # 남기지 않고 프로세스를 중단시켰다. 불변조건 위반 케이스는 증거가
                # 남아야 하므로 안전하게 거부하면서 결과와 trace를 기록한다.

                # Policy가 APPROVAL_REQUIRED라고 판단했다면 Authorization 결과에는 required_approver가 반드시 있어야 한다.
                if authorization.required_approver is None:
                    result = RuntimeResult.failure(
                        "internal_invariant_violation", "approval", tool_name, call_id,
                        "MISSING_REQUIRED_APPROVER",
                        "approval-required decision lacks required approver",
                        security=security_context
                    )
                    self.trace.record_result(intent, result)
                    return result

                # (b) 유효한 승인이 없으면 새 pending record를 만들고 즉시 반환한다.
                #     실행은 하지 않는다.
                pending = self.approvals.request(intent, decision, required_approver=authorization.required_approver)
                result = RuntimeResult.failure("approval_required", "approval", tool_name, call_id, "APPROVAL_REQUIRED", decision.reason, security={**security_context, "approval": pending.status.value, "approval_id": pending.approval_id, "required_approver": pending.required_approver})
                self.trace.record_approval(intent, pending)
                self.trace.record_result(intent, result)
                return result

            self.trace.record_approval(intent, approval_state)

            # (c) dispatch 직전에 승인을 1회용으로 소비한다. consumed_now=True인
            #     호출만 Dispatcher에 들어간다. 같은 approval ID를 다시 제출하면
            #     이미 CONSUMED이므로 False가 되어 실행되지 않는다(replay 차단).
            approval_state, consumed_now = self.approvals.consume(
                approval_id or "",
                intent_fingerprint=intent.fingerprint()
            )
            if not consumed_now:
                result = RuntimeResult.failure("approval_required", "approval", tool_name, call_id, "APPROVAL_NOT_USABLE", "approved approval was not usable", security={**security_context, "approval": approval_state.status.value, "approval_id": approval_state.approval_id, "required_approver": approval_state.required_approver})
                self.trace.record_approval(intent, approval_state)
                self.trace.record_result(intent, result)
                return result

            self.trace.record_approval(intent, approval_state)

        # 3) ALLOW 또는 APPROVAL_REQUIRED -> APPROVED -> CONSUMED
        # [A-05] _dispatch()가 도구함수 호출역할을 하며 유일한 실행 경계다.
        # Schema, Validation, Policy, Authorization, Approval을 모두 통과해야 도달한다.
        try:
            data = self._dispatch(intent, validation)

            result = RuntimeResult.success( tool_name, call_id, data, security={**security_context, "approval": approval_state.status.value, "approval_id": approval_state.approval_id, "required_approver": approval_state.required_approver})

        except Exception as exc:  # 도구 오류를 매핑하며 세부 정보는 로컬에 둔다.
            code = "NOT_FOUND" if isinstance(exc, FileNotFoundError) else "EXECUTION_ERROR"
            result = RuntimeResult.failure( 
                "execution_failed", "runtime", tool_name, call_id, code, str(exc), 
                security={**security_context, "approval": approval_state.status.value, "approval_id": approval_state.approval_id, "required_approver": approval_state.required_approver}
            )

        self.trace.record_result(intent, result)

        return result


    # 함수이름: Runtime._dispatch
    # 인자:
    #     intent (ToolIntent): 모든 관문을 통과한 정규화된 요청
    #     validation (Mapping): validate_tool_call()의 결과. 정규화된 경로를 담는다
    # 반환값:
    #     str: 도구 실행 결과 문자열
    #     RuntimeError: 매핑되지 않은 도구가 도달했을 때 발생
    # 기능 설명:
    #     실제 도구 함수를 호출하는 유일한 지점이다.
    #
    #     경로를 다시 계산하지 않고 validation이 이미 정규화한 resolved_path만 쓴다.
    #     여기서 인자로 경로를 다시 만들면 검사한 경로와 실행하는 경로가 달라질 수
    #     있다. 마지막 RuntimeError는 Policy가 허용했는데 구현이 없다는 뜻이므로 기록으로 남긴다. 
    def _dispatch(self, intent: ToolIntent, validation: Mapping[str, Any]) -> str:
        path = validation["resolved_path"]

        if intent.tool_name == "calculator":
            return calculator(str(intent.arguments["expression"]))

        if intent.tool_name == "get_time":
            return datetime.now(timezone.utc).isoformat()

        if intent.tool_name == "read_file":
            return self._read_file(path)

        if intent.tool_name == "write_file":
            return self._write_file(path, str(intent.arguments["content"]))

        if intent.tool_name == "list_files":
            return self._list_files(path)

        if intent.tool_name == "run_command":
            return self._run_command(str(validation["command_base"]), path)
        raise RuntimeError("unknown tool reached dispatch")

    # 함수이름: Runtime._read_file
    # 인자:
    #     path (Path): 정규화가 끝난 절대 경로
    # 반환값:
    #     str: UTF-8로 읽은 파일 내용
    #     FileNotFoundError: 파일이 없을 때 발생
    # 기능 설명:
    #     파일 하나를 읽는다. 오류 메시지에 전체 경로가 아니라 path.name만 넣는 이유
    #     오류 문구가 모델에게 전달될 수 있고 전체 경로는 sandbox 밖 구조를
    #     알려 주는 정보가 되기 때문이다.
    def _read_file(self, path: Path) -> str:
        if not path.is_file():
            raise FileNotFoundError(f"file not found: {path.name}")

        return path.read_text(encoding="utf-8")

    # 함수이름: Runtime._write_file
    # 인자:
    #     path (Path): 정규화가 끝난 절대 경로
    #     content (str): 쓸 내용
    # 반환값:
    #     str: 'Wrote file: <상대경로>' 형태의 결과 문자열
    #     NotADirectoryError: 부모 디렉터리가 선언되지 않았을 때 발생
    # 기능 설명:
    #     파일 하나를 쓰되 디렉터리는 만들지 않는다.
    def _write_file(self, path: Path, content: str) -> str:
        # [A-09] 이전에는 mkdir(parents=True)로 임의 깊이의 디렉터리를 만들었다.
        # 하지만 디렉터리 생성은 그 자체로 상태 변이에 해당하며,  소유권 판정 시에 AuthorizationEngine이
        # data/{actor}/ 디렉터리 이름에 의존하므로 디렉터리 생성을 허용하면 새 네임스페이스를 스스로 만들 수 있게 된다. 
        # 따라서 파일의 부모 디렉터리가 이미 존재할 때만 쓰기를 허용한다.
        if not path.parent.is_dir():
            raise NotADirectoryError(
                f"parent directory is not declared in the sandbox: "
                f"{path.parent.relative_to(self.sandbox_root).as_posix()}"
            )
        path.write_text(content, encoding="utf-8")

        return f"Wrote file: {path.relative_to(self.sandbox_root).as_posix()}"


    # 함수이름: Runtime._list_files
    # 인자:
    #     path (Path): 정규화가 끝난 디렉터리 절대 경로
    # 반환값:
    #     str: sandbox 기준 상대 경로를 정렬해 줄바꿈으로 이은 문자열
    #     NotADirectoryError: 디렉터리가 아닐 때 발생
    # 기능 설명:
    #     디렉터리 하나를 나열한다. 결과가 모델에게 전달되므로 절대경로 대신 상대경로를 돌려준다.
    #     재현 digest의 입력으로 넣기 위해서 정렬한다.
    def _list_files(self, path: Path) -> str:
        if not path.is_dir():
            raise NotADirectoryError("not a directory")

        return "\n".join(sorted(child.relative_to(self.sandbox_root).as_posix() for child in path.iterdir()))


    # 함수이름: Runtime._run_command
    # 인자:
    #     command_base (str): 검증된 명령 이름 (pwd / ls / cat 중 하나)
    #     path (Path | None): 명령 대상 경로. pwd는 None
    # 반환값:
    #     str: 명령 실행 결과
    #     RuntimeError: 허용되지 않은 명령이 도달했을 때 발생
    # 기능 설명:
    #     이전 버전 호환용 제한 명령을 처리한다.
    #
    #     command 명령을 실행할 때는 실제 subprocess를 쓰지 않는다.
    #      _read_file/_list_files로 위임한다. 셸을 띄우면 파이프, 리다이렉션, 명령 치환이 열리기 때문에 
    #      policy의 allowlist가 무의미해진다.
    def _run_command(self, command_base: str, path: Path | None) -> str:
        if command_base == "pwd":
            return "sandbox"

        if command_base == "ls" and path is not None:
            return self._list_files(path)

        if command_base == "cat" and path is not None:
            return self._read_file(path)

        # Policy와 Runtime이 정상적으로 연결돼 있다면 pwd, ls, cat 외 명령은 여기까지 오지 않는다.
        raise RuntimeError("policy/runtime mismatch: command reached execution")
