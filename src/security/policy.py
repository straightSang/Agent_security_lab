# 모듈이름: security.policy
# 역할: 일반 정책 판정. 도구를 직접 실행하지 않고 결정만 돌려준다
# 호출 주체: runtime.Runtime.execute_tool()의 3단계
#
# 기능 설명:
#     "이 요청이 규칙상 허용되는가"에 답한다. "누가 요청했는가"는 답하지 않는다.
#     그것은 security.authorization의 몫이다.
#
#         1. provenance -> trust label 계산
#         2. 민감 리소스 이름 검사   -> SENSITIVE_RESOURCE_DENIED
#         3. capability allowlist    -> CAPABILITY_NOT_ALLOWLISTED
#         4. untrusted provenance    -> UNTRUSTED_PROVENANCE_CANNOT_AUTHORIZE_TOOL
#         5. 범위·명령 규칙          -> RESOURCE_OR_COMMAND_SCOPE_DENIED
#         6. 승인 필요 여부          -> WRITE_REQUIRES_EXPLICIT_APPROVAL
#         7. 통과                    -> BASELINE_CAPABILITY_ALLOWED
#
#     비신뢰 출처의 제안은 승인 단계에 도달하기 전에 항상 거부된다. 만약 순서가
#     뒤집혀 범위 검사를 먼저 통과시키면, 파일이나 웹 콘텐츠에서 유래한 명령이
#     "승인만 받으면 되는 요청"이 되어 버린다. 그 순간 approval ID로 주입 명령을
#     되살릴 수 있다.
#
#     같은 입력과 같은 정책 버전이면 항상 같은 문자열이 나와야 한다. reason이
#     흔들리면 재현성 digest가 깨지고, 운영자가 거부 사유를 학습할 수도 없다.
#     rule_id는 현재 reason과 같은 값을 쓰지만 스키마 구조상으로는 별개다.


from __future__ import annotations

from .permission import POLICY
from .trust import label_trust
from .types import Capability, Decision, PolicyDecision, ToolIntent, TrustLabel

_SENSITIVE_NAMES = {".env", "credentials", "credential", "secret", "secrets", "id_rsa", "token", "tokens", "password", "passwords"}
# [A-11] 이전 규칙은 조각이 정확히 일치하거나 특정 접두사로 시작할 때만 민감으로
# 보았기 때문에 ``api.env`` 같은 이름을 놓쳤다. 확장자와 부분 문자열을 함께 본다.
_SENSITIVE_SUFFIXES = (".env", ".pem", ".key", ".p12", ".pfx", ".keystore")
_SENSITIVE_SUBSTRINGS = ("credential", "secret", "token", "password", "passwd", "apikey", "api_key")


def _is_sensitive_part(part: str) -> bool:
    if part in _SENSITIVE_NAMES:
        return True
    if part.endswith(_SENSITIVE_SUFFIXES):
        return True
    return any(marker in part for marker in _SENSITIVE_SUBSTRINGS)


# 클래스이름: PolicyEngine
# 필드: 없음. 상태를 갖지 않는다
# 메서드:
#     evaluate(): 유일한 공개 메서드. ToolIntent 하나를 판정한다
#     _decision(): PolicyDecision 생성 헬퍼
#     _resource_scope(): 경로를 범위 이름으로 분류
#     _permission_allows(): POLICY 규칙 적용
# 기능 설명:
#     감사 가능한 작은 기본 정책 엔진이다.
#
#     같은 입력에 항상 같은 판정이 나와야 한다. 내부 상태가 있으면 호출
#     순서에 따라 결과가 달라지고, 그러면 재현성 digest가 무의미해진다.
#
#     security/permission.py의 POLICY를 고친다. Runtime Dispatcher에 정책
#     예외를 추가하지 않는다. 예외는 감사 불가능한 우회 경로가 된다.
class PolicyEngine:

    # 함수이름: PolicyEngine.evaluate
    # 인자:
    #     intent (ToolIntent): Runtime이 정규화한 요청. capability와 resource는
    #         서버가 계산한 값이며 모델이 제시한 값이 아니다
    # 반환값:
    #     PolicyDecision: outcome(ALLOW / DENY / APPROVAL_REQUIRED),
    #         reason, capability, action, resource, trust, rule_id
    # 기능 설명:
    #     모듈 docstring의 7단계를 순서대로 적용하고, 먼저 걸리는 규칙의
    #     reason을 돌려준다.
    #
    #     이 메서드는 판정만 한다. 도구 호출은 Runtime._dispatch()만 한다.
    #     판정과 실행을 분리해야 "허용했지만 실행하지 않았다"는 상태(승인
    #     대기)를 표현할 수 있다.
    #
    #     capability나 범위가 아무리 정상이어도 대상이 비밀 파일이면 볼 것도
    #     없다. 가장 강한 금지를 앞에 두면 뒤 규칙이 느슨해져도 뚫리지 않는다.
    def evaluate(self, intent: ToolIntent) -> PolicyDecision:

        # provenance : trustlabel 부여
        trust = label_trust(intent.provenance.kind)

        resource_parts = set((intent.resource or "").lower().replace("\\", "/").split("/"))

        # 민감 키워드 확인
        if any(_is_sensitive_part(part) for part in resource_parts):
            return self._decision(Decision.DENY, "SENSITIVE_RESOURCE_DENIED", intent, trust)

        # capability 검증
        if intent.capability is Capability.UNKNOWN:
            return self._decision(Decision.DENY, "CAPABILITY_NOT_ALLOWLISTED", intent, trust)

        # 간접 콘텐츠는 데이터일 뿐 권한을 위임하지 않는다. 신뢰할 수 없는
        # provenance는 승인 단계보다 먼저 항상 DENY한다. 따라서 approval ID로
        # 파일·웹·도구 출력에서 유래한 명령을 되살릴 수 없다.
        # provenance-trust 검증
        if trust is TrustLabel.UNTRUSTED:
            return self._decision(Decision.DENY, "UNTRUSTED_PROVENANCE_CANNOT_AUTHORIZE_TOOL", intent, trust)

        # 선언형 permission 설정이 sandbox 내부 리소스 범위와 논리 명령의
        # 단일 기준이다.
        if not self._permission_allows(intent):
            return self._decision(Decision.DENY, "RESOURCE_OR_COMMAND_SCOPE_DENIED", intent, trust)

        if POLICY.get(intent.tool_name, {}).get("approval_required", False):
            return self._decision(Decision.APPROVAL_REQUIRED, "WRITE_REQUIRES_EXPLICIT_APPROVAL", intent, trust)

        return self._decision(Decision.ALLOW, "BASELINE_CAPABILITY_ALLOWED", intent, trust)

    # 함수이름: PolicyEngine._decision
    # 인자:
    #     outcome (Decision): ALLOW / DENY / APPROVAL_REQUIRED
    #     reason (str): 안정적인 규칙 식별자 문자열
    #     intent (ToolIntent): 판정 대상 요청
    #     trust (TrustLabel): 이 요청의 신뢰 등급
    # 반환값:
    #     PolicyDecision: 판정 결과 객체
    # 기능 설명:
    #     모든 판정이 같은 모양으로 나가도록 강제하는 생성 헬퍼다.
    #
    #     지금은 규칙 레지스트리가 없어 reason이 곧 규칙 ID다. 나중에 별도
    #     레지스트리를 도입해도 기존 reason 계약은 유지한다. 과거 실험 로그의
    #     reason 문자열이 계속 유효해야 하기 때문이다.
    @staticmethod
    def _decision(outcome: Decision, reason: str, intent: ToolIntent, trust: TrustLabel) -> PolicyDecision:
        return PolicyDecision(
            outcome, reason, intent.capability, intent.action, intent.resource,
            trust, rule_id=reason,
        )

    # 함수이름: PolicyEngine._resource_scope
    # 인자:
    #     resource (str | None): sandbox 기준 상대 경로. 경로가 없는 도구는 None
    # 반환값:
    #     str: 'none' / 'sandbox_root' / 'data' / 'root_file' / 'other_subdirectory'
    #         중 하나
    # 기능 설명:
    #     경로를 POLICY가 이해하는 범위 이름으로 분류한다.
    #
    #         None            -> 'none'                (calculator처럼 경로가 없는 도구)
    #         '' 또는 '.'     -> 'sandbox_root'        (sandbox 최상위 자체)
    #         'data' 또는     -> 'data'                (data 디렉터리와 그 하위 전체)
    #         'data/...'
    #         '/' 없음        -> 'root_file'           (최상위 직하위 파일)
    #         그 외           -> 'other_subdirectory'  (현재 어떤 규칙도 허용 안 함)
    #
    #     POLICY를 사람이 읽고 검토할 수 있게 하려는 것이다. 정규식이나 경로
    #     객체로 표현하면 정책 문서와 코드가 어긋나기 쉽다.
    @staticmethod
    def _resource_scope(resource: str | None) -> str:
        if resource is None:
            return "none"
        normalized = resource.replace("\\", "/").strip("/")
        if normalized in {"", "."}:
            return "sandbox_root"
        if normalized == "data" or normalized.startswith("data/"):
            return "data"
        if "/" not in normalized:
            return "root_file"
        return "other_subdirectory"

    # 함수이름: PolicyEngine._permission_allows
    # 인자:
    #     intent (ToolIntent): 판정 대상 요청
    # 반환값:
    #     bool: POLICY 규칙상 허용되면 True
    # 기능 설명:
    #     trust 검사를 통과한 요청에 리소스·명령 범위 규칙을 적용한다.
    #
    #         calculator / get_time   POLICY의 allowed 플래그만 본다
    #         경로 도구 3종            _resource_scope() 결과가 allowed_scopes에
    #                                 있는지 본다
    #         run_command             명령 이름을 먼저 확인하고, 경로가 있는
    #                                 명령은 위임 도구의 범위 규칙을 그대로 쓴다
    #
    #     'cat'은 read_file과 같은 권한이고 'ls'는 list_files와 같은 권한이다.
    #     규칙을 두 벌 유지하면 반드시 어긋난다. 같은 능력이면 같은 규칙을
    #     쓰게 해서 우회 경로를 만들지 않는다.
    #
    #     기본값이 거부다(fail closed). 새 도구를 추가하면서 POLICY에 규칙을
    #     빠뜨리면 조용히 허용되는 것이 아니라 막힌다.
    @classmethod
    def _permission_allows(cls, intent: ToolIntent) -> bool:
        if intent.tool_name in {"calculator", "get_time"}:
            return bool(POLICY[intent.tool_name]["allowed"])

        if intent.tool_name in {"read_file", "write_file", "list_files"}:
            scope = cls._resource_scope(intent.resource)
            return scope in POLICY[intent.tool_name]["allowed_scopes"]

        if intent.tool_name != "run_command":
            return False
        if intent.action not in POLICY["run_command"]["allowed_commands"]:
            return False
        if intent.action == "pwd":
            return True
        delegated_tool = "read_file" if intent.action == "cat" else "list_files"
        scope = cls._resource_scope(intent.resource)
        return scope in POLICY[delegated_tool]["allowed_scopes"]
