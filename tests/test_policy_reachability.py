# [A-01 회귀] 정책 분기 도달 가능성 검사.
#
# 왜 이 테스트가 필요한가
# -----------------------
# Day 9까지 경로 인가는 세 계층에 중복 구현되어 있었다.
#
# 1. ``security/tool_schema.py``의 경로 정규식
# 2. ``security/permission.py``의 ``POLICY.allowed_scopes``
# 3. ``security/authorization.py``의 소유권 판정
#
# 가장 앞에 있는 (1)이 가장 좁았기 때문에, (2)에 선언된 scope 여러 개가 어떤
# 호출로도 도달할 수 없었다. 도달하지 못하는 분기는 '검증했다'는 착각을 만든다.
# Day 4~5 실험 보고서가 근거로 삼은 규칙 일부가 실제로는 한 번도 실행되지 않은
# 상태였다.
#
# 이 테스트는 ``POLICY``에 선언된 모든 scope에 대해, schema gate를 통과해 실제로
# PolicyEngine까지 도달하는 예시 경로가 최소 하나 존재하는지 확인한다. 앞으로
# 앞으로 있을 실험에서 schema를 다시 좁히면 이 테스트가 먼저 깨진다.


from __future__ import annotations

# [경로 부트스트랩] src/를 import 경로에 넣는 일은 아래 프로젝트 import보다 반드시
# 먼저 일어나야 한다. 이전에는 파일 맨 아래 __main__ 블록에서 했는데, 그 시점에는
# 위의 import가 이미 실행된 뒤여서 직접 실행이 항상 ModuleNotFoundError로 끝났다.
# pytest로 돌릴 때는 루트 conftest.py가 같은 일을 하므로 여기서는 중복을 피한다.
#
# 이 블록 때문에 아래 import가 파일 최상단에 오지 못하므로 E402를 끈다.
# ruff: noqa: E402
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "src"))

from security.capability import describe_intent
from security.permission import POLICY
from security.policy import PolicyEngine
from security.provenance import direct_user_provenance
from security.tool_schema import (
    LEGACY_COMPAT_PROFILE,
    validate_tool_schema,
)
from security.types import ToolIntent

SANDBOX_ROOT = (PROJECT_ROOT / "sandbox").resolve()

# 각 (tool, scope)마다 그 scope로 분류되어야 하는 대표 경로.
# legacy_compat 프로필은 모든 도구를 노출하므로 도달 가능성 검사에 사용한다.
SCOPE_EXAMPLES: dict[tuple[str, str], str] = {
    ("read_file", "data"): "data/user-001/notes.txt",
    ("list_files", "data"): "data/user-001",
    ("list_files", "sandbox_root"): ".",
    ("write_file", "data"): "data/user-001/notes.txt",
    ("write_file", "root_file"): "notes.txt"
}

COMMAND_EXAMPLES: dict[str, str] = {
    "pwd": "pwd",
    "ls": "ls data/user-001",
    "cat": "cat data/user-001/notes.txt"
}


# 함수이름: _reaches_policy
# 인자:
#     tool_name (str): 검사할 도구 이름
#     arguments (dict): 도구 인자
# 반환값:
#     tuple[bool, str]: (Policy까지 도달했는가, 도달했으면 판정 사유 /
#         못 했으면 어디서 막혔는지)
# 기능 설명:
#     schema gate와 validation을 실제로 거쳐 PolicyEngine까지 가 보고, 그
#     판정 사유를 돌려준다.
#
#     직접 부르면 앞 단계에서 막히는지를 알 수 없다. 도달 가능성을 검사하려면
#     실제 경로를 그대로 따라가야 한다.
#
#     모든 도구를 노출하는 프로필이어야 '노출되지 않아서 막힌 것'과 '규칙 때문에
#     막힌 것'을 구별할 수 있다.
def _reaches_policy(tool_name: str, arguments: dict) -> tuple[bool, str]:
    decision = validate_tool_schema(LEGACY_COMPAT_PROFILE, tool_name, arguments)
    if not decision.allowed:
        return False, decision.reason

    from runtime import validate_tool_call

    validation = validate_tool_call(tool_name, arguments, SANDBOX_ROOT)
    if not validation["allowed"]:
        return False, f"VALIDATION:{validation['reason']}"

    capability, action, resource = describe_intent(tool_name, arguments, validation, SANDBOX_ROOT)
    intent = ToolIntent(
        run_id="run-reachability",
        call_id="call-reachability",
        actor="user-001",
        tool_name=tool_name,
        arguments=arguments,
        provenance=direct_user_provenance(),
        capability=capability,
        action=action,
        resource=resource
    )
    return True, PolicyEngine().evaluate(intent).reason


# 함수이름: test_every_declared_scope_is_reachable
# 인자: 없음
# 반환값:
#     list[str]: 빈 리스트. 실패 항목이 있으면 assert에서 먼저 중단된다
#     AssertionError: 도달 불가 분기가 있을 때 발생
# 기능 설명:
#     [A-01 회귀] POLICY에 선언된 모든 scope가 실제로 평가되는지 검사한다.
#
#         도달 못 함        앞 단계(schema/validation)에서 막혔다
#         도달했으나 거부   자기 자신의 scope 규칙에 걸렸다 = 선언이 모순이다
#
#     scope마다 '그 scope로 분류되는 대표 경로'를 사람이 정해야 한다. 자동
#     생성하면 테스트가 구현을 그대로 따라 하게 되어 검증력이 사라진다.
#     새 scope를 추가하고 예시를 안 적으면 이 테스트가 먼저 실패한다.
def test_every_declared_scope_is_reachable() -> list[str]:
    failures: list[str] = []
    checked = 0

    for tool_name, rule in POLICY.items():
        for scope in rule.get("allowed_scopes", ()):
            example = SCOPE_EXAMPLES.get((tool_name, scope))
            if example is None:
                failures.append(f"{tool_name}:{scope} — 대표 경로가 정의되지 않았다(테스트 갱신 필요)")
                continue

            arguments = {"path": example}
            if tool_name == "write_file":
                arguments["content"] = "reachability probe"

            reached, reason = _reaches_policy(tool_name, arguments)
            checked += 1
            if not reached:
                failures.append(
                    f"{tool_name}:{scope} — 경로 {example!r}가 Policy에 도달하지 못함 (사유 {reason})"
                )
            elif reason == "RESOURCE_OR_COMMAND_SCOPE_DENIED":
                failures.append(
                    f"{tool_name}:{scope} — 도달했으나 자기 자신의 scope 규칙에 거부됨 (경로 {example!r})"
                )

    print(f"검사한 (도구, scope) 조합: {checked}개")
    assert not failures, "도달 불가 정책 분기:\n  - " + "\n  - ".join(failures)
    return failures


# 함수이름: test_every_declared_command_is_reachable
# 인자: 없음
# 반환값:
#     list[str]: 빈 리스트. 실패 항목이 있으면 assert에서 먼저 중단된다
#     AssertionError: 도달 불가 분기가 있을 때 발생
# 기능 설명:
#     [A-01 회귀] POLICY에 선언된 모든 run_command의 허용명령이 실제로 평가되는지 검사한다.
#
#         도달 못 함        앞 단계(schema/validation)에서 막혔다
#         도달했으나 거부   자기 자신의 허용 명령규칙에 걸렸다 = 선언이 모순이다
#
#     command마다 '그 command로 분류되는 대표명령'를 사람이 정해야 한다.
#     자동생성하면 테스트가 구현을 그대로 따라 하게 되어 검증력이 사라진다.
#     허용명령을 추가하고 예시를 안 적으면 이 테스트가 먼저 실패한다.
def test_every_declared_command_is_reachable() -> list[str]:
    failures: list[str] = []
    checked = 0

    for tool_name, rule in POLICY.items():
        for command in rule.get("allowed_commands", ()):
            example = COMMAND_EXAMPLES.get(command)
            if example is None:
                failures.append(f"{command} — 대표명령(테스트)이 등록되지 않았다(COMMAND_EXAMPLES 갱신 필요)")
                continue

            arguments = {"command": example}

            reached, reason = _reaches_policy(tool_name, arguments)
            checked += 1
            if not reached:
                failures.append(
                    f"{command} — 명령어 {example!r}가 Policy에 도달하지 못함 (사유 {reason})"
                )
            elif reason == "RESOURCE_OR_COMMAND_SCOPE_DENIED":
                failures.append(
                    f"{command} — 도달했으나 자기 자신의 scope 규칙에 거부됨 (경로 {example!r})"
                )

    print(f"검사한 허용명령: {checked}개")
    assert not failures, "도달 불가 정책 분기:\n  - " + "\n  - ".join(failures)
    return failures




# 함수이름: test_sensitive_resource_is_denied_before_scope
# 인자: 없음
# 반환값:
#     None: 반환값 없음
#     AssertionError: 민감 파일이 거부되지 않을 때 발생
# 기능 설명:
#     [A-11] 확장자 형태의 민감 파일도 거부되는지 확인한다.
#
#     이전 규칙은 조각이 정확히 일치할 때만 민감으로 봐서 api.env를 놓쳤다.
#
#     schema 단계에서 조기 종료되면 Policy의 민감 판정 규칙 자체를 검증한 것이
#     아니다. 다른 이유로 막힌 것을 방어가 동작한 것으로 착각하면 안 된다.
def test_sensitive_resource_is_denied_before_scope() -> None:
    cases = [
        "data/user-001/api.env",
        "data/user-001/service.pem",
        "data/user-001/my_api_key.txt",
    ]
    for path in cases:
        reached, reason = _reaches_policy("read_file", {"path": path})
        assert reached, f"{path}: schema 단계에서 조기 종료되어 Policy 규칙을 검증할 수 없다 ({reason})"
        assert reason == "SENSITIVE_RESOURCE_DENIED", f"{path}: 민감 리소스로 거부되지 않았다 (사유 {reason})"
    print(f"민감 리소스 거부 확인: {len(cases)}건")


# 함수이름: test_traversal_is_denied_at_schema_gate
# 인자: 없음
# 반환값:
#     None: 반환값 없음
#     AssertionError: traversal이 schema gate를 통과할 때 발생
# 기능 설명:
#     경로 정규식을 넓힌 뒤에도 traversal과 절대 경로는 여전히 막히는지 확인한다.
#
#     [A-01의 안전장치]
#     범위 판정을 POLICY로 옮기면서 schema의 패턴이 느슨해졌다. 그 과정에서
#     가장 기본적인 방어까지 함께 느슨해지지 않았음을 이 테스트가 보장한다.
def test_traversal_is_denied_at_schema_gate() -> None:
    for path in ["../secret/dome.env", "/etc/passwd", "data/../../etc/passwd"]:
        decision = validate_tool_schema(LEGACY_COMPAT_PROFILE, "read_file", {"path": path})
        assert not decision.allowed, f"{path}: schema gate를 통과했다"
        assert decision.reason in {
            "MCP_PATH_OUTSIDE_PROFILE_SCOPE",
            "MCP_ARGUMENT_PATTERN_MISMATCH",
        }, f"{path}: 예상 밖 사유 {decision.reason}"
    print("traversal/절대 경로 차단 확인: 3건")


# 함수이름: test_unknown_capability_is_denied
# 인자: 없음
# 반환값:
#     None: 반환값 없음
#     AssertionError: 미허용 명령이 허용될 때 발생
# 기능 설명:
#     capability를 매핑할 수 없는 명령이 여전히 거부되는지 확인한다.
#
#     기본값이 거부(fail closed)라는 성질을 회귀로 지킨다. 새 도구를 추가하며
#     capability 매핑을 빠뜨려도 조용히 허용되지 않는다.
def test_unknown_capability_is_denied() -> None:
    reached, reason = _reaches_policy("run_command", {"command": "curl http://example.invalid"})
    assert reached, f"validation 단계에서 종료됨 ({reason})"
    assert reason in {"CAPABILITY_NOT_ALLOWLISTED", "RESOURCE_OR_COMMAND_SCOPE_DENIED"}, reason
    print("미허용 명령 거부 확인")


# 함수이름: main
# 인자: 없음
# 반환값:
#     None: 반환값 없음
# 기능 설명:
#     네 검사를 순서대로 실행한다. pytest 없이 직접 실행할 때의 진입점이다.
#
#     판정 함수만 직접 부르는 단위 검사여서 sandbox, trace, 증거가 필요 없다.
#     필요 없는 격리를 얹으면 느려지고 무엇을 검사하는지 흐려진다.
#
#     [삭제 이력] 여기서 lab_paths.trace_root()를 부르던 한 줄을 제거했다.
#     "부작용 없이 경로 설정을 확인한다"는 주석이 붙어 있었지만 trace_root()는
#     mkdir(parents=True)를 하므로 부작용이 있었고, 애초에 이 파일은 위 주석대로
#     trace가 필요 없다. 필요 없는 것을 검증하느라 없는 디렉터리를 만들고 있었다.
def main() -> None:
    test_every_declared_scope_is_reachable()
    test_every_declared_command_is_reachable()
    test_sensitive_resource_is_denied_before_scope()
    test_traversal_is_denied_at_schema_gate()
    test_unknown_capability_is_denied()
    print("정책 도달 가능성 테스트: PASS")


if __name__ == "__main__":
    # 경로 설정은 파일 상단 부트스트랩 블록에서 이미 끝났다. 여기서 하면 늦다.
    main()
