# [계층 분리 회귀] MCP schema gate와 validation의 역할이 겹치지 않는지 검사한다.
#
# 왜 이 테스트가 필요한가
# -----------------------
# Day 9까지 두 계층이 같은 질문에 답했다.
#
#     schema gate   inputSchema 기준 인자 계약 검사
#     validation    ARGUMENT_SPEC 기준 인자 계약 검사   ← 중복
#
# 같은 질문에 두 곳이 답하면 둘이 어긋나는 순간 도달 불가 분기가 생긴다.
# A-01이 정확히 그 유형의 결함이었다. ARGUMENT_SPEC을 제거해 계약 검사를
# schema gate 하나로 모았고, validation은 '문자열을 실체로 바꾸는' 일만 한다.
#
# 이 테스트는 그 분리가 유지되는지를 세 방향에서 확인한다.
#
#     1. schema gate만 잡는 것이 있다      (노출 통제, 길이 제한)
#     2. validation만 잡는 것이 있다        (심볼릭 링크 탈출)
#     3. validation은 계약을 검사하지 않는다 (초과 인자를 그냥 통과시킨다)
#
# 3번이 핵심이다. validation이 다시 계약을 검사하기 시작하면 중복이 되살아난다.

from __future__ import annotations

# [경로 부트스트랩] src/를 import 경로에 넣는 일은 아래 프로젝트 import보다 반드시
# 먼저 일어나야 한다. 이전에는 파일 맨 아래 __main__ 블록에서 했는데, 그 시점에는
# 위의 import가 이미 실행된 뒤여서 직접 실행이 항상 ModuleNotFoundError로 끝났다.
# pytest로 돌릴 때는 루트 conftest.py가 같은 일을 하므로 여기서는 중복을 피한다.
#
# 이 블록 때문에 아래 import가 파일 최상단에 오지 못하므로 E402를 끈다.
# ruff: noqa: E402
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "src"))

from runtime import KNOWN_TOOLS, validate_tool_call
from security.tool_schema import (
    LEGACY_COMPAT_PROFILE,
    MCP_TOOL_CATALOG,
    READ_ONLY_PROFILE,
    validate_tool_schema,
)

SANDBOX_ROOT = (PROJECT_ROOT / "sandbox").resolve()


# 함수이름: test_schema_gate_only_catches_exposure_and_limits
# 인자: 없음
# 반환값:
#     None: 반환값 없음
#     AssertionError: schema gate 전담 검사가 사라졌을 때 발생
# 기능 설명:
#     schema gate만 잡을 수 있는 두 가지를 확인한다.
#
#         미노출 도구   validation에는 프로필 개념이 없어 통과시킨다
#         길이 초과     validation에는 maxLength 개념이 없어 통과시킨다
#
#     validation이 이것들을 잡기 시작하면 프로필과 길이 제한이 두 곳에
#     생긴 것이므로 중복이다.
def test_schema_gate_only_catches_exposure_and_limits() -> None:
    # 미노출 도구: read_only 프로필에 run_command는 없다.
    decision = validate_tool_schema(
        READ_ONLY_PROFILE, "run_command", {"command": "cat data/user-001/notes.txt"}
    )
    assert not decision.allowed, "schema gate가 미노출 도구를 통과시켰다"
    assert decision.reason == "TOOL_NOT_EXPOSED_IN_PROFILE", decision.reason

    validation = validate_tool_call(
        "run_command", {"command": "cat data/user-001/notes.txt"}, SANDBOX_ROOT
    )
    assert validation["allowed"], "validation이 노출 통제를 하고 있다(중복)"

    # 길이 초과: inputSchema의 maxLength는 240이다.
    long_path = "data/user-001/" + "a" * 300
    decision = validate_tool_schema(LEGACY_COMPAT_PROFILE, "read_file", {"path": long_path})
    assert not decision.allowed, "schema gate가 길이 초과를 통과시켰다"
    assert decision.reason == "MCP_ARGUMENT_TOO_LONG", decision.reason

    validation = validate_tool_call("read_file", {"path": long_path}, SANDBOX_ROOT)
    assert validation["allowed"], "validation이 길이 제한을 하고 있다(중복)"

    print("schema gate 전담 검사 확인: 노출 통제 · 길이 제한")


# 함수이름: test_validation_only_catches_symlink_escape
# 인자: 없음
# 반환값:
#     None: 반환값 없음
#     AssertionError: 심볼릭 링크 탈출이 막히지 않을 때 발생
# 기능 설명:
#     validation만 잡을 수 있는 것을 확인한다.
#
#     sandbox 안의 심볼릭 링크가 밖을 가리키면, 문자열에는 '..'도 절대 경로도
#     없다. schema gate는 파일시스템을 만지지 않으므로 통과시킨다. resolve()로
#     링크를 따라가는 validation에서만 잡힌다.
#
#     이것이 두 계층을 나눈 가장 분명한 근거다. schema gate가 파일시스템을
#     만지지 않는 것은 결함이 아니라 설계이며, 그래서 싸고 맨 앞에 둘 수 있다.
def test_validation_only_catches_symlink_escape() -> None:
    with tempfile.TemporaryDirectory(prefix="lab-symlink-") as tmp:
        root = Path(tmp)
        sandbox = root / "sandbox"
        (sandbox / "data" / "user-001").mkdir(parents=True)
        outside = root / "outside.txt"
        outside.write_text("SIMULATED_SECRET", encoding="utf-8")

        link = sandbox / "data" / "user-001" / "innocent.txt"
        try:
            link.symlink_to(outside)
        except (OSError, NotImplementedError):  # pragma: no cover - 플랫폼 의존
            print("심볼릭 링크를 만들 수 없는 환경이라 건너뛴다")
            return

        args = {"path": "data/user-001/innocent.txt"}

        decision = validate_tool_schema(LEGACY_COMPAT_PROFILE, "read_file", args)
        assert decision.allowed, (
            "schema gate가 심볼릭 링크를 잡았다. 파일시스템을 만지고 있다는 뜻이므로 "
            "계층 분리가 깨졌다"
        )

        validation = validate_tool_call("read_file", args, sandbox.resolve())
        assert not validation["allowed"], "validation이 sandbox 탈출을 놓쳤다"
        assert str(validation["reason"]).startswith("PATH_ESCAPES_SANDBOX"), validation["reason"]

    print("validation 전담 검사 확인: 심볼릭 링크 탈출")


# 함수이름: test_validation_does_not_check_contract
# 인자: 없음
# 반환값:
#     None: 반환값 없음
#     AssertionError: validation이 인자 계약을 다시 검사할 때 발생
# 기능 설명:
#     [중복 재발 방지] validation이 인자 계약을 검사하지 않는지 확인한다.
#
#     선언되지 않은 인자를 넣어도 validation은 통과시켜야 한다. 계약 위반을
#     거부하는 것은 schema gate의 책임이며, 정상 경로에서는 그 단계가 먼저
#     걸러 낸다.
#
#     이 테스트가 실패하면 ARGUMENT_SPEC 같은 두 번째 계약 목록이 되살아났다는
#     뜻이다. 그대로 두면 두 목록이 어긋나는 순간 도달 불가 분기가 생긴다.
def test_validation_does_not_check_contract() -> None:
    args = {"path": "data/user-001/notes.txt", "recursive": True}

    decision = validate_tool_schema(LEGACY_COMPAT_PROFILE, "read_file", args)
    assert not decision.allowed, "schema gate가 초과 인자를 통과시켰다"
    assert decision.reason == "MCP_ADDITIONAL_ARGUMENT_DENIED", decision.reason

    validation = validate_tool_call("read_file", args, SANDBOX_ROOT)
    assert validation["allowed"], (
        "validation이 초과 인자를 거부했다. 인자 계약 검사가 두 곳으로 갈라졌다"
    )
    assert validation["resolved_path"] is not None, "정규화된 경로를 만들지 못했다"

    print("계약 검사 단일화 확인: validation은 초과 인자를 판정하지 않는다")


# 함수이름: test_validation_fails_closed_without_usable_argument
# 인자: 없음
# 반환값:
#     None: 반환값 없음
#     AssertionError: 쓸 수 없는 인자가 조용히 통과할 때 발생
# 기능 설명:
#     계약 검사는 하지 않지만, 자기 일을 할 수 없으면 거부하는지 확인한다.
#
#     경로를 정규화하려면 문자열 경로가 있어야 한다. 없거나 타입이 다르면
#     정규화 자체가 불가능하므로 거부한다. 이때 오류 코드는 '계약 위반'이
#     아니라 '이 단계가 쓸 수 없는 값'이라는 뜻의 ..._UNUSABLE이다. trace에서
#     두 종류의 거부를 구별할 수 있어야 한다.
#
#     알 수 없는 도구도 정규화할 대상이 없으므로 거부한다(fail closed).
def test_validation_fails_closed_without_usable_argument() -> None:
    missing = validate_tool_call("read_file", {}, SANDBOX_ROOT)
    assert not missing["allowed"]
    assert missing["reason"] == "PATH_ARGUMENT_UNUSABLE", missing["reason"]

    wrong_type = validate_tool_call("read_file", {"path": 123}, SANDBOX_ROOT)
    assert not wrong_type["allowed"]
    assert wrong_type["reason"] == "PATH_ARGUMENT_UNUSABLE", wrong_type["reason"]

    unknown = validate_tool_call("delete_everything", {"path": "x"}, SANDBOX_ROOT)
    assert not unknown["allowed"]
    assert str(unknown["reason"]).startswith("UNKNOWN_TOOL"), unknown["reason"]

    print("fail closed 확인: 쓸 수 없는 인자 · 알 수 없는 도구")


# 함수이름: test_tool_catalog_is_the_single_source
# 인자: 없음
# 반환값:
#     None: 반환값 없음
#     AssertionError: 도구 목록이 두 곳으로 갈라졌을 때 발생
# 기능 설명:
#     Runtime의 KNOWN_TOOLS가 MCP catalog에서 파생되는지 확인한다.
#
#     이전에는 ARGUMENT_SPEC이 두 번째 도구 목록 역할을 했다. 새 도구를 catalog에
#     추가하고 ARGUMENT_SPEC에 빠뜨리면 그 도구는 schema는 통과하는데 validation
#     에서 'unknown tool'로 막혔다. 목록이 하나면 이 부류의 결함이 생기지 않는다.
def test_tool_catalog_is_the_single_source() -> None:
    assert KNOWN_TOOLS == frozenset(MCP_TOOL_CATALOG), (
        "Runtime의 도구 목록이 MCP catalog와 다르다. 두 번째 목록이 생겼다"
    )
    print(f"도구 목록 단일 기준 확인: {len(KNOWN_TOOLS)}개")


# 함수이름: main
# 인자: 없음
# 반환값:
#     None: 반환값 없음
# 기능 설명:
#     다섯 검사를 순서대로 실행한다. pytest 없이 직접 실행할 때의 진입점이다.
def main() -> None:
    test_schema_gate_only_catches_exposure_and_limits()
    test_validation_only_catches_symlink_escape()
    test_validation_does_not_check_contract()
    test_validation_fails_closed_without_usable_argument()
    test_tool_catalog_is_the_single_source()
    print("계층 분리 테스트: PASS")


if __name__ == "__main__":
    # 경로 설정은 파일 상단 부트스트랩 블록에서 이미 끝났다. 여기서 하면 늦다.
    main()
