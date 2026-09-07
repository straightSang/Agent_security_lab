# [RFC-001 회귀] 공개 인터페이스 검사.
#
# 왜 이 테스트가 필요한가
# -----------------------
# 이 저장소는 "도구가 실행되는 지점은 _dispatch() 하나뿐이며, 거기 도달하려면
# 여섯 관문을 순서대로 통과해야 한다"고 주장한다. 그 주장을 검증하려는 사람은
# 공개된 진입점을 전부 확인해야 한다.
#
# RFC-001 이전에는 agent.__all__에 14개가 올라가 있었고, 그중 12개는 어떤
# 파일도 import하지 않았다. 실제 인터페이스는 2개인데 감사 비용은 14개어치였다.
#
# 그 12개에는 "Day 1~8 호환용"이라는 주석이 붙어 있었다. 그러나 Day 1~8 코드는
# 이 저장소에 없다. 단일 트리로 옮기면서 AI_security_Lab에 남겨 뒀다. 어댑터가
# 가리키는 대상이 존재하지 않았던 것이다.
#
# 이 테스트는 그 상태로 돌아가지 못하게 막는다. 세 가지를 검사한다.
#
#     1. __all__의 모든 이름이 실제로 쓰이거나 PLANNED에 등록되어 있다
#     2. PLANNED에 등록된 것이 이미 쓰이고 있으면 목록에서 빼라고 알린다
#     3. Runtime을 우회할 수 있는 공개 이름이 없다
#
# 2번이 특히 중요하다. "나중에 쓸 거라서 남겨 둔다"가 주석 속 구전이 아니라
# 깨질 수 있는 선언이 된다. W1 D4가 끝나면 run_agent_loop이 PLANNED에서 자동으로
# 빠져야 하고, 안 빠지면 이 테스트가 알려 준다.

from __future__ import annotations

# 이 파일은 importlib로 agent 모듈을 직접 불러오므로 src/가
# import 경로에 있어야 한다. 이전에는 파일 맨 아래 __main__ 블록에서 넣었는데,
# 그 시점에는 이미 늦어 직접 실행이 ModuleNotFoundError로 끝났다.
import ast
import importlib
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC = PROJECT_ROOT / "src"
TESTS = PROJECT_ROOT / "tests"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

# 공개 인터페이스를 가진 모듈. 여기 없는 모듈은 내부 구현으로 본다.
PUBLIC_MODULES = ("agent",)

# 아직 쓰이지 않지만 의도적으로 공개한 이름과 그 사유.
#
# 사유 없이 넣을 수 없다. 사유를 적는 순간 "언제 이 항목이 사라져야 하는가"가
# 명시되고, 그때가 되면 아래 test_planned_entries_are_still_pending()이
# 목록에서 빼라고 알려 준다.
PLANNED: dict[str, str] = {
    "run_agent_loop": "W1 D4 model-in-the-loop 기준선 측정에서 사용 예정",
}


# 함수이름: _imported_names
# 인자: 없음
# 반환값:
#     dict[str, set[str]]: {모듈명: 그 모듈에서 import된 이름 집합}
# 기능 설명:
#     src/와 tests/의 모든 파일을 ast로 파싱해 'from <모듈> import <이름>'
#     구문을 수집한다.
#
#     문자열 검색을 쓰지 않는 이유는 부분 일치 때문이다. 'TOOLS'로 grep하면
#     READ_ONLY_TOOLS, PATH_TOOLS, KNOWN_TOOLS가 전부 잡혀 실제로는 죽은
#     이름이 살아 있는 것처럼 보인다. RFC-001의 감사도 이 방식으로 했다.
#
#     자기 자신(공개 모듈)의 파일은 제외한다. 모듈이 자기 이름을 쓰는 것은
#     '바깥에서 쓰인다'는 증거가 아니기 때문이다.
def _imported_names() -> dict[str, set[str]]:
    found: dict[str, set[str]] = {module: set() for module in PUBLIC_MODULES}
    for path in list(SRC.rglob("*.py")) + list(TESTS.glob("*.py")):
        if path.stem in PUBLIC_MODULES:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module in found:
                for alias in node.names:
                    found[node.module].add(alias.name)
    return found


# 함수이름: test_no_dead_public_names
# 인자: 없음
# 반환값:
#     None: 반환값 없음
#     AssertionError: 아무도 쓰지 않고 PLANNED에도 없는 공개 이름이 있을 때 발생
# 기능 설명:
#     [RFC-001 핵심 검사] __all__의 모든 이름이 정당화되는지 확인한다.
#
#     허용되는 경우는 둘뿐이다.
#
#         (a) 저장소 안 어딘가에서 실제로 import된다
#         (b) PLANNED에 사유와 함께 등록되어 있다
#
#     둘 다 아니면 죽은 공개 표면이다. 감사 비용만 늘리고 나중에 악용될 수 있다.
def test_no_dead_public_names() -> None:
    used = _imported_names()
    dead: list[str] = []

    for module_name in PUBLIC_MODULES:
        module = importlib.import_module(module_name)
        exported = getattr(module, "__all__", None)
        assert exported is not None, f"{module_name}에 __all__이 없다. 공개 인터페이스가 선언되지 않았다"

        for name in exported:
            if name in used[module_name] or name in PLANNED:
                continue
            dead.append(f"{module_name}.{name}")

    assert not dead, (
        "아무도 import하지 않는 공개 이름이 있다. 삭제하거나 PLANNED에 사유와 함께 등록하라:\n  - "
        + "\n  - ".join(dead)
    )
    total = sum(len(getattr(importlib.import_module(m), "__all__", [])) for m in PUBLIC_MODULES)
    print(f"공개 인터페이스 확인: {total}개 전부 정당화됨 (사용 중 또는 PLANNED)")


# 함수이름: test_planned_entries_are_still_pending
# 인자: 없음
# 반환값:
#     None: 반환값 없음
#     AssertionError: PLANNED 항목이 이미 쓰이고 있을 때 발생
# 기능 설명:
#     PLANNED가 유효기간이 지난 채로 남아 있지 않은지 확인한다.
#
#     "나중에 쓸 거라서 남겨 둔다"는 주석은 시간이 지나면 아무도 검증하지
#     않는다. 여기서는 그것이 깨질 수 있는 선언이 된다. 해당 이름이 실제로
#     쓰이기 시작하면 이 테스트가 실패하면서 PLANNED에서 빼라고 알려 준다.
#
#     PLANNED에 있지만 __all__에는 없는 항목도 잡는다. 목록이 서로 어긋나면
#     둘 중 하나가 낡은 것이다.
def test_planned_entries_are_still_pending() -> None:
    used = _imported_names()
    all_exported: set[str] = set()
    all_used: set[str] = set()
    for module_name in PUBLIC_MODULES:
        module = importlib.import_module(module_name)
        all_exported.update(getattr(module, "__all__", []))
        all_used.update(used[module_name])

    graduated = sorted(name for name in PLANNED if name in all_used)
    assert not graduated, (
        "PLANNED 항목이 이미 사용되고 있다. PLANNED에서 제거하라:\n  - "
        + "\n  - ".join(f"{n} ({PLANNED[n]})" for n in graduated)
    )

    orphaned = sorted(name for name in PLANNED if name not in all_exported)
    assert not orphaned, (
        "PLANNED에 있지만 __all__에는 없는 항목이다. 둘 중 하나가 낡았다:\n  - "
        + "\n  - ".join(orphaned)
    )

    for name, reason in sorted(PLANNED.items()):
        print(f"PLANNED 확인: {name} — {reason}")


# 함수이름: test_public_surface_cannot_bypass_runtime
# 인자: 없음
# 반환값:
#     None: 반환값 없음
#     AssertionError: 실행 경계를 우회할 수 있는 공개 이름이 있을 때 발생
# 기능 설명:
#     공개된 이름 중 Runtime을 거치지 않고 도구를 실행할 수 있는 것이 없는지
#     확인한다.
#
#     실행 지점은 _dispatch() 하나뿐이어야 하므로 
#     공개 표면에 그것을 우회하는 통로가 있으면 안 된다. 
#     여기서는 금지 이름 목록으로 방어한다 
#      — dispatch나 실제 파일 조작 함수가 공개로 올라오면 즉시 실패한다.
def test_public_surface_cannot_bypass_runtime() -> None:
    forbidden = {"_dispatch", "dispatch", "_read_file", "_write_file", "_run_command", "_list_files"}
    leaked: list[str] = []
    for module_name in PUBLIC_MODULES:
        module = importlib.import_module(module_name)
        for name in getattr(module, "__all__", []):
            if name in forbidden:
                leaked.append(f"{module_name}.{name}")

    assert not leaked, (
        "실행 경계를 우회할 수 있는 이름이 공개되었다:\n  - " + "\n  - ".join(leaked)
    )
    print(f"우회 경로 확인: 금지 이름 {len(forbidden)}종 모두 비공개")


# 함수이름: test_entry_point_count_is_small
# 인자: 없음
# 반환값:
#     None: 반환값 없음
#     AssertionError: 공개 진입점이 상한을 넘을 때 발생
# 기능 설명:
#     공개 진입점 수에 상한을 둔다.
#
#     숫자 자체가 목적은 아니다. 상한이 있으면 새 이름을 공개할 때마다
#     "이게 정말 인터페이스인가"를 한 번 더 묻게 된다는 점이 목적이다. 늘려야 할
#     이유가 생기면 이 상수를 올리되, 그때 RFC에 근거를 남긴다.
def test_entry_point_count_is_small() -> None:
    limit = 5
    for module_name in PUBLIC_MODULES:
        module = importlib.import_module(module_name)
        exported = getattr(module, "__all__", [])
        assert len(exported) <= limit, (
            f"{module_name}.__all__이 {len(exported)}개로 상한 {limit}개를 넘었다. "
            f"정말 공개 인터페이스인지 검토하고, 맞다면 근거를 RFC에 남기고 상한을 올려라"
        )
        print(f"진입점 수 확인: {module_name} {len(exported)}개 (상한 {limit})")


# 함수이름: main
# 인자: 없음
# 반환값:
#     None: 반환값 없음
# 기능 설명:
#     네 검사를 순서대로 실행한다. pytest 없이 직접 실행할 때의 진입점이다.
def main() -> None:
    test_no_dead_public_names()
    test_planned_entries_are_still_pending()
    test_public_surface_cannot_bypass_runtime()
    test_entry_point_count_is_small()
    print("공개 인터페이스 테스트: PASS")


if __name__ == "__main__":
    main()
