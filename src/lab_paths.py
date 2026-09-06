# 모듈이름: lab_paths
# 역할: 저장소 전체가 공유하는 경로 상수
# 호출 주체: src/의 모든 모듈과 tests/
#
# 기능 설명:
#     [C-02] Day별 폴더 복사 구조를 단일 트리로 통합하면서, 경로를 각 모듈이
#     제각각 계산하지 않도록 한 곳에 모았다. 모든 경로는 저장소 루트 기준이다.
#
#     [C-03] trace 기본 출력은 저장소 안이 아니라 임시 디렉터리다. 자세한 이유는
#     trace_root() 주석 참조.

from __future__ import annotations

import os
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

SRC_DIR = PROJECT_ROOT / "src"
SANDBOX_ROOT = PROJECT_ROOT / "sandbox"
FIXTURE_DIR = PROJECT_ROOT / "fixtures"
SCHEMA_DIR = PROJECT_ROOT / "schemas"
EVIDENCE_DIR = PROJECT_ROOT / "evidence"
DOCS_DIR = PROJECT_ROOT / "docs"


# 함수이름: trace_root
# 인자: 없음
# 반환값:
#     Path: trace 출력 루트 디렉터리. 없으면 생성해서 돌려준다
# 기능 설명:
#     trace를 어디에 남길지 결정한다. 기본은 임시 디렉터리다.
#
#     회귀 테스트를 돌릴 때마다 저장소에 trace가 쌓이면 증거 디렉터리가 무한히
#     커지고 "어느 trace가 보고서의 근거인가"가 흐려진다. 테스트 산출물은 폐기
#     가능해야 하고 증거는 append-only여야 하는데, 두 요구가 같은 경로를 쓰면
#     충돌한다.
#
#     LAB_TRACE_ROOT=evidence/<experiment-id> 로 지정해 명시적으로 승격한다.
def trace_root() -> Path:
    override = os.environ.get("LAB_TRACE_ROOT")
    if override:
        root = Path(override).expanduser().resolve()
    else:
        root = Path(tempfile.gettempdir()) / "ai_agent_security_lab" / "traces"
    root.mkdir(parents=True, exist_ok=True)
    return root
