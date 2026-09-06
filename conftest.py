# 모듈이름: conftest
# 역할: pytest와 직접 실행 양쪽에서 src/를 import 경로에 넣는다
# 호출 주체: pytest가 자동으로 읽는다
#
# 기능 설명:
#     [C-04] Day별 폴더 구조에서는 각 테스트를 src 안에서 개별 실행해야 했다.
#     단일 트리로 통합하면서 저장소 루트에서 `pytest` 한 번으로 전체 회귀를
#     돌릴 수 있게 한다.

import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
