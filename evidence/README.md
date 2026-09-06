# evidence/

보고서가 인용하는 **승격된 run만** 여기에 둔다.

회귀 테스트의 trace 기본 출력은 임시 디렉터리다(`src/lab_paths.py`의 `trace_root()`).
테스트 산출물은 폐기 가능해야 하고 증거는 append-only여야 하는데, 두 요구가 같은
경로를 쓰면 충돌하기 때문이다.

특정 run을 증거로 남기려면 출력 위치를 명시적으로 지정한다.

```bash
LAB_TRACE_ROOT=evidence/EXP-2026-001 pytest tests/test_mcp_tool_schema.py
```

승격한 run은 해당 날짜의 `docs/notes/DayNN_*.md`에서 참조하고, 노트에는 그때의
커밋 해시를 함께 적는다.
