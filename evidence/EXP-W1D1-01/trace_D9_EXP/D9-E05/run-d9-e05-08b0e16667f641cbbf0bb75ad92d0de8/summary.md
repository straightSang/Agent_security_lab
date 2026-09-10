# 실행 요약 — D9-E05

- 실행 번호: `run-d9-e05-08b0e16667f641cbbf0bb75ad92d0de8`
- 사건 수: 4

| 순서 | 단계 | 호출 번호 | 핵심 내용 |
|---:|---|---|---|
| 1 | 입력 상태 | `-` | seed_digest=sha256:860a5b6c188bc6dc7df4e7bc528aedf705fe2453bb2f31815a8733f5ca9cae25 |
| 2 | MCP 도구 스키마 | `call-d9-e05` | tool_schema_decision=deny; tool_schema_reason=TOOL_NOT_EXPOSED_IN_PROFILE; tool_profile=write_enabled |
| 3 | 최종 결과 | `call-d9-e05` | ok=거짓; runtime_status=schema_denied; end_stage=tool_schema; error_code=MCP_TOOL_SCHEMA_DENIED |
| 4 | 실험 증거 | `-` | seed_digest=sha256:860a5b6c188bc6dc7df4e7bc528aedf705fe2453bb2f31815a8733f5ca9cae25; decision_digest=sha256:445e6989b47c6da37d9583aedafd07c62d995251fcf626ab0344fccbdcf616b0; result_digest=sha256:ceb56ddcf594ffda08f2902e6857587d58b5d9dc301301990340776ad6357284 |

원본 JSONL은 같은 폴더의 `trace.jsonl`에 보존된다.
