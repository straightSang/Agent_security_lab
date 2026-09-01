# 실행 요약 — D9-E03

- 실행 번호: `run-d9-e03-5d1eadcd21fa4957ac77349db6b43a64`
- 사건 수: 4

| 순서 | 단계 | 호출 번호 | 핵심 내용 |
|---:|---|---|---|
| 1 | 입력 상태 | `-` | seed_digest=sha256:860a5b6c188bc6dc7df4e7bc528aedf705fe2453bb2f31815a8733f5ca9cae25 |
| 2 | MCP 도구 스키마 | `call-d9-e03` | tool_schema_decision=deny; tool_schema_reason=MCP_ADDITIONAL_ARGUMENT_DENIED; tool_profile=read_only; declared_capability=filesystem.read |
| 3 | 최종 결과 | `call-d9-e03` | ok=거짓; runtime_status=schema_denied; end_stage=tool_schema; error_code=MCP_TOOL_SCHEMA_DENIED |
| 4 | 실험 증거 | `-` | seed_digest=sha256:860a5b6c188bc6dc7df4e7bc528aedf705fe2453bb2f31815a8733f5ca9cae25; decision_digest=sha256:5c466add17a46bccc8f36ad4c8d8f4dd355f54373060c378c8f741eb939f6288; result_digest=sha256:e4475a55f619f1b461b220739d84ebf3c29927150bf9218edc27681583c241d0 |

원본 JSONL은 같은 폴더의 `trace.jsonl`에 보존된다.
