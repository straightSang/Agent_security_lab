# 실행 요약 — D9-E03

- 실행 번호: `run-d9-e03-c9850b755bea4240a83a87893b0b619a`
- 사건 수: 4

| 순서 | 단계 | 호출 번호 | 핵심 내용 |
|---:|---|---|---|
| 1 | 입력 상태 | `-` | seed_digest=sha256:860a5b6c188bc6dc7df4e7bc528aedf705fe2453bb2f31815a8733f5ca9cae25 |
| 2 | MCP 도구 스키마 | `call-d9-e03` | tool_schema_decision=deny; tool_schema_reason=MCP_ADDITIONAL_ARGUMENT_DENIED; tool_profile=read_only; declared_capability=filesystem.read |
| 3 | 최종 결과 | `call-d9-e03` | ok=거짓; runtime_status=schema_denied; end_stage=tool_schema; error_code=MCP_TOOL_SCHEMA_DENIED |
| 4 | 실험 증거 | `-` | seed_digest=sha256:860a5b6c188bc6dc7df4e7bc528aedf705fe2453bb2f31815a8733f5ca9cae25; decision_digest=sha256:7ace094aa231da63195c5b4a1c9b585c59ef425f645ab7570d2f4fbb1938d899; result_digest=sha256:cc462a3277316c512d9d73f9629be21c0a0e65ceded63731ee06b05b31d07504 |

원본 JSONL은 같은 폴더의 `trace.jsonl`에 보존된다.
