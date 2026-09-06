# 실행 요약 — D9-E04

- 실행 번호: `run-d9-e04-9f2e923e9e8f4fe7bf33078ea50b639e`
- 사건 수: 4

| 순서 | 단계 | 호출 번호 | 핵심 내용 |
|---:|---|---|---|
| 1 | 입력 상태 | `-` | seed_digest=sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945 |
| 2 | MCP 도구 스키마 | `call-d9-e04` | tool_schema_decision=deny; tool_schema_reason=MCP_PATH_OUTSIDE_PROFILE_SCOPE; tool_profile=read_only; declared_capability=filesystem.read |
| 3 | 최종 결과 | `call-d9-e04` | ok=거짓; runtime_status=schema_denied; end_stage=tool_schema; error_code=MCP_TOOL_SCHEMA_DENIED |
| 4 | 실험 증거 | `-` | seed_digest=sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945; decision_digest=sha256:c6a292a8823bea5993137004b5b29d3e09f0fd2a74e3895943577b4a14804762; result_digest=sha256:4ed5f8d9a7cf099ed7e53a0d7f8a80b4acc28400dd196c15b424fe507a8a0cf8 |

원본 JSONL은 같은 폴더의 `trace.jsonl`에 보존된다.
