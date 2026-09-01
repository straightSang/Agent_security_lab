# 실행 요약 — D9-E02

- 실행 번호: `run-d9-e02-20e568a14b7a4f08ae896bd7947a42f3`
- 사건 수: 4

| 순서 | 단계 | 호출 번호 | 핵심 내용 |
|---:|---|---|---|
| 1 | 입력 상태 | `-` | seed_digest=sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945 |
| 2 | MCP 도구 스키마 | `call-d9-e02` | tool_schema_decision=deny; tool_schema_reason=TOOL_NOT_EXPOSED_IN_PROFILE; tool_profile=read_only |
| 3 | 최종 결과 | `call-d9-e02` | ok=거짓; runtime_status=schema_denied; end_stage=tool_schema; error_code=MCP_TOOL_SCHEMA_DENIED |
| 4 | 실험 증거 | `-` | seed_digest=sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945; decision_digest=sha256:d35c664c8bcc63ebf426beb8c5e07fc84fc14034fb721cd072718cfc72ca1a3b; result_digest=sha256:c0eab6b3c82d5aec195b093e1bff32297fd08c644ca76e8e06dde787d3ac2ef1 |

원본 JSONL은 같은 폴더의 `trace.jsonl`에 보존된다.
