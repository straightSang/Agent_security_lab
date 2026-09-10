# 실행 요약 — D9-E04

- 실행 번호: `run-d9-e04-f2513297a001439e8ac1d091f696b87b`
- 사건 수: 4

| 순서 | 단계 | 호출 번호 | 핵심 내용 |
|---:|---|---|---|
| 1 | 입력 상태 | `-` | seed_digest=sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945 |
| 2 | MCP 도구 스키마 | `call-d9-e04` | tool_schema_decision=deny; tool_schema_reason=MCP_PATH_OUTSIDE_PROFILE_SCOPE; tool_profile=read_only; declared_capability=filesystem.read |
| 3 | 최종 결과 | `call-d9-e04` | ok=거짓; runtime_status=schema_denied; end_stage=tool_schema; error_code=MCP_TOOL_SCHEMA_DENIED |
| 4 | 실험 증거 | `-` | seed_digest=sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945; decision_digest=sha256:38efc8a99aa4ebbd93c1481dd0c88d2ff0e18abafd68cf092962d010dbac2630; result_digest=sha256:1427582f9b6c1259f9ea43df34dc09f97a94c7da0bb865821681cec04979d244 |

원본 JSONL은 같은 폴더의 `trace.jsonl`에 보존된다.
