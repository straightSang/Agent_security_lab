# 실행 요약 — D9-E02

- 실행 번호: `run-d9-e02-8ef65dd5cbe14cce9751a835292a33de`
- 사건 수: 4

| 순서 | 단계 | 호출 번호 | 핵심 내용 |
|---:|---|---|---|
| 1 | 입력 상태 | `-` | seed_digest=sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945 |
| 2 | MCP 도구 스키마 | `call-d9-e02` | tool_schema_decision=deny; tool_schema_reason=TOOL_NOT_EXPOSED_IN_PROFILE; tool_profile=read_only |
| 3 | 최종 결과 | `call-d9-e02` | ok=거짓; runtime_status=schema_denied; end_stage=tool_schema; error_code=MCP_TOOL_SCHEMA_DENIED |
| 4 | 실험 증거 | `-` | seed_digest=sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945; decision_digest=sha256:6aea463d08212829520c5cfe65811e7c734e1b1dd8a4e346486575ccfc69e204; result_digest=sha256:e33c61fd164999d265c0f0e4509a3a35181c418e1218f7be8594555c88ae0e89 |

원본 JSONL은 같은 폴더의 `trace.jsonl`에 보존된다.
