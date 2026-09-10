# 실행 요약 — D9-E08

- 실행 번호: `run-d9-e08-d23a7afdafea45cdad2abb0682f513e7`
- 사건 수: 8

| 순서 | 단계 | 호출 번호 | 핵심 내용 |
|---:|---|---|---|
| 1 | 입력 상태 | `-` | seed_digest=sha256:bce8bae1fa34237a61cc9760a36db91bb875c3f8d0fe110691155bb78f9e2945 |
| 2 | MCP 도구 스키마 | `call-d9-e08-authz-deny` | tool_schema_decision=allow; tool_schema_reason=MCP_TOOL_SCHEMA_ALLOWED; tool_profile=write_enabled; declared_capability=filesystem.read |
| 3 | 형식 검사 | `call-d9-e08-authz-deny` | validation_allowed=참 |
| 4 | 실행 요청 | `call-d9-e08-authz-deny` | actor=user-001; tool_name=read_file; capability=filesystem.read; action=read; resource=data/user-002/private.txt |
| 5 | 정책 판단 | `call-d9-e08-authz-deny` | policy_decision=allow; reason=BASELINE_CAPABILITY_ALLOWED; rule_id=BASELINE_CAPABILITY_ALLOWED; trust=user_controlled |
| 6 | 인가 판단 | `call-d9-e08-authz-deny` | authorization_decision=deny; authorization_reason=ACTOR_NOT_RESOURCE_OWNER |
| 7 | 최종 결과 | `call-d9-e08-authz-deny` | ok=거짓; runtime_status=forbidden; end_stage=authorization; error_code=FORBIDDEN |
| 8 | 실험 증거 | `-` | seed_digest=sha256:bce8bae1fa34237a61cc9760a36db91bb875c3f8d0fe110691155bb78f9e2945; decision_digest=sha256:cd7d1596b9070573f7b440dc0184ed5fcd7735e043839cc3ade98123848dba35; result_digest=sha256:b177003f5acc872359c2bfda667d15d109283872d2a52b9ccff9c29410fba018 |

원본 JSONL은 같은 폴더의 `trace.jsonl`에 보존된다.
