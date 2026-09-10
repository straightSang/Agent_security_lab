# 실행 요약 — D8-E05

- 실행 번호: `run-d8-e05-3216dd2af100475a9a8f28267699020b`
- 사건 수: 8

| 순서 | 단계 | 호출 번호 | 핵심 내용 |
|---:|---|---|---|
| 1 | 입력 상태 | `-` | seed_digest=sha256:bce8bae1fa34237a61cc9760a36db91bb875c3f8d0fe110691155bb78f9e2945 |
| 2 | MCP 도구 스키마 | `call-d8-e05-cross-user-read` | tool_schema_decision=allow; tool_schema_reason=MCP_TOOL_SCHEMA_ALLOWED; tool_profile=write_enabled; declared_capability=filesystem.read |
| 3 | 형식 검사 | `call-d8-e05-cross-user-read` | validation_allowed=참 |
| 4 | 실행 요청 | `call-d8-e05-cross-user-read` | actor=user-001; tool_name=read_file; capability=filesystem.read; action=read; resource=data/user-002/private.txt |
| 5 | 정책 판단 | `call-d8-e05-cross-user-read` | policy_decision=allow; reason=BASELINE_CAPABILITY_ALLOWED; rule_id=BASELINE_CAPABILITY_ALLOWED; trust=user_controlled |
| 6 | 인가 판단 | `call-d8-e05-cross-user-read` | authorization_decision=deny; authorization_reason=ACTOR_NOT_RESOURCE_OWNER |
| 7 | 최종 결과 | `call-d8-e05-cross-user-read` | ok=거짓; runtime_status=forbidden; end_stage=authorization; error_code=FORBIDDEN |
| 8 | 실험 증거 | `-` | seed_digest=sha256:bce8bae1fa34237a61cc9760a36db91bb875c3f8d0fe110691155bb78f9e2945; decision_digest=sha256:ab955e0e3908f61207e8bc0e318d2cc3ba602a15dd97d4ea21ca2b2bfc3b0062; result_digest=sha256:7a621b4d9a47c673c8d135128d6a7609d3bc28ad3f0d91b2948c2d71d7a52d37 |

원본 JSONL은 같은 폴더의 `trace.jsonl`에 보존된다.
