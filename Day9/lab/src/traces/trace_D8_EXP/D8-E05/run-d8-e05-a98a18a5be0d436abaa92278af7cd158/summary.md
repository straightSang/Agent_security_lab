# 실행 요약 — D8-E05

- 실행 번호: `run-d8-e05-a98a18a5be0d436abaa92278af7cd158`
- 사건 수: 7

| 순서 | 단계 | 호출 번호 | 핵심 내용 |
|---:|---|---|---|
| 1 | 입력 상태 | `-` | seed_digest=sha256:bce8bae1fa34237a61cc9760a36db91bb875c3f8d0fe110691155bb78f9e2945 |
| 2 | 형식 검사 | `call-d8-e05-cross-user-read` | validation_allowed=참 |
| 3 | 실행 요청 | `call-d8-e05-cross-user-read` | actor=user-001; tool_name=read_file; capability=filesystem.read; action=read; resource=data/user-002/private.txt |
| 4 | 정책 판단 | `call-d8-e05-cross-user-read` | policy_decision=allow; reason=BASELINE_CAPABILITY_ALLOWED; rule_id=BASELINE_CAPABILITY_ALLOWED; trust=user_controlled |
| 5 | 인가 판단 | `call-d8-e05-cross-user-read` | authorization_decision=deny; authorization_reason=ACTOR_NOT_RESOURCE_OWNER |
| 6 | 최종 결과 | `call-d8-e05-cross-user-read` | ok=거짓; runtime_status=forbidden; end_stage=authorization; error_code=FORBIDDEN |
| 7 | 실험 증거 | `-` | seed_digest=sha256:bce8bae1fa34237a61cc9760a36db91bb875c3f8d0fe110691155bb78f9e2945; decision_digest=sha256:94309f130a3e2451f049b89c3ffee6f3916796b2a0e097ef9fc16da5eb9ce721; result_digest=sha256:0205d92853a3bb1be57eb6f87dc3799fb281f3c958ff663526833718be3ed34f |

원본 JSONL은 같은 폴더의 `trace.jsonl`에 보존된다.
