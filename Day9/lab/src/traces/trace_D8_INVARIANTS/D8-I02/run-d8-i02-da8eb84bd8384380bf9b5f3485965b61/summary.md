# 실행 요약 — D8-I02

- 실행 번호: `run-d8-i02-da8eb84bd8384380bf9b5f3485965b61`
- 사건 수: 7

| 순서 | 단계 | 호출 번호 | 핵심 내용 |
|---:|---|---|---|
| 1 | 입력 상태 | `-` | seed_digest=sha256:bce8bae1fa34237a61cc9760a36db91bb875c3f8d0fe110691155bb78f9e2945 |
| 2 | 형식 검사 | `call-d8-i02-authz-deny` | validation_allowed=참 |
| 3 | 실행 요청 | `call-d8-i02-authz-deny` | actor=user-001; tool_name=read_file; capability=filesystem.read; action=read; resource=data/user-002/private.txt |
| 4 | 정책 판단 | `call-d8-i02-authz-deny` | policy_decision=allow; reason=BASELINE_CAPABILITY_ALLOWED; rule_id=BASELINE_CAPABILITY_ALLOWED; trust=user_controlled |
| 5 | 인가 판단 | `call-d8-i02-authz-deny` | authorization_decision=deny; authorization_reason=ACTOR_NOT_RESOURCE_OWNER |
| 6 | 최종 결과 | `call-d8-i02-authz-deny` | ok=거짓; runtime_status=forbidden; end_stage=authorization; error_code=FORBIDDEN |
| 7 | 실험 증거 | `-` | seed_digest=sha256:bce8bae1fa34237a61cc9760a36db91bb875c3f8d0fe110691155bb78f9e2945; decision_digest=sha256:7edc89dd8ad505d229f0e7a3fabdc5511e486aca42b64ec70b227dde3543ffd3; result_digest=sha256:b4d35ad4298c6ee623ee708f4ddad9f5b4663355bdd8e61e56cc1fbee53ef11a |

원본 JSONL은 같은 폴더의 `trace.jsonl`에 보존된다.
