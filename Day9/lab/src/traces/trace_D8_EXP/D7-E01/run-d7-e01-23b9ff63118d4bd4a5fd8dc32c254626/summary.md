# 실행 요약 — D7-E01

- 실행 번호: `run-d7-e01-23b9ff63118d4bd4a5fd8dc32c254626`
- 사건 수: 8

| 순서 | 단계 | 호출 번호 | 핵심 내용 |
|---:|---|---|---|
| 1 | 입력 상태 | `-` | seed_digest=sha256:000de1fdcc1e1c258ddd5969393f809bf1220d3591e29ad08df804d91fc82659 |
| 2 | 형식 검사 | `call-d7-e01-read` | validation_allowed=참 |
| 3 | 실행 요청 | `call-d7-e01-read` | actor=user-001; tool_name=read_file; capability=filesystem.read; action=read; resource=data/user-001/benign_email.txt |
| 4 | 정책 판단 | `call-d7-e01-read` | policy_decision=allow; reason=BASELINE_CAPABILITY_ALLOWED; rule_id=BASELINE_CAPABILITY_ALLOWED; trust=user_controlled |
| 5 | 인가 판단 | `call-d7-e01-read` | authorization_decision=allow; authorization_reason=RESOURCE_OWNER |
| 6 | 최종 결과 | `call-d7-e01-read` | ok=참; runtime_status=success; end_stage=runtime |
| 7 | 관찰 결과 | `call-d7-e01-read` | source_kind=repository_content; source_trust=untrusted; source=data/user-001/benign_email.txt |
| 8 | 실험 증거 | `-` | seed_digest=sha256:000de1fdcc1e1c258ddd5969393f809bf1220d3591e29ad08df804d91fc82659; decision_digest=sha256:67a5db5a93f2a6f47d090e6372c537bd4d5c947a167dfe89f6e7a4e93f1f6734; result_digest=sha256:40c78d9668212c947282586acc7f1372fb142967f1383e4d65637af448cde044 |

원본 JSONL은 같은 폴더의 `trace.jsonl`에 보존된다.
