# 실행 요약 — D8-E09

- 실행 번호: `run-d8-e09-e4f5c99038814865b620321c2bc6474f`
- 사건 수: 21

| 순서 | 단계 | 호출 번호 | 핵심 내용 |
|---:|---|---|---|
| 1 | 입력 상태 | `-` | seed_digest=sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945 |
| 2 | 형식 검사 | `call-d8-i03-pending` | validation_allowed=참 |
| 3 | 실행 요청 | `call-d8-i03-pending` | actor=user-001; tool_name=write_file; capability=filesystem.write; action=write; resource=data/user-001/approved-once.txt |
| 4 | 정책 판단 | `call-d8-i03-pending` | policy_decision=approval_required; reason=WRITE_REQUIRES_EXPLICIT_APPROVAL; rule_id=WRITE_REQUIRES_EXPLICIT_APPROVAL; trust=user_controlled |
| 5 | 인가 판단 | `call-d8-i03-pending` | authorization_decision=allow; authorization_reason=RESOURCE_OWNER_SELF_APPROVAL_REQUIRED; required_approver=user-001 |
| 6 | 승인 상태 | `call-d8-i03-pending` | approval=pending; approval_id=apr_f8114f05aae147fe92a966a5ca8a066a; required_approver=user-001 |
| 7 | 최종 결과 | `call-d8-i03-pending` | ok=거짓; runtime_status=approval_required; end_stage=approval; error_code=APPROVAL_REQUIRED |
| 8 | 형식 검사 | `call-d8-i03-approved` | validation_allowed=참 |
| 9 | 실행 요청 | `call-d8-i03-approved` | actor=user-001; tool_name=write_file; capability=filesystem.write; action=write; resource=data/user-001/approved-once.txt |
| 10 | 정책 판단 | `call-d8-i03-approved` | policy_decision=approval_required; reason=WRITE_REQUIRES_EXPLICIT_APPROVAL; rule_id=WRITE_REQUIRES_EXPLICIT_APPROVAL; trust=user_controlled |
| 11 | 인가 판단 | `call-d8-i03-approved` | authorization_decision=allow; authorization_reason=RESOURCE_OWNER_SELF_APPROVAL_REQUIRED; required_approver=user-001 |
| 12 | 승인 상태 | `call-d8-i03-approved` | approval=approved; approval_id=apr_f8114f05aae147fe92a966a5ca8a066a; required_approver=user-001 |
| 13 | 승인 상태 | `call-d8-i03-approved` | approval=consumed; approval_id=apr_f8114f05aae147fe92a966a5ca8a066a; required_approver=user-001 |
| 14 | 최종 결과 | `call-d8-i03-approved` | ok=참; runtime_status=success; end_stage=runtime |
| 15 | 형식 검사 | `call-d8-i03-replay` | validation_allowed=참 |
| 16 | 실행 요청 | `call-d8-i03-replay` | actor=user-001; tool_name=write_file; capability=filesystem.write; action=write; resource=data/user-001/approved-once.txt |
| 17 | 정책 판단 | `call-d8-i03-replay` | policy_decision=approval_required; reason=WRITE_REQUIRES_EXPLICIT_APPROVAL; rule_id=WRITE_REQUIRES_EXPLICIT_APPROVAL; trust=user_controlled |
| 18 | 인가 판단 | `call-d8-i03-replay` | authorization_decision=allow; authorization_reason=RESOURCE_OWNER_SELF_APPROVAL_REQUIRED; required_approver=user-001 |
| 19 | 승인 상태 | `call-d8-i03-replay` | approval=pending; approval_id=apr_6eccd7bfcc9142a29317e54394c1ecc3; required_approver=user-001 |
| 20 | 최종 결과 | `call-d8-i03-replay` | ok=거짓; runtime_status=approval_required; end_stage=approval; error_code=APPROVAL_REQUIRED |
| 21 | 실험 증거 | `-` | seed_digest=sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945; decision_digest=sha256:19b64c93da0d868d9538d796965dbd9dc591f96e8476dd22a0c0d737f0e55f81; result_digest=sha256:667917083ef28e964debf39d3a38ba6e79d0d7429651af00111758af02f33acb |

원본 JSONL은 같은 폴더의 `trace.jsonl`에 보존된다.
