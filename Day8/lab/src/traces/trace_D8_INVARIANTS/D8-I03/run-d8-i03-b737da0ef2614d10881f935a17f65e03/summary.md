# 실행 요약 — D8-I03

- 실행 번호: `run-d8-i03-b737da0ef2614d10881f935a17f65e03`
- 사건 수: 21

| 순서 | 단계 | 호출 번호 | 핵심 내용 |
|---:|---|---|---|
| 1 | 입력 상태 | `-` | seed_digest=sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945 |
| 2 | 형식 검사 | `call-d8-i03-pending` | validation_allowed=참 |
| 3 | 실행 요청 | `call-d8-i03-pending` | actor=user-001; tool_name=write_file; capability=filesystem.write; action=write; resource=data/user-001/approved-once.txt |
| 4 | 정책 판단 | `call-d8-i03-pending` | policy_decision=approval_required; reason=WRITE_REQUIRES_EXPLICIT_APPROVAL; rule_id=WRITE_REQUIRES_EXPLICIT_APPROVAL; trust=user_controlled |
| 5 | 인가 판단 | `call-d8-i03-pending` | authorization_decision=allow; authorization_reason=RESOURCE_OWNER_SELF_APPROVAL_REQUIRED; required_approver=user-001 |
| 6 | 승인 상태 | `call-d8-i03-pending` | approval=pending; approval_id=apr_6a9db4cd4a8a49acaec1f9d6793d4d2d; required_approver=user-001 |
| 7 | 최종 결과 | `call-d8-i03-pending` | ok=거짓; runtime_status=approval_required; end_stage=approval; error_code=APPROVAL_REQUIRED |
| 8 | 형식 검사 | `call-d8-i03-approved` | validation_allowed=참 |
| 9 | 실행 요청 | `call-d8-i03-approved` | actor=user-001; tool_name=write_file; capability=filesystem.write; action=write; resource=data/user-001/approved-once.txt |
| 10 | 정책 판단 | `call-d8-i03-approved` | policy_decision=approval_required; reason=WRITE_REQUIRES_EXPLICIT_APPROVAL; rule_id=WRITE_REQUIRES_EXPLICIT_APPROVAL; trust=user_controlled |
| 11 | 인가 판단 | `call-d8-i03-approved` | authorization_decision=allow; authorization_reason=RESOURCE_OWNER_SELF_APPROVAL_REQUIRED; required_approver=user-001 |
| 12 | 승인 상태 | `call-d8-i03-approved` | approval=approved; approval_id=apr_6a9db4cd4a8a49acaec1f9d6793d4d2d; required_approver=user-001 |
| 13 | 승인 상태 | `call-d8-i03-approved` | approval=consumed; approval_id=apr_6a9db4cd4a8a49acaec1f9d6793d4d2d; required_approver=user-001 |
| 14 | 최종 결과 | `call-d8-i03-approved` | ok=참; runtime_status=success; end_stage=runtime |
| 15 | 형식 검사 | `call-d8-i03-replay` | validation_allowed=참 |
| 16 | 실행 요청 | `call-d8-i03-replay` | actor=user-001; tool_name=write_file; capability=filesystem.write; action=write; resource=data/user-001/approved-once.txt |
| 17 | 정책 판단 | `call-d8-i03-replay` | policy_decision=approval_required; reason=WRITE_REQUIRES_EXPLICIT_APPROVAL; rule_id=WRITE_REQUIRES_EXPLICIT_APPROVAL; trust=user_controlled |
| 18 | 인가 판단 | `call-d8-i03-replay` | authorization_decision=allow; authorization_reason=RESOURCE_OWNER_SELF_APPROVAL_REQUIRED; required_approver=user-001 |
| 19 | 승인 상태 | `call-d8-i03-replay` | approval=pending; approval_id=apr_9344f73111504876975e756238ab0f24; required_approver=user-001 |
| 20 | 최종 결과 | `call-d8-i03-replay` | ok=거짓; runtime_status=approval_required; end_stage=approval; error_code=APPROVAL_REQUIRED |
| 21 | 실험 증거 | `-` | seed_digest=sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945; decision_digest=sha256:e8ef4c38c59762f36a1364d10eade01bc7a030dd2689165dc4bb5f79394e895e; result_digest=sha256:526f27d16975c3b31f90bfcea2c247b8850138cd671eae8465b50a7a220636b9 |

원본 JSONL은 같은 폴더의 `trace.jsonl`에 보존된다.
