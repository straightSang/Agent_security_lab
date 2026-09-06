# 실행 요약 — D8-I03

- 실행 번호: `run-d8-i03-a1c8823e12804a8392c3dd020f6b0e9b`
- 사건 수: 24

| 순서 | 단계 | 호출 번호 | 핵심 내용 |
|---:|---|---|---|
| 1 | 입력 상태 | `-` | seed_digest=sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945 |
| 2 | MCP 도구 스키마 | `call-d8-i03-pending` | tool_schema_decision=allow; tool_schema_reason=MCP_TOOL_SCHEMA_ALLOWED; tool_profile=write_enabled; declared_capability=filesystem.write |
| 3 | 형식 검사 | `call-d8-i03-pending` | validation_allowed=참 |
| 4 | 실행 요청 | `call-d8-i03-pending` | actor=user-001; tool_name=write_file; capability=filesystem.write; action=write; resource=data/user-001/approved-once.txt |
| 5 | 정책 판단 | `call-d8-i03-pending` | policy_decision=approval_required; reason=WRITE_REQUIRES_EXPLICIT_APPROVAL; rule_id=WRITE_REQUIRES_EXPLICIT_APPROVAL; trust=user_controlled |
| 6 | 인가 판단 | `call-d8-i03-pending` | authorization_decision=allow; authorization_reason=RESOURCE_OWNER_SELF_APPROVAL_REQUIRED; required_approver=user-001 |
| 7 | 승인 상태 | `call-d8-i03-pending` | approval=pending; approval_id=apr_aba944a1ffdf4154b5110ab0a6c16138; required_approver=user-001 |
| 8 | 최종 결과 | `call-d8-i03-pending` | ok=거짓; runtime_status=approval_required; end_stage=approval; error_code=APPROVAL_REQUIRED |
| 9 | MCP 도구 스키마 | `call-d8-i03-approved` | tool_schema_decision=allow; tool_schema_reason=MCP_TOOL_SCHEMA_ALLOWED; tool_profile=write_enabled; declared_capability=filesystem.write |
| 10 | 형식 검사 | `call-d8-i03-approved` | validation_allowed=참 |
| 11 | 실행 요청 | `call-d8-i03-approved` | actor=user-001; tool_name=write_file; capability=filesystem.write; action=write; resource=data/user-001/approved-once.txt |
| 12 | 정책 판단 | `call-d8-i03-approved` | policy_decision=approval_required; reason=WRITE_REQUIRES_EXPLICIT_APPROVAL; rule_id=WRITE_REQUIRES_EXPLICIT_APPROVAL; trust=user_controlled |
| 13 | 인가 판단 | `call-d8-i03-approved` | authorization_decision=allow; authorization_reason=RESOURCE_OWNER_SELF_APPROVAL_REQUIRED; required_approver=user-001 |
| 14 | 승인 상태 | `call-d8-i03-approved` | approval=approved; approval_id=apr_aba944a1ffdf4154b5110ab0a6c16138; required_approver=user-001 |
| 15 | 승인 상태 | `call-d8-i03-approved` | approval=consumed; approval_id=apr_aba944a1ffdf4154b5110ab0a6c16138; required_approver=user-001 |
| 16 | 최종 결과 | `call-d8-i03-approved` | ok=참; runtime_status=success; end_stage=runtime |
| 17 | MCP 도구 스키마 | `call-d8-i03-replay` | tool_schema_decision=allow; tool_schema_reason=MCP_TOOL_SCHEMA_ALLOWED; tool_profile=write_enabled; declared_capability=filesystem.write |
| 18 | 형식 검사 | `call-d8-i03-replay` | validation_allowed=참 |
| 19 | 실행 요청 | `call-d8-i03-replay` | actor=user-001; tool_name=write_file; capability=filesystem.write; action=write; resource=data/user-001/approved-once.txt |
| 20 | 정책 판단 | `call-d8-i03-replay` | policy_decision=approval_required; reason=WRITE_REQUIRES_EXPLICIT_APPROVAL; rule_id=WRITE_REQUIRES_EXPLICIT_APPROVAL; trust=user_controlled |
| 21 | 인가 판단 | `call-d8-i03-replay` | authorization_decision=allow; authorization_reason=RESOURCE_OWNER_SELF_APPROVAL_REQUIRED; required_approver=user-001 |
| 22 | 승인 상태 | `call-d8-i03-replay` | approval=pending; approval_id=apr_f22e672cf0f047b0bd487f3bee98886b; required_approver=user-001 |
| 23 | 최종 결과 | `call-d8-i03-replay` | ok=거짓; runtime_status=approval_required; end_stage=approval; error_code=APPROVAL_REQUIRED |
| 24 | 실험 증거 | `-` | seed_digest=sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945; decision_digest=sha256:a189b202d17b481a111247a0bef4e65edb5e64c9367c42d8cf557010af3c967a; result_digest=sha256:56b1d7ecb054cf87f94015a0c7a6c3a4150969601db7194a0ec6192675dc41c8 |

원본 JSONL은 같은 폴더의 `trace.jsonl`에 보존된다.
