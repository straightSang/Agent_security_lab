# 실행 요약 — D9-E09

- 실행 번호: `run-d9-e09-e5e5bc4fed5e4af78bcc19d20932ab05`
- 사건 수: 24

| 순서 | 단계 | 호출 번호 | 핵심 내용 |
|---:|---|---|---|
| 1 | 입력 상태 | `-` | seed_digest=sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945 |
| 2 | MCP 도구 스키마 | `call-d9-e09-pending` | tool_schema_decision=allow; tool_schema_reason=MCP_TOOL_SCHEMA_ALLOWED; tool_profile=write_enabled; declared_capability=filesystem.write |
| 3 | 형식 검사 | `call-d9-e09-pending` | validation_allowed=참 |
| 4 | 실행 요청 | `call-d9-e09-pending` | actor=user-001; tool_name=write_file; capability=filesystem.write; action=write; resource=data/user-001/approved-once.txt |
| 5 | 정책 판단 | `call-d9-e09-pending` | policy_decision=approval_required; reason=WRITE_REQUIRES_EXPLICIT_APPROVAL; rule_id=WRITE_REQUIRES_EXPLICIT_APPROVAL; trust=user_controlled |
| 6 | 인가 판단 | `call-d9-e09-pending` | authorization_decision=allow; authorization_reason=RESOURCE_OWNER_SELF_APPROVAL_REQUIRED; required_approver=user-001 |
| 7 | 승인 상태 | `call-d9-e09-pending` | approval=pending; approval_id=apr_d1cd33c2f6e14add8c8115d5b32e22ca; required_approver=user-001 |
| 8 | 최종 결과 | `call-d9-e09-pending` | ok=거짓; runtime_status=approval_required; end_stage=approval; error_code=APPROVAL_REQUIRED |
| 9 | MCP 도구 스키마 | `call-d9-e09-approved` | tool_schema_decision=allow; tool_schema_reason=MCP_TOOL_SCHEMA_ALLOWED; tool_profile=write_enabled; declared_capability=filesystem.write |
| 10 | 형식 검사 | `call-d9-e09-approved` | validation_allowed=참 |
| 11 | 실행 요청 | `call-d9-e09-approved` | actor=user-001; tool_name=write_file; capability=filesystem.write; action=write; resource=data/user-001/approved-once.txt |
| 12 | 정책 판단 | `call-d9-e09-approved` | policy_decision=approval_required; reason=WRITE_REQUIRES_EXPLICIT_APPROVAL; rule_id=WRITE_REQUIRES_EXPLICIT_APPROVAL; trust=user_controlled |
| 13 | 인가 판단 | `call-d9-e09-approved` | authorization_decision=allow; authorization_reason=RESOURCE_OWNER_SELF_APPROVAL_REQUIRED; required_approver=user-001 |
| 14 | 승인 상태 | `call-d9-e09-approved` | approval=approved; approval_id=apr_d1cd33c2f6e14add8c8115d5b32e22ca; required_approver=user-001 |
| 15 | 승인 상태 | `call-d9-e09-approved` | approval=consumed; approval_id=apr_d1cd33c2f6e14add8c8115d5b32e22ca; required_approver=user-001 |
| 16 | 최종 결과 | `call-d9-e09-approved` | ok=참; runtime_status=success; end_stage=runtime |
| 17 | MCP 도구 스키마 | `call-d9-e09-replay` | tool_schema_decision=allow; tool_schema_reason=MCP_TOOL_SCHEMA_ALLOWED; tool_profile=write_enabled; declared_capability=filesystem.write |
| 18 | 형식 검사 | `call-d9-e09-replay` | validation_allowed=참 |
| 19 | 실행 요청 | `call-d9-e09-replay` | actor=user-001; tool_name=write_file; capability=filesystem.write; action=write; resource=data/user-001/approved-once.txt |
| 20 | 정책 판단 | `call-d9-e09-replay` | policy_decision=approval_required; reason=WRITE_REQUIRES_EXPLICIT_APPROVAL; rule_id=WRITE_REQUIRES_EXPLICIT_APPROVAL; trust=user_controlled |
| 21 | 인가 판단 | `call-d9-e09-replay` | authorization_decision=allow; authorization_reason=RESOURCE_OWNER_SELF_APPROVAL_REQUIRED; required_approver=user-001 |
| 22 | 승인 상태 | `call-d9-e09-replay` | approval=pending; approval_id=apr_228586bb7f5a4832ac1f420f841cc3c7; required_approver=user-001 |
| 23 | 최종 결과 | `call-d9-e09-replay` | ok=거짓; runtime_status=approval_required; end_stage=approval; error_code=APPROVAL_REQUIRED |
| 24 | 실험 증거 | `-` | seed_digest=sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945; decision_digest=sha256:4a4b4971b26f09cce24ec0fb4da44d0be333c22fd49e9daae0a6c4eb64306c32; result_digest=sha256:3f321a05c0ae112c30d098ca22c90ebd575913ab40853e12445ee5d3493b4c33 |

원본 JSONL은 같은 폴더의 `trace.jsonl`에 보존된다.
