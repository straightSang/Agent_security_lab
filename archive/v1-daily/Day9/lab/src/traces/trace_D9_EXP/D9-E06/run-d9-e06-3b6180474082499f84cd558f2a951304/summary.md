# 실행 요약 — D9-E06

- 실행 번호: `run-d9-e06-3b6180474082499f84cd558f2a951304`
- 사건 수: 9

| 순서 | 단계 | 호출 번호 | 핵심 내용 |
|---:|---|---|---|
| 1 | 입력 상태 | `-` | seed_digest=sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945 |
| 2 | MCP 도구 스키마 | `call-d9-e06` | tool_schema_decision=allow; tool_schema_reason=MCP_TOOL_SCHEMA_ALLOWED; tool_profile=write_enabled; declared_capability=filesystem.write |
| 3 | 형식 검사 | `call-d9-e06` | validation_allowed=참 |
| 4 | 실행 요청 | `call-d9-e06` | actor=user-001; tool_name=write_file; capability=filesystem.write; action=write; resource=data/user-001/day9-approved-write.txt |
| 5 | 정책 판단 | `call-d9-e06` | policy_decision=approval_required; reason=WRITE_REQUIRES_EXPLICIT_APPROVAL; rule_id=WRITE_REQUIRES_EXPLICIT_APPROVAL; trust=user_controlled |
| 6 | 인가 판단 | `call-d9-e06` | authorization_decision=allow; authorization_reason=RESOURCE_OWNER_SELF_APPROVAL_REQUIRED; required_approver=user-001 |
| 7 | 승인 상태 | `call-d9-e06` | approval=pending; approval_id=apr_4a8123eabfcc404cb67c1d981842762c; required_approver=user-001 |
| 8 | 최종 결과 | `call-d9-e06` | ok=거짓; runtime_status=approval_required; end_stage=approval; error_code=APPROVAL_REQUIRED |
| 9 | 실험 증거 | `-` | seed_digest=sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945; decision_digest=sha256:bd0f4d0a46386bab0193af10a971ece584c354cec0857860cddd5548b376519c; result_digest=sha256:cb82922adc3854216d118998f2c3cbc5deef870d13a9bfa6eac181dcc12a0bf7 |

원본 JSONL은 같은 폴더의 `trace.jsonl`에 보존된다.
