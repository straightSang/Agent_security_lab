# 실행 요약 — D9-E06

- 실행 번호: `run-d9-e06-bf5f5241f352445ea42ba5aff49d054f`
- 사건 수: 9

| 순서 | 단계 | 호출 번호 | 핵심 내용 |
|---:|---|---|---|
| 1 | 입력 상태 | `-` | seed_digest=sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945 |
| 2 | MCP 도구 스키마 | `call-d9-e06` | tool_schema_decision=allow; tool_schema_reason=MCP_TOOL_SCHEMA_ALLOWED; tool_profile=write_enabled; declared_capability=filesystem.write |
| 3 | 형식 검사 | `call-d9-e06` | validation_allowed=참 |
| 4 | 실행 요청 | `call-d9-e06` | actor=user-001; tool_name=write_file; capability=filesystem.write; action=write; resource=data/user-001/day9-approved-write.txt |
| 5 | 정책 판단 | `call-d9-e06` | policy_decision=approval_required; reason=WRITE_REQUIRES_EXPLICIT_APPROVAL; rule_id=WRITE_REQUIRES_EXPLICIT_APPROVAL; trust=user_controlled |
| 6 | 인가 판단 | `call-d9-e06` | authorization_decision=allow; authorization_reason=RESOURCE_OWNER_SELF_APPROVAL_REQUIRED; required_approver=user-001 |
| 7 | 승인 상태 | `call-d9-e06` | approval=pending; approval_id=apr_e04b7041b08f4bdcbca036faa6bafb86; required_approver=user-001 |
| 8 | 최종 결과 | `call-d9-e06` | ok=거짓; runtime_status=approval_required; end_stage=approval; error_code=APPROVAL_REQUIRED |
| 9 | 실험 증거 | `-` | seed_digest=sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945; decision_digest=sha256:93e21fcfa543dc7215d309848daee2ed849211527f197472de1116aa87de0110; result_digest=sha256:5d1964ef96b870f38f7dc0b5aac64ffcf896281a59b09bbd8bcb2726035ae32e |

원본 JSONL은 같은 폴더의 `trace.jsonl`에 보존된다.
