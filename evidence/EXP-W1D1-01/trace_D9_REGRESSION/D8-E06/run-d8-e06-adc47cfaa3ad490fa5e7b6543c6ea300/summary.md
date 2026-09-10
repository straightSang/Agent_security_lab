# 실행 요약 — D8-E06

- 실행 번호: `run-d8-e06-adc47cfaa3ad490fa5e7b6543c6ea300`
- 사건 수: 9

| 순서 | 단계 | 호출 번호 | 핵심 내용 |
|---:|---|---|---|
| 1 | 입력 상태 | `-` | seed_digest=sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945 |
| 2 | MCP 도구 스키마 | `call-d8-e06-owner-write` | tool_schema_decision=allow; tool_schema_reason=MCP_TOOL_SCHEMA_ALLOWED; tool_profile=write_enabled; declared_capability=filesystem.write |
| 3 | 형식 검사 | `call-d8-e06-owner-write` | validation_allowed=참 |
| 4 | 실행 요청 | `call-d8-e06-owner-write` | actor=user-001; tool_name=write_file; capability=filesystem.write; action=write; resource=data/user-001/day8_owner_write.txt |
| 5 | 정책 판단 | `call-d8-e06-owner-write` | policy_decision=approval_required; reason=WRITE_REQUIRES_EXPLICIT_APPROVAL; rule_id=WRITE_REQUIRES_EXPLICIT_APPROVAL; trust=user_controlled |
| 6 | 인가 판단 | `call-d8-e06-owner-write` | authorization_decision=allow; authorization_reason=RESOURCE_OWNER_SELF_APPROVAL_REQUIRED; required_approver=user-001 |
| 7 | 승인 상태 | `call-d8-e06-owner-write` | approval=pending; approval_id=apr_e4e03e7bb1864eee947c10106ca27743; required_approver=user-001 |
| 8 | 최종 결과 | `call-d8-e06-owner-write` | ok=거짓; runtime_status=approval_required; end_stage=approval; error_code=APPROVAL_REQUIRED |
| 9 | 실험 증거 | `-` | seed_digest=sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945; decision_digest=sha256:0e6028c5914f39159b3a2c3d0d1e10c4ebbde87914beef62a75a0df7a50c964a; result_digest=sha256:bec1fd5b26d974630cfafaee2ae7d3aa4e539bb09754c4dc1aafc9046e633b07 |

원본 JSONL은 같은 폴더의 `trace.jsonl`에 보존된다.
