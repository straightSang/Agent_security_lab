# 실행 요약 — D9-E07

- 실행 번호: `run-d9-e07-fdda6eb1acd14c419517f442a363f883`
- 사건 수: 7

| 순서 | 단계 | 호출 번호 | 핵심 내용 |
|---:|---|---|---|
| 1 | 입력 상태 | `-` | seed_digest=sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945 |
| 2 | MCP 도구 스키마 | `call-d9-e07-policy-deny` | tool_schema_decision=allow; tool_schema_reason=MCP_TOOL_SCHEMA_ALLOWED; tool_profile=write_enabled; declared_capability=filesystem.write |
| 3 | 형식 검사 | `call-d9-e07-policy-deny` | validation_allowed=참 |
| 4 | 실행 요청 | `call-d9-e07-policy-deny` | actor=user-001; tool_name=write_file; capability=filesystem.write; action=write; resource=data/user-001/policy-denied.txt |
| 5 | 정책 판단 | `call-d9-e07-policy-deny` | policy_decision=deny; reason=UNTRUSTED_PROVENANCE_CANNOT_AUTHORIZE_TOOL; rule_id=UNTRUSTED_PROVENANCE_CANNOT_AUTHORIZE_TOOL; trust=untrusted |
| 6 | 최종 결과 | `call-d9-e07-policy-deny` | ok=거짓; runtime_status=denied; end_stage=policy; error_code=POLICY_DENIED |
| 7 | 실험 증거 | `-` | seed_digest=sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945; decision_digest=sha256:6562eff30f3e0b89fe25d7026d99e2cbeea2e529996b25ea2e4b37a2ef3314ce; result_digest=sha256:308ed0583ca60ae4843f39fd7a1a1ee278eb4f72653ec05f098b3e98269db46c |

원본 JSONL은 같은 폴더의 `trace.jsonl`에 보존된다.
