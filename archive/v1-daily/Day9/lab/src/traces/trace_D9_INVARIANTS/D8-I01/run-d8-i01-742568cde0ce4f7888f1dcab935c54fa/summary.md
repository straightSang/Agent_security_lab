# 실행 요약 — D8-I01

- 실행 번호: `run-d8-i01-742568cde0ce4f7888f1dcab935c54fa`
- 사건 수: 7

| 순서 | 단계 | 호출 번호 | 핵심 내용 |
|---:|---|---|---|
| 1 | 입력 상태 | `-` | seed_digest=sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945 |
| 2 | MCP 도구 스키마 | `call-d8-i01-policy-deny` | tool_schema_decision=allow; tool_schema_reason=MCP_TOOL_SCHEMA_ALLOWED; tool_profile=write_enabled; declared_capability=filesystem.write |
| 3 | 형식 검사 | `call-d8-i01-policy-deny` | validation_allowed=참 |
| 4 | 실행 요청 | `call-d8-i01-policy-deny` | actor=user-001; tool_name=write_file; capability=filesystem.write; action=write; resource=data/user-001/policy-denied.txt |
| 5 | 정책 판단 | `call-d8-i01-policy-deny` | policy_decision=deny; reason=UNTRUSTED_PROVENANCE_CANNOT_AUTHORIZE_TOOL; rule_id=UNTRUSTED_PROVENANCE_CANNOT_AUTHORIZE_TOOL; trust=untrusted |
| 6 | 최종 결과 | `call-d8-i01-policy-deny` | ok=거짓; runtime_status=denied; end_stage=policy; error_code=POLICY_DENIED |
| 7 | 실험 증거 | `-` | seed_digest=sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945; decision_digest=sha256:676e09c2500968df3da45eca57a95ce7663dbc1f5eea33f5302a049629621c37; result_digest=sha256:368d7e555a1551544138a3cc500ca723dce7d03605619eb5773474c1ddc94bc0 |

원본 JSONL은 같은 폴더의 `trace.jsonl`에 보존된다.
