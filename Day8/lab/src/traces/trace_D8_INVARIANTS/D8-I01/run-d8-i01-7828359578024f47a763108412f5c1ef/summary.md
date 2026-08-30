# 실행 요약 — D8-I01

- 실행 번호: `run-d8-i01-7828359578024f47a763108412f5c1ef`
- 사건 수: 6

| 순서 | 단계 | 호출 번호 | 핵심 내용 |
|---:|---|---|---|
| 1 | 입력 상태 | `-` | seed_digest=sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945 |
| 2 | 형식 검사 | `call-d8-i01-policy-deny` | validation_allowed=참 |
| 3 | 실행 요청 | `call-d8-i01-policy-deny` | actor=user-001; tool_name=write_file; capability=filesystem.write; action=write; resource=data/user-001/policy-denied.txt |
| 4 | 정책 판단 | `call-d8-i01-policy-deny` | policy_decision=deny; reason=UNTRUSTED_PROVENANCE_CANNOT_AUTHORIZE_TOOL; rule_id=UNTRUSTED_PROVENANCE_CANNOT_AUTHORIZE_TOOL; trust=untrusted |
| 5 | 최종 결과 | `call-d8-i01-policy-deny` | ok=거짓; runtime_status=denied; end_stage=policy; error_code=POLICY_DENIED |
| 6 | 실험 증거 | `-` | seed_digest=sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945; decision_digest=sha256:b1f8f83051fcb4067083f071c8fd36895a4e849d767beb2279286cd762b05188; result_digest=sha256:cfd1475acff72160a36c2a99687c5ce02070d9aa68c5ac668c3b097d0543550f |

원본 JSONL은 같은 폴더의 `trace.jsonl`에 보존된다.
