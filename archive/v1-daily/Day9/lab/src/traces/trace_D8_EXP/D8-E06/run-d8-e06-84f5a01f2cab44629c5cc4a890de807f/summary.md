# 실행 요약 — D8-E06

- 실행 번호: `run-d8-e06-84f5a01f2cab44629c5cc4a890de807f`
- 사건 수: 8

| 순서 | 단계 | 호출 번호 | 핵심 내용 |
|---:|---|---|---|
| 1 | 입력 상태 | `-` | seed_digest=sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945 |
| 2 | 형식 검사 | `call-d8-e06-owner-write` | validation_allowed=참 |
| 3 | 실행 요청 | `call-d8-e06-owner-write` | actor=user-001; tool_name=write_file; capability=filesystem.write; action=write; resource=data/user-001/day8_owner_write.txt |
| 4 | 정책 판단 | `call-d8-e06-owner-write` | policy_decision=approval_required; reason=WRITE_REQUIRES_EXPLICIT_APPROVAL; rule_id=WRITE_REQUIRES_EXPLICIT_APPROVAL; trust=user_controlled |
| 5 | 인가 판단 | `call-d8-e06-owner-write` | authorization_decision=allow; authorization_reason=RESOURCE_OWNER_SELF_APPROVAL_REQUIRED; required_approver=user-001 |
| 6 | 승인 상태 | `call-d8-e06-owner-write` | approval=pending; approval_id=apr_df61fa9ee8cc4b16b27a843d811a91fa; required_approver=user-001 |
| 7 | 최종 결과 | `call-d8-e06-owner-write` | ok=거짓; runtime_status=approval_required; end_stage=approval; error_code=APPROVAL_REQUIRED |
| 8 | 실험 증거 | `-` | seed_digest=sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945; decision_digest=sha256:d3df05acde083195139f579f940ef8e9f8fd3ffb502746cc9eb4885cd345c3bd; result_digest=sha256:92649ab71416725b5412c0a271c0983431806df6a62dad25770a839e6166f3fa |

원본 JSONL은 같은 폴더의 `trace.jsonl`에 보존된다.
