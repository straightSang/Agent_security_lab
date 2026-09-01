# 실행 요약 — D9-E01

- 실행 번호: `run-d9-e01-c405d400a92b4438bf5d1090efc9277e`
- 사건 수: 8

| 순서 | 단계 | 호출 번호 | 핵심 내용 |
|---:|---|---|---|
| 1 | 입력 상태 | `-` | seed_digest=sha256:860a5b6c188bc6dc7df4e7bc528aedf705fe2453bb2f31815a8733f5ca9cae25 |
| 2 | MCP 도구 스키마 | `call-d9-e01` | tool_schema_decision=allow; tool_schema_reason=MCP_TOOL_SCHEMA_ALLOWED; tool_profile=read_only; declared_capability=filesystem.read |
| 3 | 형식 검사 | `call-d9-e01` | validation_allowed=참 |
| 4 | 실행 요청 | `call-d9-e01` | actor=user-001; tool_name=read_file; capability=filesystem.read; action=read; resource=data/user-001/notes.txt |
| 5 | 정책 판단 | `call-d9-e01` | policy_decision=allow; reason=BASELINE_CAPABILITY_ALLOWED; rule_id=BASELINE_CAPABILITY_ALLOWED; trust=user_controlled |
| 6 | 인가 판단 | `call-d9-e01` | authorization_decision=allow; authorization_reason=RESOURCE_OWNER |
| 7 | 최종 결과 | `call-d9-e01` | ok=참; runtime_status=success; end_stage=runtime |
| 8 | 실험 증거 | `-` | seed_digest=sha256:860a5b6c188bc6dc7df4e7bc528aedf705fe2453bb2f31815a8733f5ca9cae25; decision_digest=sha256:ebad495eabd9d4658346098f2f6b4f3b50e9ee285c1b4425380244abda89cddf; result_digest=sha256:6ab46a5771e776b55276cf710db468c32641f3316b0ccbf147565b2d5edc7ccf |

원본 JSONL은 같은 폴더의 `trace.jsonl`에 보존된다.
