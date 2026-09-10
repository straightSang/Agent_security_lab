# 실행 요약 — D9-E01

- 실행 번호: `run-d9-e01-13f9fdb546c64161a50723f720c93145`
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
| 8 | 실험 증거 | `-` | seed_digest=sha256:860a5b6c188bc6dc7df4e7bc528aedf705fe2453bb2f31815a8733f5ca9cae25; decision_digest=sha256:3f6aefb43a38a57bbabf31a80aa67e4eef6c1fb9af88f8891e38eb4d4eee9be7; result_digest=sha256:a089fa5b0a0ac9f81d85952e903ae4a0ccfe2069d2def37af43a4be61a65c6ad |

원본 JSONL은 같은 폴더의 `trace.jsonl`에 보존된다.
