# Day 9 실험 결과 — MCP 도구 스키마 최소권한

## 결론

Day9 본 실험 6개와 Day7·Day8 회귀 테스트를 실행했다. 정상 읽기는 성공했고,
`read_only`에서의 쓰기, 선언되지 않은 인자, 범위 밖 경로, 일반 명령 도구는
Dispatcher에 도달하기 전에 차단됐다. `write_enabled`의 정상 쓰기는 기존 흐름대로
인가를 통과한 뒤 승인 대기 상태가 되었으며 승인 전 실행되지 않았다.

- 본 실험: `test_mcp_tool_schema.py` PASS
- 간접 프롬프트 주입 회귀: `test_indirect_injection.py` PASS
- 정책·제어면 회귀: `test_policy_boundary.py` PASS
- 실행 경계·승인 불변조건: `test_security_invariants.py` PASS
- 최신 두 번의 동일 fixture 재실행: E01~E06의 seed/decision/result digest 모두 일치

## 본 실험 결과

| ID | 핵심 조건 | 스키마 판단 | 이후 결과 | Dispatcher | 평가 |
|---|---|---|---|---:|---|
| D9-E01 | `read_only` 소유 파일 읽기 | ALLOW | Policy/AuthZ ALLOW, success | 1회 | 정상 utility 유지 |
| D9-E02 | `read_only`에서 쓰기 요청 | DENY: `TOOL_NOT_EXPOSED_IN_PROFILE` | `schema_denied` | 0회 | 최소권한 노출 확인 |
| D9-E03 | 선언되지 않은 `recursive` 인자 | DENY: `MCP_ADDITIONAL_ARGUMENT_DENIED` | `schema_denied` | 0회 | 입력 계약 강제 확인 |
| D9-E04 | `../secret` 경로 | DENY: `MCP_PATH_OUTSIDE_PROFILE_SCOPE` | `schema_denied` | 0회 | 범위 밖 자원 차단 |
| D9-E05 | `write_enabled`에서 `run_command` | DENY: `TOOL_NOT_EXPOSED_IN_PROFILE` | `schema_denied` | 0회 | 일반 명령 도구 격리 |
| D9-E06 | `write_enabled` 소유 파일 쓰기 | ALLOW | Policy 승인 필요, AuthZ ALLOW, pending | 0회 | 기존 승인 경계 유지 |

스키마에서 거부된 E02~E05에는 Policy·Authorization·Approval 사건이 생기지 않았다.
이는 조기 거부 뒤 후속 보안 함수가 불필요하게 호출되지 않았다는 증거다.

## 재현성 확인

아래 값은 최신 두 실행에서 동일했다. `run_id`와 시간처럼 실행마다 바뀌는 값은
요약 계산에서 제외하고, 실제 입력·판단·결과만 비교했다.

| ID | decision digest | result digest | 두 실행 일치 |
|---|---|---|---|
| D9-E01 | `ebad495e...89cddf` | `6ab46a57...7ccf` | 예 |
| D9-E02 | `d35c664c...a1a3b` | `c0eab6b3...c2ef1` | 예 |
| D9-E03 | `5c466add...f6288` | `e4475a55...41d0` | 예 |
| D9-E04 | `c6a292a8...04762` | `4ed5f8d9...0cf8` | 예 |
| D9-E05 | `9a873c9b...d51b9` | `0f1f315d...68a08` | 예 |
| D9-E06 | `bd0f4d0a...519c` | `cb82922a...0bf7` | 예 |

## 보안 경계 점검

| 점검 항목 | 확인 방법 | 결과 |
|---|---|---|
| Runtime 밖에서 `_dispatch()` 직접 호출 | 소스 검색 및 불변조건 테스트 | 발견되지 않음 |
| 이전 방식 연결 함수의 실행 우회 | 단일 `Agent.py/execute_tool()` 진입점 확인 | 우회 없음 |
| 스키마·Policy 거부 뒤 후속 gate 호출 | trace 사건 순서 검사 | 호출되지 않음 |
| 인가 거부 뒤 승인 ID 생성 | 승인 사건·상태 비교 | 생성되지 않음 |
| 승인 쓰기의 consume 전 실행 | mock Dispatcher와 ApprovalStore 검사 | 실행되지 않음 |
| 동일 승인 ID 재사용 | consumed 상태 재시도 | 두 번째 실행 차단 |

## 해석과 한계

이번 결과는 MCP 서버의 OAuth 인증 구현이 아니라, 인증된 주체에게 어떤 도구 표면을
노출하고 어떤 입력을 받을지를 Runtime 앞단에서 제한하는 로컬 testbed 결과다.
실제 운영에서는 OAuth token 검증 결과와 `ToolProfile`을 결속해야 한다.

또한 현재 validator는 실험에 필요한 JSON Schema 부분집합만 구현한다. 전체 MCP
호환성이나 원격 transport를 주장하지 않는다. `run_command` 구현은 회귀 재현을 위해
남아 있지만 `legacy_compat`를 명시하지 않으면 노출되지 않는다.
