# 권한 정책 v0.8 — Day 9 MCP tool schema·least privilege

## 정책 원칙

- ToolProfile은 현재 작업에 어떤 tool을 노출할지 정한다.
- inputSchema는 인자의 정적 형식과 profile 범위를 정한다.
- Runtime Validation은 canonical sandbox 경계를 다시 확인한다.
- Policy는 trust/capability/resource 일반 규칙을 판단한다.
- Authorization은 actor-resource-action 관계를 판단한다.
- Approval은 허용 가능한 write의 명시적 동의를 판단한다.
- 어느 한 단계의 ALLOW도 뒤 단계를 생략하지 않는다.

## 도구 노출 정책

| profile | 허용 tool | 기본 사용 | 금지 |
|---|---|---|---|
| `read_only` | calculator, get_time, read_file, list_files | 읽기·요약 | write_file, run_command |
| `write_enabled` | read_only + write_file | 명시적 쓰기 과업 | run_command |
| `legacy_compat` | write_enabled + run_command | 이전 회귀 전용 | 일반 Agent 기본 사용 |

profile 선택 권한은 LLM이나 observation에 없다. Lab에서는 환경 설정/test harness,
운영에서는 인증된 session/token scope 같은 control-plane만 선택할 수 있다.

## inputSchema 정책

| tool | 핵심 제한 | 이유 |
|---|---|---|
| calculator | expression 문자열, 최대 500자 | 과도한 입력 제한 |
| get_time | 인자 없음 | 숨은 추가 동작 방지 |
| read_file | `data/{actor-or-shared}/...`, 최대 240자 | root/임의 하위 경로 노출 축소 |
| list_files | `data` 또는 actor/shared 하위 | directory 탐색 범위 축소 |
| write_file | data 경로, content 최대 4096자 | 쓰기 범위·크기 제한 |
| run_command | legacy profile에서만 | 자유 문자열 multiplex 도구 격리 |

모든 schema는 필수 인자와 `additionalProperties=false`를 사용한다. schema 검사를
통과해도 `safe_resolve()`와 기존 Runtime Validation을 다시 수행한다.

## 기존 resource/actor 정책

| resource | read/list | write | 승인자 |
|---|---|---|---|
| `data/{ACTOR_NAME}/**` | 같은 actor | 같은 actor만 | actor 본인 |
| `data/shared/**` | user-001, user-003 | 등록 멤버 | reviewer-001 |
| 다른 actor private path | DENY | DENY | approval 생성 없음 |
| 미등록 path | DENY | DENY | 없음 |

## 결정 순서

1. Tool schema: profile 노출과 inputSchema 검사
2. Validation: 인자와 canonical sandbox path 검사
3. Capability mapping: tool을 capability/action/resource로 변환
4. Policy: 민감 자원, capability, provenance trust, resource scope 검사
5. Authorization: actor 소유자/멤버 관계 검사
6. Approval: write의 실제 승인 record 검사
7. Runtime: 승인 consume 후 Dispatcher 호출

## 주요 결정 코드

| 코드 | 단계 | 의미 |
|---|---|---|
| `TOOL_NOT_EXPOSED_IN_PROFILE` | schema | 현재 작업에 tool이 없음 |
| `MCP_REQUIRED_ARGUMENT_MISSING` | schema | 필수 인자 누락 |
| `MCP_ADDITIONAL_ARGUMENT_DENIED` | schema | 정의되지 않은 인자 |
| `MCP_ARGUMENT_TYPE_MISMATCH` | schema | JSON type 불일치 |
| `MCP_ARGUMENT_PATTERN_MISMATCH` | schema | 정적 경로 pattern 불일치 |
| `MCP_PATH_OUTSIDE_PROFILE_SCOPE` | schema | 절대/상위 경로 시도 |
| `UNTRUSTED_PROVENANCE_CANNOT_AUTHORIZE_TOOL` | Policy | 비신뢰 입력의 권한 위임 차단 |
| `ACTOR_NOT_RESOURCE_OWNER` | AuthZ | cross-user 접근 차단 |
| `WRITE_REQUIRES_EXPLICIT_APPROVAL` | Policy | write 승인 필요 |

## MCP annotations 주의사항

`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`는 도구 동작을
설명하는 힌트다. 신뢰되지 않은 MCP server의 annotation은 권한 근거로 사용하지
않는다. 이 Lab은 annotation 대신 내부 ToolProfile, capability mapping, Policy,
AuthZ, Approval을 권위 있는 기준으로 사용한다.

## MCP authorization 연결 기준

원격 운영 환경에서는 token 검증 결과의 actor/scope를 profile과 결속해야 한다.

```text
validated token scope=files.read
  -> read_only profile

validated token scope=files.write + explicit task
  -> write_enabled profile
  -> 기존 Approval 계속 필요
```

token이 있다고 자동으로 write를 허용하지 않는다. token 검증, tool exposure,
resource authorization, human approval은 서로 다른 단계다.

## 정책을 추가할 때 확인할 것

- 정상 과업에 정말 필요한 tool인가?
- read와 write를 한 tool에 섞고 있지 않은가?
- free-form command 대신 좁은 전용 tool로 분리할 수 있는가?
- path pattern이 canonical Runtime 검사보다 느슨하지 않은가?
- 추가 인자를 기본 허용하고 있지 않은가?
- profile 선택이 비신뢰 데이터에서 유래하지 않는가?
- schema ALLOW 뒤 Policy/AuthZ/Approval이 유지되는가?
- 정상 utility와 false block을 공격 차단률과 함께 측정하는가?
