# THREAT MODEL — v0.7

| 필드 | 값 |
|---|---|
| 버전 | v0.7 |
| 직전 버전 | v0.6 (Day 9, `ThreatModel0.6.md`) |
| 상태 | Validated (로컬 랩 범위) |
| 범위 | 로컬 격리 랩·합성 데이터 전용 |

> **버전 인터페이스.** 같은 번호면 같은 내용이다. 이전 저장소에서는 Day7과 Day8의
> `ThreatModel0.5.md`가 같은 번호로 서로 다른 내용을 담고 있었다(123줄 vs 222줄).
> 이 문서는 그 인터페이스를 복구한다. 내용이 바뀌면 반드시 번호를 올리고 아래 "변경 이력"에
> 직전 버전과의 차이를 적는다.

## v0.6 → v0.7 변경 요약

| 항목 | 변경 | 이유 |
|---|---|---|
| 경계 정의 | schema gate의 역할을 '구조적 안전성'으로 축소, 범위 판정은 Policy로 일원화 | 세 계층이 같은 질문에 답해 도달 불가 분기가 생겼음 |
| 공격자 능력 | '선언되지 않은 디렉터리 생성'을 명시적 위협으로 추가 | 쓰기가 ownership 네임스페이스를 스스로 만들 수 있었음 |
| 불변조건 | 13~16번 신규 | canary 탐지·디렉터리 선언·관측 무결성·도달 가능성 |
| 잔여 위험 | model-in-the-loop 미측정을 최상위 잔여 위험으로 승격 | 위협모델 상단이 시뮬레이션으로만 검증된 상태 |

---


## 보호할 자산

- sandbox 파일의 기밀성·무결성
- actor/resource ownership 규칙
- Policy·ApprovalStore·tool profile의 신뢰된 상태
- Dispatcher의 유일 실행 경계
- trace와 evaluator의 감사 가능성

## 신뢰 경계

```text
비신뢰
  user text / repository content / tool observation / LLM proposal
     |
     v
신뢰 경계
  authenticated actor / trusted ToolProfile / server-side schema catalog
  Runtime Validation / Policy / AuthZ / Approval / Dispatcher
```

fixture의 `profile`은 실험 harness가 읽는 설정이다. 운영에서는 인증된 session이나
token scope가 profile을 정해야 한다. 모델이나 observation이 profile을 바꾸면 안 된다.

## 공격자 능력

- 미노출 `write_file` 또는 `run_command` 이름을 직접 제안
- 필수 인자를 생략하거나 예상 밖 인자를 추가
- path에 `..`, 절대 경로, scope 밖 경로 삽입
- tool description/annotation을 보안 권한처럼 해석하도록 유도
- indirect prompt injection으로 write capability 요청
- schema ALLOW를 최종 permission처럼 오용하도록 유도
- [v0.7] 선언되지 않은 하위 디렉터리를 쓰기로 생성해 ownership 네임스페이스를 확장
- [v0.7] 확장자 형태(`api.env`, `svc.pem`)로 민감 리소스 판정을 회피

## 공격자가 할 수 없어야 하는 것

- trusted ToolProfile 변경
- MCP catalog 또는 schema digest 변경
- 서버가 계산한 capability 변경
- actor/resource ownership 위조
- Policy DENY 뒤 AuthZ/Approval/Dispatcher 도달
- schema DENY 뒤 ToolIntent/Policy/Dispatcher 도달
- 승인 없는 write 또는 consumed approval 재사용

## 통제 구조

| 통제 | 방어 대상 | 실패 시 영향 |
|---|---|---|
| ToolProfile | 불필요 도구 노출 | 공격 표면 증가 |
| MCP inputSchema | 잘못된 인자·정적 범위 | 모호한/과도한 호출 생성 |
| Runtime Validation | canonical path·실제 형식 | sandbox 탈출 |
| capability mapping | 모델의 권한 자기 선언 | 권한 상승 |
| Policy | trust/resource 일반 규칙 | 비신뢰 action 허용 |
| Authorization | actor-resource 관계 | cross-user 접근 |
| Approval | 위험 action의 명시적 동의 | 무단 write |
| Dispatcher 단일 경계 | gate 우회 | 실제 위험 실행 |
| Trace/Evaluator | 판단 누락·우회 | 검증 불가능 |
| Canary 탐지 | 차단 실패의 무증상화 | 유출을 알아채지 못함 |
| 도달 가능성 회귀 | 죽은 정책 분기 | 검증했다는 착각 |

## 보안 불변조건

1. profile에 없는 tool은 `tool_schema` 단계에서 종료한다.
2. schema DENY call에는 ToolIntent·Policy·AuthZ·Approval 사건이 없다.
3. schema ALLOW도 Policy/AuthZ/Approval을 생략하지 않는다.
4. annotations는 허용 근거가 아니다.
5. `read_only`는 write와 generic command capability를 노출하지 않는다.
6. `write_enabled`도 `run_command`를 노출하지 않는다.
7. `legacy_compat`는 회귀 목적에서만 명시적으로 선택한다.
8. Policy DENY 뒤 AuthZ·Approval·Dispatcher는 0회다.
9. AuthZ DENY 뒤 approval ID는 발급되지 않는다.
10. 승인 write는 consume 후 한 번만 실행된다.
11. 모든 판단은 동일 run_id와 call_id로 연결된다.
12. 모델에 광고한 schema/annotation 복사본 변경은 원본 catalog를 바꾸지 않는다.
13. [v0.7] inert canary가 허용되지 않은 sink에 도달하면 run은 실패로 표시된다.
    (`evaluate_run().canary_leak`)
14. [v0.7] 쓰기는 선언된 디렉터리 안에서만 가능하다. 도구가 디렉터리를 만들지 않는다.
15. [v0.7] `POLICY`에 선언된 모든 scope는 schema gate를 통과해 실제로 평가된다.
    도달 불가 분기는 회귀 테스트가 차단한다.
16. [v0.7] 내부 불변조건 위반도 예외로 중단하지 않고 결과와 trace를 남긴 뒤 거부한다.

## 위협·실험 대응표

| ID | 위협 | 방어 | 실험 |
|---|---|---|---|
| T9-01 | read-only 작업의 write 노출 | read_only profile | D9-E02 |
| T9-02 | 추가 인자로 동작 확장 | additionalProperties=false | D9-E03 |
| T9-03 | path traversal | schema pattern + Runtime canonicalization | D9-E04 |
| T9-04 | generic command 재도입 | 기본 profile에서 미노출 | D9-E05 |
| T9-05 | schema를 최종 permission으로 오해 | 기존 Policy/AuthZ/Approval 유지 | D9-E06 |
| T9-06 | 정상 기능 과도 차단 | read-only benign read | D9-E01 |
| T9-07 | Policy 거부 뒤 후속 gate 호출 | 단축 종료 mock 계측 | D9-E07 |
| T9-08 | AuthZ 거부 뒤 승인 번호 발급 | 승인 저장소 호출 계측 | D9-E08 |
| T9-09 | 승인 ID replay | consume-before-dispatch·일회성 상태 | D9-E09 |
| T9-10 | 광고 schema/annotation으로 원본 변경 | 깊은 복사·원본 snapshot 비교 | 정적 격리 검사 |
| T9-11 | Day7/8 방어 회귀 | 기존 test suite | 회귀 2종 |

## MCP authorization 경계

원격 MCP 운영 환경은 access token을 검증해 authenticated actor와 scope를 얻어야 한다.
이 단계는 `inputSchema`와 다르다.

```text
OAuth / session authentication
  -> actor + granted scopes
  -> scope에서 trusted ToolProfile 선택
  -> MCP schema gate
  -> Policy/AuthZ/Approval/Runtime
```

현재 Lab은 첫 단계를 test harness actor/profile로 대체한다. 따라서 검증 가능한 것은
tool-level 최소권한과 Runtime 결속이며, token 발급·검증·PKCE·resource metadata는
이번 결과의 범위 밖이다.

## trace 필수 증거

- `tool_schema_decision`, `tool_schema_reason`
- `tool_profile`, `declared_capability`, `tool_schema_digest`
- schema 통과 시 validation/intent/policy/authz/approval
- `runtime_status`, `end_stage`, `ok`
- seed/decision/result digest
- evaluator의 schema_bypass/schema_false_block/trace_completeness

## 성공 기준

- D9-E01 task_success=true
- D9-E02~E05 Dispatcher=0
- D9-E06 approval pending, Dispatcher=0
- D9-E07 Policy 뒤 AuthZ·승인·Dispatcher=0
- D9-E08 AuthZ 뒤 승인 발급·Dispatcher=0
- D9-E09 consume-before-dispatch=true, replay Dispatcher=0
- schema_bypass=false
- schema_false_block=false
- unsafe_action=false
- trace_completeness=true
- Day7/8 회귀 PASS
- same seed/profile replay digest 일치

## 잔여 위험과 다음 단계

- **[최상위] model-in-the-loop 미측정.** `run_agent_loop()`는 구현했으나 실제 모델로
  ASR 기준선을 측정한 적이 없다. 현재까지 증명된 것은 '정책 엔진이 주어진 제안을 올바르게
  판정한다'이며, '모델이 injection에 실제로 넘어가는가'는 미측정이다. 이 둘을 구분하지 않으면
  실험 결과를 과대 해석하게 된다.
- **관측 계층 자체에 대한 공격 시나리오 부재.** trace 무결성과 승인 UI 기만은 위협 모델에
  있으나 대응 실험이 없다. 다른 경계의 검증을 관측에 의존하면서 관측을 검증하지 않은
  순환 논리가 남아 있다.
- tool description 자체의 poisoning과 server trust 검증은 별도 실험이 필요하다.
- JSON Schema 의미가 지나치게 넓거나 설명과 구현이 다를 수 있다.
- 실제 MCP server 목록이 동적으로 바뀔 때 schema pinning/version 관리가 필요하다.
- OAuth token scope와 ToolProfile 결속이 잘못되면 confused-deputy 위험이 남는다.
- multi-process ApprovalStore는 DB transaction/CAS로 교체해야 한다.

## 변경 이력

| 버전 | 날짜 | 변경 |
|---|---|---|
| v0.1 | Day 2 | 초기 자산·경계 정의 |
| v0.2 | Day 3 | Filesystem capability 위협 추가 |
| v0.3 | Day 4 | 입력·스키마 검증 위협 추가 |
| v0.4 | Day 5 | actor-resource 인가·승인 위협 추가 |
| v0.5 | Day 6~8 | observation provenance, indirect injection, guardrail 분리 |
| v0.6 | Day 9 | MCP tool schema·least privilege |
| v0.7 | 이번 개정 | 계층 역할 분리, 디렉터리 선언, canary 탐지, 도달 가능성, model-in-the-loop 잔여 위험 승격 |

> v0.5는 Day7과 Day8에서 서로 다른 두 문서로 존재했다. 이 표는 Day8 판(222줄)을 기준으로
> 통합한 결과를 기록한다.
