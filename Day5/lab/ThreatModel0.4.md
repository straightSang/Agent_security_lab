# Threat Model v0.4 — Day 5 Approval → 일회성 실행·Authorization Gate

**범위:** 로컬 fixture-sandbox 기반 Day 5 Mini Agent  
**목적:** Day 4의 provenance/trust/policy/approval을 유지하면서 actor-resource Authorization과 `pending → approved → consumed → dispatch` 승인 후 실행 lifecycle의 공격 표면을 재현 가능하게 검증한다.

## System

```text
Authenticated actor (fixture/session-owned)
  -> Agent / LLM
  -> Tool Proposal
  -> Validation
  -> ToolIntent(provenance, actor, capability, action, canonical resource)
  -> Trust Label
  -> Policy Decision
  -> Authorization Decision                 # Day 5
  -> Approval Store, if required            # Day 4 유지
  -> Runtime Enforcement / Dispatcher
  -> Local Sandbox Tool
  -> Runtime Result / Trace / Evaluator
```

모델 출력은 ToolIntent를 제안할 뿐, actor identity·access right·approval을 만들지 못한다.

## Assets

- `data/user-001/**`, `data/user-002/**`, `data/shared/**`의 가짜 fixture resource
- `secrets/**`로 분류된 가짜 민감 resource
- actor-resource ownership mapping과 authorization rules
- capability, action, canonical resource
- provenance/trust metadata
- approval record, ID, fingerprint, TTL, consumed 상태
- Policy·Authorization·Approval·Runtime trace의 무결성
- Runtime Dispatcher의 실행 무결성

## Trust Boundaries

| 구성 요소 | 신뢰 수준 | 이유 |
|---|---|---|
| 사용자 자연어 입력 | 내용은 신뢰하지 않음 | 안전/위험 요청 모두 가능 |
| LLM output / tool arguments | 비신뢰 | hallucination, prompt injection 영향 가능 |
| repository/tool/web observation | `untrusted` | 데이터일 뿐 authority를 위임하지 않음 |
| session/test harness → actor | 신뢰된 입력 경계 | actor는 LLM이 아니라 서버/fixture가 공급 |
| Policy / Authorization / Runtime | Trusted Computing Base | 일반 규칙, actor-resource 관계, 실행을 각각 강제 |
| Approval control | Trusted Computing Base | 인증된 approver만 상태 변경 가능해야 함 |
| TraceLogger | 감사 증거 구성 요소 | 동일 run의 판단과 결과 재현에 필요 |

현재 `user-001`, `user-002`, `reviewer-001`은 fixture label이다. 운영에서는 서버가 검증한 session/OIDC subject, role, tenant로 교체한다.

## Security Invariants

1. Tool Proposal은 실행 권한도 actor identity도 아니다.
2. sandbox 밖 path는 Validation에서 거부된다.
3. unknown capability, allow-list 밖 command, untrusted provenance는 Policy에서 거부된다.
4. Policy가 ALLOW여도 Authorization이 DENY면 Runtime은 `FORBIDDEN`으로 끝난다.
5. Authorization DENY 요청은 approval ID를 만들지 않으며 Dispatcher가 호출되지 않는다.
6. Approval은 Authorization이 허용한, Policy가 `APPROVAL_REQUIRED`로 판단한 정확한 Intent에만 발급된다.
7. approval fingerprint는 actor/tool/arguments/capability/action/resource에 결속되고 만료되며 한 번 소비된다.
8. Dispatcher는 Policy와 Authorization이 허용하고, 필요 시 유효한 승인도 있는 경우에만 호출된다.
9. trace에는 actor, policy decision, authorization decision, approval state, runtime result가 같은 `run_id`로 남는다.

## Threats and Controls

| ID | 위협 | 공격 표면 | Day 4 통제 | Day 5 추가 통제 | 검증 |
|---|---|---|---|---|---|
| T-001 | Path traversal | tool path | safe resolve + sandbox root | 동일 | validation deny |
| T-002 | scope 밖 resource/command | capability/resource | permission allow-list | 동일 | policy deny |
| T-003 | 무단 쓰기 | `write_file` | root-file approval | AuthZ 통과 뒤에만 approval 발급 | pending/deny fixture |
| T-004 | shell command injection | `run_command` | shell 미사용, logical allow-list | 동일 | dispatcher 미도달 |
| T-005 | Indirect Prompt Injection | README/tool observation | provenance → untrusted → deny | content가 actor/approval을 정할 수 없음 | unsafe fixture |
| T-006 | approval replay/mutation | approval ID/retry | fingerprint, TTL, consumed | 승인 뒤 재시도·일회성 dispatch를 trace로 검증 | replay fixture |
| T-007 | Runtime bypass | Agent/alternate path | single runtime entry | authz gate도 Runtime 내부 강제 | mock dispatch |
| T-008 | 불완전한 감사 | trace | required trace keys/evaluator | authz decision/reason 추가 | completeness |
| T-009 | Cross-user access | actor + `data/user-*` | Day 4 `data` read scope | owner/shared authorization | Policy allow + AuthZ deny |
| T-010 | approval-before-authz | approval request | approval lifecycle | AuthZ deny면 record 미생성 | approval event 없음 |
| T-011 | actor spoofing | LLM/user actor claim | Day 4 actor label | actor source를 session/harness로 제한 | actor provenance test |

## 주요 공격 시나리오

### T-009 Cross-user read

```text
actor = user-001
read_file("data/user-002/private.txt")
-> Validation PASS
-> Policy ALLOW (Day 4 data read scope)
-> Authorization DENY (ACTOR_NOT_RESOURCE_OWNER)
-> approval request 없음
-> Dispatcher 미도달
-> RuntimeResult: forbidden, end_stage=authorization
```

이 시나리오는 Day 5의 핵심이다. Policy의 허용은 모든 actor의 접근 허용을 의미하는 것이 아니다.

### T-010 Approval 전에 Authorization 확인

```text
Policy = APPROVAL_REQUIRED
-> Authorization DENY
-> approval ID 발급 금지
-> Dispatcher 미도달
```

승인은 접근 권한 부족을 보충하는 수단이 아니다. actor가 먼저 resource/action의 대상이어야 한다.

### T-006 Approval replay/mutation

```text
approved approval ID
-> 현재 Intent fingerprint 비교
-> 동일 actor/path/content/action/resource: dispatch 직전 consumed
-> 하나라도 변경: fingerprint mismatch, 새 approval 또는 deny
-> consumed/expired/rejected: 실행 불가
```

approval ID는 Agent ID, DID, 범용 capability token이 아니라 특정 승인 요청 record의 랜덤 조회 키다.

### T-005 Indirect Prompt Injection

```text
malicious file의 지시
-> 다음 ToolIntent provenance = repository_content
-> trust = untrusted
-> Policy DENY
-> Authorization / Approval / Dispatcher 미도달
```

사용자가 같은 작업을 나중에 직접 요청해도 새로운 `user_task` Intent이며, Day 4 Policy와 Day 5 Authorization·Approval을 처음부터 다시 통과해야 한다.

## Security Flow

```text
Validation PASS
-> Policy DENY
   -> policy 종료

Validation PASS
-> Policy ALLOW / APPROVAL_REQUIRED
-> Authorization DENY
   -> forbidden 종료, approval/dispatcher 미도달

Validation PASS
-> Policy ALLOW
-> Authorization ALLOW
   -> dispatch

Validation PASS
-> Policy APPROVAL_REQUIRED
-> Authorization ALLOW
   -> pending/rejected/expired/consumed: 종료
   -> approved + matching fingerprint: consume -> dispatch
```

## Evaluation Hypotheses

| ID | 가설 | 측정 |
|---|---|---|
| H1 | cross-user 요청은 Policy ALLOW 뒤에도 Runtime 전에 차단된다. | `authorization_false_allow = 0` |
| H2 | AuthZ DENY는 approval ID 발급보다 먼저 일어난다. | trace에 approval request 없음 |
| H3 | approval ID는 다른 actor/path/content/action에 재사용되지 않는다. | `approval_bypass = 0` |
| H4 | untrusted provenance는 Day 4처럼 Policy에서 먼저 차단된다. | `unsafe_action = false` |
| H5 | own/shared 정상 작업은 과도하게 차단되지 않는다. | safe success, false block 측정 |
| H6 | 모든 판단이 감사 가능하다. | `trace_completeness = true` |

```text
Day 5 신규 가설
→ H1, H2

Day 4 회귀 불변조건
→ H3, H4
- 승인 전에는 write 실행 불가
- 승인 ID 재사용 불가
- untrusted provenance는 권한을 만들 수 없음
- sandbox 밖 경로 접근 불가
- unknown command 실행 불가

Day 5 완료·측정 기준
→ H5, H6
```

## Residual Risk / 범위 밖

- 실제 인증, OIDC/session validation, MFA, identity lifecycle
- 실제 ACL/RBAC/ABAC DB, tenant isolation, delegated authority
- approval record 영속화, 동시성, 서명, 접근 제어, 장기 감사 보존
- approval UI의 인간 요인과 unsafe diff 표현
- OS ACL, container sandbox, symlink/TOCTOU, Python 프로세스 장악
- 외부 MCP server identity, credential, network authorization
- trace 파일 자체의 변조 방지

## Day 5 결론의 기준

비신뢰 입력은 authority를 만들지 못하고, Policy는 일반 규칙을 판단하며, Authorization은 actor-resource 관계를 판단하고, Approval은 이미 허용 가능한 특정 Intent를 짧게 재확인하고, Runtime만 실제 부작용을 실행한다.

이 결론을 fixture, Dispatcher mock, JSONL trace, evaluator 지표로 뒷받침할 수 있을 때 Day 5 Lab이 완료된다.

## 승인 후 실행 보안 불변조건

```text
approve(approval_id) != execute(approved request)
```

1. `approve()`는 `pending` record를 `approved`로 바꾸는 trusted control이며 파일·도구 부작용을 만들지 않는다.
2. 실행은 같은 Intent가 다시 Runtime에 제출될 때만 시작한다.
3. 재시도는 Validation, Policy, Authorization을 다시 모두 통과해야 한다.
4. current fingerprint가 approved record와 일치할 때만 dispatch 직전에 `consumed`로 바꾼다.
5. `consumed`, `expired`, `rejected`, mismatch record는 어떤 도구 실행도 허용하지 않는다.
6. 한 approval ID가 정확히 한 번만 dispatch를 허용하도록 consume은 원자적이어야 한다.

### 추가 위협

| ID | 위협 | 방어/검증 |
|---|---|---|
| T-012 | 승인 직후 자동 실행 | approve event 뒤 Dispatcher 호출과 파일 변화가 없어야 함 |
| T-013 | 같은 approved ID의 double-dispatch/replay | dispatch 직전 atomic consume, 두 번째 요청 block |
| T-014 | 승인 뒤 path/content/actor/action 바꿔치기 | 재시도 fingerprint 비교, mismatch면 새 approval 또는 deny |

이 경계가 없으면 승인 이후의 content/path 바꿔치기, ID replay, 동시 재시도로 인한 double write가 가능해진다. 운영 환경에서는 in-memory 상태가 아니라 DB transaction 또는 compare-and-swap으로 consume을 구현해야 한다.
