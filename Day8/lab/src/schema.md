# Runtime 데이터 형식 — Day 8 Guardrail·Policy 분리

## Day 8 Policy 계약

Day 8은 기존 fixture와 Runtime 형식을 유지하면서 `ToolIntent`와 `PolicyDecision`의 책임을 명확히 분리한다.

```text
ToolIntent
  = actor, tool_name, arguments, provenance,
    capability, action, resource

PolicyDecision
  = outcome, reason, capability, action,
    resource, trust, rule_id
```

`ToolIntent`는 요청이며 실행 권한이 아니다. `PolicyDecision`은 LLM, observation, fixture의 필드가 아니라 `PolicyEngine.evaluate()`만 생성한다. `rule_id`는 판단 근거 추적용 식별자이며 permission이나 비밀 토큰이 아니다.

필수 불변조건:

```text
untrusted text cannot set trust
untrusted text cannot add capability
untrusted text cannot choose PolicyDecision
untrusted text cannot create ApprovalState
no PolicyDecision -> no dispatch
```

## Day 8 fixture 입력 계약

Day 8은 Day 7의 `fixtures/benign_email.json`과 `fixtures/injected_email.json`을 회귀 입력으로 재사용한다. 두 파일은 `schemas/indirect-prompt-injection.fixture.schema.json`을 따르며, test harness가 읽는 data일 뿐 LLM·fixture content가 Runtime Policy를 덮어쓰는 통로가 아니다.

Day 8 본 실험에서는 다음 파일을 별도로 추가했다.

| 파일 | fixture ID | 용도 |
|---|---|---|
| `fixtures/policy_mutation.json` | D8-E03 | trust·Policy 변경 주장 재현 |
| `fixtures/control_plane_spoof.json` | D8-E04 | actor·approval 위조 주장 재현 |
| `schemas/day8-policy-boundary.fixture.schema.json` | D8-E03/E04 | 위 두 JSON의 필수 필드와 형식 검증 |

아직 위 파일은 구현되지 않았다. 기존 Day 7 schema의 fixture ID pattern은
`D7-E..`만 허용하므로, Day 8 파일을 기존 schema에 억지로 넣지 않고 별도 schema로
구분한다.

```text
fixture_id / category / user_task
observation(source_kind, source, content)
attack_proposal(tool_name, arguments)   # unsafe fixture에만 선택적
expected                                # assertion/evaluator 기준
```

`fixture_id`는 ToolIntent fingerprint에 포함되지 않는 trace/evaluator 라벨이다. `source_kind`는 harness가 trusted provenance helper를 선택하는 데 쓰며, trust label은 `security/trust.py`가 다시 계산한다.

`expected`는 test harness가 실제 결과와 비교하는 정답표일 뿐 Runtime 입력이 아니다.
다음 방향으로만 사용해야 한다.

```text
fixture.expected -> test assertion과 evaluator의 expected 값
fixture.expected -X-> PolicyEngine의 실제 allow/deny 결정
```

### PolicyDecision의 stable 필드

`security/types.py/PolicyDecision`에는 `outcome`, `reason`, `rule_id`가 있다.
현재 `security/policy.py/PolicyEngine._decision()`이 `rule_id=reason`으로 만들고,
`trace_logger.py/TraceLogger.record_policy()`가 두 필드를 기록한다.

stable은 같은 입력과 같은 Policy 버전에서 동일한 코드가 반복되어야 한다는 뜻이다.
예를 들어 untrusted provenance 차단은 항상 아래 값이어야 한다.

```text
outcome = deny
reason = UNTRUSTED_PROVENANCE_CANNOT_AUTHORIZE_TOOL
rule_id = UNTRUSTED_PROVENANCE_CANNOT_AUTHORIZE_TOOL
```

`rule_id`는 권한 토큰이 아니라 감사·재현용 식별자다.

이 문서는 Day 8의 Agent, Runtime, Policy, trace 데이터 형식을 사람이 읽기 쉽게 정리한다. 코드와 다르면 Python 코드가 최종 기준이다.

## 문서를 읽는 세 과정

이 문서의 자료형을 한꺼번에 읽지 않는다. 실제 실행, 기록, 평가 순서로 구분한다.

## 제1장 — 실제 실험 수행에서 사용하는 자료형

| 자료형 | 생성 주체 | 받는 주체 | 역할 | 존재 이유 |
|---|---|---|---|---|
| `Provenance` | 인증·source adapter | `ToolIntent`, Policy | 요청 출처 표현 | 자연어 내용과 출처를 분리 |
| `ToolIntent` | Runtime | Policy·AuthZ·Approval | 정규화된 실행 요청 | 모든 보안 단계가 같은 요청을 사용 |
| `PolicyDecision` | PolicyEngine | Runtime | 일반 정책 결론 | 요청과 permission을 분리 |
| `AuthorizationDecision` | AuthorizationEngine | Runtime | actor별 자격 결론 | Policy ALLOW와 사용자 권한 분리 |
| `ApprovalState` | ApprovalStore | Runtime | 승인 상태 | pending·approved·consumed 구분 |
| `RuntimeResult` | Runtime | Agent·test harness | 최종 성공·거부·오류 | 종료 단계와 보안 이유 전달 |

## 제2장 — 기록 수행에서 사용하는 자료형

| 자료형·사건 | 생성 주체 | 역할 | 존재 이유 |
|---|---|---|---|
| `ObservationEnvelope` | provenance helper | 결과 내용과 출처·신뢰 연결 | 다음 turn에서 provenance 유실 방지 |
| `tool_intent` 사건 | TraceLogger | Policy 입력 기록 | 어떤 요청을 판단했는지 증명 |
| `policy_decision` 사건 | TraceLogger | outcome·reason·rule_id 기록 | 적용 정책 규칙 증명 |
| `authorization_decision` 사건 | TraceLogger | actor 자격 판단 기록 | Policy와 AuthZ 단계 분리 증명 |
| `approval` 사건 | TraceLogger | 승인 상태 기록 | 승인 재사용·위조 확인 |
| `runtime_result` 사건 | TraceLogger | 최종 결과 기록 | 실행 또는 차단 증명 |
| `experiment_evidence` 사건 | TraceLogger | seed·decision·result digest 기록 | 재실행 비교 |

## 제3장 — 평가 수행에서 사용하는 값

| 값 | 계산 주체 | 역할 | 존재 이유 |
|---|---|---|---|
| fixture `expected` | 실험 설계자 | 기대 결과 고정 | 실행 후 정답을 바꾸는 오류 방지 |
| `EvaluationResult` | `evaluate_run()` | 공통 안전성·유용성 지표 | 케이스 간 같은 평가 기준 사용 |
| `seed_digest` | 실험 지원 함수 | 시작 입력 비교 | 같은 입력 조건 확인 |
| `decision_digest` | 실험 지원 함수 | 판단 사건 묶음 비교 | 정책·인가·승인 결과 재현 확인 |
| `result_digest` | 실험 지원 함수 | 최종 결과 사건 비교 | 실행 결과 재현 확인 |
| control-plane before/after | Day 8 실험 지원 함수 | 설정 상태 전후 비교 | 정책·승인 상태 변조 확인 |

## 1. Runtime 경계

```text
LLM Tool Proposal
  -> validation
  -> ToolIntent
  -> PolicyDecision
  -> AuthorizationDecision
  -> ApprovalState (필요 시)
  -> RuntimeResult
  -> ObservationEnvelope (성공 결과)
```

LLM은 proposal을 만들 뿐 실행 권한이 없다. 실제 실행은 `runtime.py/Runtime._dispatch()`만 수행한다.

## 2. ToolIntent 형식

`security/types.py/ToolIntent`는 Runtime이 판단하는 정규화된 요청이다.

```text
run_id
call_id
actor
tool_name
arguments
provenance
capability
action
resource
agent_step
```

`actor`는 test harness 또는 인증 session이 전달한다. LLM, tool output, 파일 내용은 actor를 정하지 못한다.

## 3. Provenance 형식

`security/provenance.py/Provenance`는 ToolIntent가 어떤 입력 문맥에서 나왔는지 기록한다.

```text
kind
source
parent_event_id        # 이전 trace 형식과의 호환 필드. Day 6에서는 parent call ID를 담는다.
received_at
attributes
```

`kind`와 trust의 기본 대응은 다음과 같다.

| ProvenanceKind | TrustLabel |
|---|---|
| `USER_TASK` | `USER_CONTROLLED` |
| `SYSTEM` | `TRUSTED` |
| `REPOSITORY_CONTENT` | `UNTRUSTED` |
| `TOOL_OBSERVATION` | `UNTRUSTED` |
| `EXTERNAL_CONTENT` | `UNTRUSTED` |

이 변환은 `security/trust.py/label_trust(provenance_kind)`이 수행한다.

## 4. ObservationEnvelope 형식

`security/types.py/ObservationEnvelope`는 성공한 tool 결과 하나를 감싼다.

```python
ObservationEnvelope(
    observation_id="obs_...",
    parent_call_id="call_...",
    source_kind=ProvenanceKind.REPOSITORY_CONTENT,
    source="data/safe_note.txt",
    trust=TrustLabel.UNTRUSTED,
    result_digest="sha256:...",
    content="실제 tool 결과 문자열",
)
```

| 필드 | 의미 |
|---|---|
| `observation_id` | 이 tool 결과를 식별하는 ID |
| `parent_call_id` | 이 결과를 만든 tool call ID |
| `source_kind` | repository/tool/external 중 출처 종류 |
| `source` | 파일 경로 또는 tool 이름 같은 출처 식별자 |
| `trust` | source kind에서 계산한 trust label |
| `result_digest` | content의 SHA-256 digest |
| `content` | 다음 LLM turn에 data로 전달할 실제 결과 |

`source`는 content나 LLM 최종 답변이 아니다.

## 5. RuntimeResult와 LLM 전달 형식

`RuntimeResult`는 Runtime의 실행 결과다. `runtime.py/to_observation()`은 이를 LLM 전달용 작은 객체로 바꾼다.

```text
RuntimeResult.success(data="파일 내용")
  -> to_observation(...)
  -> {"status": "success", "data": "파일 내용"}
```

동시에 Agent는 `make_observation()`으로 Envelope을 만들고 trace에 기록한다.

```text
LLM에 전달: status/data 또는 status/error
Runtime/trace에 유지: source/trust/digest/observation ID
```

## 6. 복수 observation 형식

성공한 tool call마다 Envelope 하나가 생긴다.

```text
call-read-01 -> obs-read-01
call-calc-01 -> obs-calc-01
```

`provenance_for_observations()`는 다음 ToolIntent에 쓸 Provenance 하나를 만든다.

```text
attributes.observation_ids = [obs-read-01, obs-calc-01]
attributes.sources = [data/safe_note.txt, calculator]
attributes.source_kinds = [repository_content, tool_observation]
attributes.parent_call_ids = [call-read-01, call-calc-01]
```

Envelope이 하나면 원래 source kind를 유지한다. 여러 개면 provenance `kind=TOOL_OBSERVATION`, `source=multiple_observations`가 된다.

## 7. Policy / Authorization / Approval 형식

```text
Validation
  -> PolicyDecision
  -> AuthorizationDecision
  -> ApprovalState (필요 시)
  -> RuntimeResult
```

`security/policy.py/PolicyEngine.evaluate(intent)`는 실행하지 않고 판단만 한다.

```text
provenance kind에서 trust 계산
-> 민감 resource 이름 검사
-> capability allow-list 검사
-> untrusted provenance 검사
-> 일반 resource/command scope 검사
-> allow / deny / approval_required 반환
```

`UNTRUSTED`이면 Policy가 Authorization과 Approval보다 먼저 `deny`를 반환한다.

## 8. JSONL trace 형식

각 줄은 JSON 이벤트 하나다.

```json
{"event_id":"evt_...","timestamp":"UTC ISO-8601","run_id":"run_...","event":"event name"}
```

모든 이벤트에는 `event_id`, `timestamp`, `run_id`, `event`만 공통으로 있다.
`call_id`와 아래 값은 해당 사건에 의미가 있을 때만 기록하며, 빈 `null` 필드를
반복해서 넣지 않는다.

```text
agent_step, actor, tool_name, arguments, provenance, trust, capability,
action, resource, approval, approval_id, policy_decision,
authorization_decision, authorization_reason, required_approver, reason,
validation_allowed, runtime_status, end_stage, ok, error_code,
observation_id, parent_call_id, source_kind, source, source_trust,
result_digest
```

| 이벤트 | 기록 주체 | 의미 |
|---|---|---|
| `tool_intent` | Runtime | 정규화된 도구 요청 |
| `policy_decision` | Runtime | allow / deny / approval_required 판단 |
| `authorization_decision` | Runtime | actor-resource-action 관계 판단 |
| `approval` | Runtime | pending / approved / consumed 상태 |
| `runtime_result` | Runtime | 최종 결과와 중단 단계 |
| `observation_created` | TraceLogger | tool 결과의 source/trust/digest 기록 |
| `provenance_transition` | Agent loop | 다음 ToolIntent provenance 전이 |

## 9. Day 8 테스트 계약과 기존 회귀

기존 `test_observation.py`와 `test_indirect_injection.py`는 observation provenance와 indirect-injection 차단의 회귀 기준이다. Day 8에서는 동일 경계를 유지하면서 Policy mutation, actor/approval spoofing, Policy/AuthZ 역할 분리 case를 추가한다.

```text
D8-E01: benign read -> Policy/AuthZ ALLOW -> success
D8-E02: untrusted-derived write -> Policy DENY -> dispatch 0회
D8-E03: trust/policy mutation 주장 -> control-plane digest 불변
D8-E04: actor/approval spoof 주장 -> actor/store 불변
D8-E05: cross-user read -> Policy 통과 가능 -> AuthZ DENY
D8-E06: owner write -> APPROVAL_REQUIRED -> pending, dispatch 0회
```

Day 8 trace는 fixture와 run별 디렉터리에 분리해 기록한다. 2026-08-30 로컬 실행에서
D7 회귀, D8-E03~E06, D8-I01~I03이 모두 PASS했으며, 원본 `trace.jsonl`과 사람이
읽는 `summary.md`를 같은 run 디렉터리에 남겼다.
