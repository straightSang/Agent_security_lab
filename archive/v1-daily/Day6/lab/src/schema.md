# Runtime 데이터 형식 — Day 6 Observation Provenance

이 문서는 Day 6의 Agent, Runtime, trace, observation 데이터 형식을 사람이 읽기 쉽게 정리한다. 코드와 다르면 Python 코드가 최종 기준이다.

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
{"event_id":"evt_...","timestamp":"UTC ISO-8601","run_id":"run_...","call_id":"call_... 또는 null","event":"event name"}
```

모든 이벤트에는 아래 공통 키가 있다. 해당 단계에서 값이 없으면 `null`이다.

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

## 9. 현재 Day 6 회귀 테스트

`test_observation.py`는 LLM API 없이 synthetic observation 두 개를 만들고 후속 `write_file`을 Runtime에 전달한다.

```text
Envelope 두 개
-> 다음 provenance에 두 observation ID가 있는지 검사
-> write_file
-> Policy DENY
-> Dispatcher 0회
-> evaluator 확인
```

trace 파일은 `traces/trace_D6_EXP.jsonl`이다.
