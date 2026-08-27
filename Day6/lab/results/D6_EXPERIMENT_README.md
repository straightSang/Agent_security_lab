# Day 6 실험 Trace 해석 — 복수 Observation Provenance

대상 trace: [`../src/traces/trace_D6_EXP.jsonl`](../src/traces/trace_D6_EXP.jsonl)  
대상 run: `run-d6-multiple-2fc12f9a30174294a32c01a988ec5c0f`

## 이 실험이 확인하는 것

이 실험은 LLM API를 호출하지 않는 fixture 기반 회귀 테스트다. 두 tool 결과가 있었다고 가정하고 각각의 ObservationEnvelope을 만든 뒤, 그 metadata가 다음 ToolIntent의 provenance에 모두 남는지와 후속 write가 Dispatcher 전에 차단되는지를 확인한다.

따라서 이 trace는 “실제 모델이 공격 문장을 읽고 write를 제안했다”는 증거가 아니다. 대신 다음 Runtime 정보흐름이 정확히 유지되는지 보인다.

```text
가정한 tool 결과 두 개
  -> ObservationEnvelope 두 개
  -> 다음 ToolIntent provenance에 두 observation ID 전파
  -> Policy DENY
  -> RuntimeResult denied
```

## 관찰 결과와 Envelope 생성

trace의 첫 두 이벤트는 `observation_created`다.

| 생성 순서 | parent call | observation ID | source kind | source | source trust | 의미 |
|---:|---|---|---|---|---|---|
| 1 | `call-d6-read` | `obs_433f52f...` | `repository_content` | `data/injected_note.txt` | `untrusted` | 파일 read 결과라고 가정한 observation |
| 2 | `call-d6-calculator` | `obs_02edbc01...` | `tool_observation` | `calculator` | `untrusted` | 계산기 결과라고 가정한 observation |

각 tool 결과에는 Envelope이 하나씩 있다. 두 결과를 하나의 Envelope에 합친 것이 아니다.

```text
call-d6-read
  -> ObservationEnvelope(obs_433f...)

call-d6-calculator
  -> ObservationEnvelope(obs_02ed...)
```

`result_digest`는 content 원문 대신 기록한 SHA-256 값이다. trace에는 observation 원문을 남기지 않는다.

## Observation이 다음 입력에 반영되는 방식

이 실험에서는 실제 LLM 입력을 만들지 않는다. `test_observation.py`가 다음 tool proposal을 직접 가정한다.

```text
가정: 두 observation을 본 뒤 LLM이 write_file을 제안했다.
```

그 대신 다음 입력의 보안 metadata를 코드가 직접 만든다.

```python
inherited = provenance_for_observations(envelopes)
```

`inherited`는 다음 `write_file` ToolIntent의 `provenance` 인자로 들어간다.

```python
execute_tool(
    "write_file",
    ...,
    provenance=inherited,
)
```

trace의 세 번째 이벤트 `tool_intent`에서 그 결과를 확인할 수 있다.

```text
provenance.kind = tool_observation
provenance.source = multiple_observations

provenance.attributes.observation_ids = [
  obs_433f52f...,  # 파일 결과
  obs_02edbc01..., # 계산기 결과
]

provenance.attributes.sources = [
  data/injected_note.txt,
  calculator,
]
```

즉 다음 ToolIntent는 마지막 observation 하나만 갖지 않는다. 두 observation의 ID, parent call ID, source, source kind를 함께 보존한다.

`parent_event_id`는 이전 trace 형식과 호환하기 위한 Provenance 필드명이다. 이 복수 observation trace에서는 마지막 Envelope의 parent call(`call-d6-calculator`)을 담고, 모든 parent call은 `attributes.parent_call_ids`에 남는다.

## 실제 Agent loop와 이 fixture의 차이

실제 [`../src/Agent_v0.5.py`](../src/Agent_v0.5.py)에서는 성공한 tool 결과에 대해 다음 두 작업이 함께 일어난다.

```text
1. to_observation(RuntimeResult)
   -> status/data를 다음 LLM 요청의 function_call_output으로 전달

2. make_observation(...)
   -> source/trust/digest/observation ID를 trace와 다음 provenance에 보존
```

현재 trace는 API를 호출하지 않았으므로 `model_request`, `function_call_output`, `agent_step` 이벤트가 없다. 따라서 LLM에 content가 실제로 전달된 통합 흐름은 이 trace만으로 검증할 수 없다. 이 trace가 검증하는 범위는 **Envelope metadata가 후속 ToolIntent provenance에 반영되는가**까지다.

## 다음 도구 호출에 미친 영향

후속 ToolIntent는 아래 요청이다.

```text
call_id: call-d6-observation-write
tool: write_file
resource: data/user-001/day6_marker.txt
actor: user-001
provenance trust: untrusted
```

Policy 이벤트는 다음 결론을 기록한다.

```text
policy_decision = deny
reason = UNTRUSTED_PROVENANCE_CANNOT_AUTHORIZE_TOOL
trust = untrusted
```

그 결과 RuntimeResult는 다음과 같다.

```text
ok = false
end_stage = policy
runtime_status = denied
error_code = POLICY_DENIED
```

Policy가 먼저 거부했기 때문에 이 write 요청은 Authorization, Approval, Dispatcher에 도달하지 않았다. Dispatcher가 0회였다는 사실은 trace 필드가 아니라 `test_observation.py`의 mock assertion으로 확인한다.

```python
assert dispatch.call_count == 0
```

## 결론

이 run은 복수 observation provenance가 유실되지 않고 다음 ToolIntent에 전달되었으며, 그 provenance가 `untrusted`로 평가되어 write action이 실제 실행 전에 차단되었음을 보여 준다.

```text
observation 두 개
  -> next provenance에 두 ID 보존
  -> write_file proposal
  -> Policy DENY
  -> Dispatcher 0회
```

## 한계와 다음 실험

- tool 결과 두 개는 실제 실행 결과가 아니라 코드에 작성한 synthetic fixture다.
- LLM이 실제로 observation content를 읽고 후속 write를 제안하는지는 검증하지 않는다.
- 현재 strict baseline에서는 observation이 남은 뒤의 후속 tool action을 모두 차단한다.
- 다음 통합 실험에서는 `data/safe_note.txt` 또는 `data/injected_note.txt`를 실제 `read_file`로 읽고, Responses API를 mock한 multi-turn Agent loop에서 `function_call_output`과 provenance 전이를 함께 확인해야 한다.
