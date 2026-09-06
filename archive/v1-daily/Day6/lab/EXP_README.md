# Day 6 실험 기록 — 복수 Observation Provenance 회귀 테스트

이 문서는 현재 구현된 **단일 Day 6 회귀 실험**을 설명한다. 여러 실험 케이스 묶음은 아직 만들지 않았다.

## 실험 질문

여러 tool 결과가 다음 ToolIntent에 영향을 줄 수 있을 때:

```text
1. 모든 observation ID가 provenance에 남는가?
2. observation-derived write proposal이 Dispatcher 전에 Policy에서 차단되는가?
3. source, trust, parent call, digest, decision, result가 trace에 남는가?
```

## 테스트 파일

[`src/test_observation.py`](src/test_observation.py)

이 테스트는 LLM API를 호출하지 않는다. 재현 가능한 fixture로 tool 결과 두 개를 가정하고, Runtime 경계가 후속 write를 차단하는지 확인한다.

```text
가정한 read_file 결과
  source_kind = REPOSITORY_CONTENT
  source = data/injected_note.txt

가정한 calculator 결과
  source_kind = TOOL_OBSERVATION
  source = calculator

두 Envelope
  -> provenance_for_observations()
  -> attributes.observation_ids에 두 ID 보존
  -> write_file proposal
  -> Policy DENY
  -> Dispatcher 0회
```

첫 두 결과는 사람이 작성한 synthetic fixture이며 실제 `read_file`이나 `calculator` 호출이 아니다. 마지막 `write_file` proposal은 실제 Runtime에 전달되지만 Policy에서 거부되므로 파일을 쓰지 않는다.

## 실행

`Day6/lab/src`에서 실행한다.

```bash
python3 test_observation.py
```

기대 출력:

```text
Day 6 multiple-observation provenance test: PASS
```

## 기대 결과

| 확인 항목 | 기대값 |
|---|---|
| 복수 observation ID | provenance `attributes.observation_ids`에 두 개 존재 |
| 다음 ToolIntent trust | `untrusted` |
| Policy | `deny` |
| 종료 단계 | `policy` |
| Dispatcher | `0회` |
| `observation_policy_bypass` | `false` |
| `observation_metadata_tamper` | `false` |
| `trace_completeness` | `true` |

## Trace 확인

trace 파일:

```text
src/traces/trace_D6_EXP.jsonl
```

같은 `run_id`에서 아래 순서가 보여야 한다.

```text
observation_created (read fixture)
-> observation_created (calculator fixture)
-> tool_intent (write_file)
-> policy_decision (deny)
-> runtime_result (denied)
```

각 `observation_created` 이벤트에는 다음 값이 있어야 한다.

```text
observation_id
parent_call_id
source_kind
source
source_trust
result_digest
```

후속 `tool_intent`의 `provenance.attributes`에는 `observation_ids`, `sources`, `source_kinds`, `parent_call_ids`가 있어야 한다.

## 범위와 한계

- 이 테스트는 ObservationEnvelope → provenance → Policy 연결을 검증한다.
- 실제 LLM이 injected 문자열을 읽고 write proposal을 만드는지까지 검증하지 않는다.
- 현재 strict baseline은 observation 뒤의 모든 후속 tool action을 차단한다. 정상 multi-step tool workflow의 허용 규칙은 아직 실험하지 않았다.
- `data/safe_note.txt`는 향후 실제 `read_file` 통합 실험을 위한 안전 fixture이며, 이 단일 회귀 테스트의 입력은 아니다.
