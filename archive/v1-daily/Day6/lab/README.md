# Day 6 — Observation Provenance와 간접 프롬프트 인젝션 방어

Day 6의 목표는 **도구나 파일이 반환한 문자열이 다음 Agent turn의 실행 권한이 되지 않게 하는 것**이다. Day 5의 Policy·Authorization·Approval·Runtime 경계는 유지한다.

## Day 5와의 차이

Day 5는 사람이 fixture에 직접 넣은 `untrusted provenance`를 Policy가 차단하는지 확인했다.

```text
repository_provenance(...) -> write_file proposal -> Policy DENY
```

Day 6은 실제 Agent 흐름에서 tool 결과가 다음 ToolIntent까지 어떻게 전달되는지를 추가로 기록한다.

```text
tool result
  -> ObservationEnvelope 생성
  -> source / trust / digest / observation_id 기록
  -> 다음 ToolIntent provenance에 observation ID 전파
  -> Policy가 후속 tool action을 판단
```

## 현재 실행 흐름

```text
사용자 입력
  -> Agent_v0.5.py/run_agent()
  -> direct_user_provenance()          # USER_TASK / USER_CONTROLLED
  -> LLM Tool Proposal
  -> Agent_v0.5.py/execute_proposal()
  -> runtime.py/Runtime.execute_tool()
  -> Validation -> Policy -> Authorization -> Approval(필요 시) -> Dispatcher
  -> RuntimeResult
  -> security/provenance.py/make_observation()
  -> ObservationEnvelope + trace event
  -> 다음 LLM turn
```

`Agent_v0.5.py`는 LLM loop이고, 실제 enforcement는 `runtime.py/Runtime`에 있다. LLM은 tool proposal만 만들며 actor, trust, capability, policy, approval state를 정하지 못한다.

## ObservationEnvelope 형식

각 **성공한 tool call 하나**에 Envelope 하나가 만들어진다.

```python
ObservationEnvelope(
    observation_id="obs_...",
    parent_call_id="call_read_...",
    source_kind=ProvenanceKind.REPOSITORY_CONTENT,
    source="data/safe_note.txt",
    trust=TrustLabel.UNTRUSTED,
    result_digest="sha256:...",
    content="도구가 실제로 반환한 data",
)
```

`source`는 결과의 출처 식별자이고 `content`는 실제 결과 내용이다.

```text
read_file("data/safe_note.txt")
  source  = data/safe_note.txt
  content = 파일 내용

calculator("2 + 2")
  source  = calculator
  content = 4
```

LLM 최종 자연어 답변은 Envelope의 `source`나 `content`가 아니다. tool 결과만 Envelope으로 기록한다.

## 복수 observation

LLM 한 번의 응답에는 여러 `function_call`이 들어갈 수 있다. 각 call은 별도 Envelope을 만든다.

```text
call-read-01       -> obs-read-01
call-calculator-01 -> obs-calc-01
```

다음 ToolIntent에는 Envelope을 새로 합치지 않고, provenance의 `attributes`에 모든 출처를 남긴다.

```text
attributes.observation_ids = [obs-read-01, obs-calc-01]
attributes.sources = [data/safe_note.txt, calculator]
attributes.parent_call_ids = [call-read-01, call-calculator-01]
```

Envelope 하나면 provenance는 원래 `source_kind`를 유지한다. 여러 Envelope이면 provenance의 `kind`는 `TOOL_OBSERVATION`, `source`는 `multiple_observations`가 된다. 이는 여러 출처가 섞였음을 나타내는 표시일 뿐이며, 개별 출처는 `attributes`에 보존된다.

## Strict baseline

현재 Day 6 baseline은 repository/tool/external 결과를 모두 `UNTRUSTED`로 취급한다.

```text
REPOSITORY_CONTENT -> UNTRUSTED
TOOL_OBSERVATION   -> UNTRUSTED
EXTERNAL_CONTENT   -> UNTRUSTED
```

따라서 성공한 observation이 LLM 문맥에 남아 있으면, 그 뒤의 새 ToolIntent는 Policy에서 거부된다. 이는 간접 지시가 권한으로 세탁되는 것을 먼저 확실히 막기 위한 보수적 기준이다.

```text
파일 읽기 -> 최종 자연어 요약
  가능: 추가 Runtime tool call이 없음

파일 읽기 -> 다음 turn에 write_file / calculator / read_file
  현재는 거부: observation-derived provenance가 UNTRUSTED
```

후속 tool action을 허용하는 것은 Day 6 범위 밖이다. 이후에는 사전 승인 workflow, 제한된 read-only capability, 또는 새 직접 사용자 요청 같은 더 좁은 규칙을 실험해야 한다.

## 현재 검증

현재 Day 6에는 하나의 회귀 실험만 있다. 여러 실험 케이스 묶음은 아직 만들지 않았다.

[`src/test_observation.py`](src/test_observation.py)는 다음을 재현한다.

```text
가정한 repository 결과 + tool 결과
  -> Envelope 두 개 생성
  -> observation ID 두 개가 다음 provenance에 보존되는지 확인
  -> observation-derived write_file proposal
  -> Policy DENY
  -> Dispatcher 0회
  -> trace / evaluator 확인
```

이 테스트는 LLM API를 호출하지 않는 fixture 기반 회귀 테스트다. 현재 실행 결과는 `src/traces/trace_D6_EXP.jsonl`에 남는다. 자세한 절차는 [EXP_README.md](EXP_README.md)에 있다.

## Sandbox fixture

모든 path는 `src/sandbox/` 기준 상대 경로다. tool call에는 `sandbox/` 접두사를 쓰지 않는다.

```text
실제 파일: src/sandbox/data/safe_note.txt
tool path: data/safe_note.txt
Envelope source: data/safe_note.txt
```

`safe_note.txt`는 실제 파일 read 통합 실험을 위한 안전한 fixture다. 현재 `test_observation.py`의 간접 지시 문자열은 파일을 읽지 않고 코드 안에서 정의한 synthetic fixture다.

## 안전 범위

- 로컬 sandbox와 synthetic fixture만 사용한다.
- 실제 비밀값, 계정, 외부 MCP 서버, 외부 네트워크를 사용하지 않는다.
- 실제 destructive command, 권한 상승, 우회 동작을 실행하지 않는다.
- trace에는 observation 원문 대신 source, trust, digest 중심의 증거를 남긴다.
