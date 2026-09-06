# Day 6 변경 기록 — Observation Provenance

## 현재 상태

Day 6은 Day 5 Runtime 경계 위에 ObservationEnvelope와 provenance 전이 기록을 추가했다. 현재 구현된 검증은 하나의 fixture 기반 회귀 테스트다.

```text
synthetic observation 두 개
-> 다음 ToolIntent provenance에 두 observation ID 보존
-> observation-derived write_file
-> Policy DENY
-> Dispatcher 0회
```

이 검증은 `src/test_observation.py`가 수행하며, 결과 trace는 `src/traces/trace_D6_EXP.jsonl`에 남는다.

## 파일별 변경

| 파일 | Day 6 역할 또는 변경 |
|---|---|
| `src/security/types.py` | `ObservationEnvelope` 형식 추가 |
| `src/security/provenance.py` | `make_observation()`, `provenance_for_observations()` 추가 |
| `src/security/trust.py` | `ProvenanceKind`를 입력으로 trust label 계산; 순환 import 제거 |
| `src/security/policy.py` | provenance kind에서 계산한 trust로 Policy 판단 |
| `src/trace_logger.py` | `observation_created` 이벤트와 observation trace 필드 추가 |
| `src/security/evaluator.py` | observation policy bypass, metadata tamper 지표 추가 |
| `src/Agent_v0.5.py` | Runtime 성공 결과에서 Envelope 생성, 다음 turn provenance 전이 |
| `src/test_observation.py` | 복수 observation provenance와 Dispatcher 0회 회귀 테스트 |
| `src/sandbox/data/safe_note.txt` | 실제 read 통합 실험을 위한 안전 fixture |
| `README.md` | Day 6 개념·strict baseline·현재 구현 설명 |
| `EXP_README.md` | 현재 단일 회귀 실험의 절차와 기대 결과 |
| `ThreatModel0.5.md` | 단일/복수 observation 위협 모델 |
| `src/schema.md` | Runtime·provenance·Envelope·trace 데이터 형식 |

## 확인한 결과

```text
test_observation.py
-> PASS
-> observation ID 두 개 보존
-> Policy DENY
-> Dispatcher 0회
-> trace completeness true

기존 Day 5 test_runtime.py
-> PASS
```

## 현재 한계

- `test_observation.py`는 실제 LLM API를 호출하지 않는다.
- 첫 두 tool 결과는 코드에 작성한 synthetic fixture다.
- strict baseline에서는 observation 뒤의 모든 후속 tool action을 차단한다.
- 실제 파일 결과를 읽고 다음 Agent turn까지 전파하는 통합 실험은 아직 별도로 만들지 않았다.
- sandbox seed reset, seed digest, decision digest를 자동으로 만드는 실험 보조 코드는 아직 Day 6에 없다.

## 다음 확장 후보

- `data/safe_note.txt`를 실제로 읽는 통합 fixture
- `data/injected_note.txt`를 사용하는 실제 file-result fixture
- Agent API loop를 mock한 다중 turn 테스트
- 사전 승인 workflow 또는 read-only capability를 통한 제한적 후속 tool 허용 연구
