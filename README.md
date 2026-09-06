# AI Agent Security Lab

LLM 에이전트에서 **비신뢰 입력이 권한 있는 행동으로 변환되는 경로**를 증명하고 측정하고 완화하기 위한 로컬 격리 연구 하니스.

모든 실험은 로컬 컨테이너/임시 sandbox, mock 도구, 합성 데이터, inert canary로만 수행한다.
외부 시스템 대상 테스트, 실제 자격 증명, 운영 계정은 범위 밖이며 코드에도 존재하지 않는다.

---

## 30초 요약

에이전트가 도구를 실행하려면 **여섯 단계를 순서대로 모두** 통과해야 한다. 어느 하나라도 거부하면
실행 경계(`Runtime._dispatch()`)에 도달하지 못한다.

```text
LLM tool proposal
   │
   ├─ 1. MCP schema gate       어떤 도구를 노출했고, 인자 계약을 지켰는가
   ├─ 2. Runtime validation    정규화된 경로가 sandbox 안인가
   ├─ 3. Policy                trust, 민감 리소스, capability, 범위 규칙
   ├─ 4. Authorization         이 actor가 이 리소스의 소유자나 멤버인가
   ├─ 5. Approval              위험 행동에 유효한 1회용 승인이 있는가
   │
   └─ 6. Dispatch              유일한 실행 지점
              │
              └─ Trace (append-only JSONL) → Evaluator (ASR/BTC/OBR/PRR)
```

핵심 원칙 세 가지.

1. **모델의 자연어 출력은 의도나 사실이나 권한을 증명하지 않는다.** 제안은 요청일 뿐이다.
2. **권한은 명시적 capability로 분해한다.** "에이전트가 할 수 있다"는 권한 모델이 아니다.
3. **관측 가능성이 없는 보안 주장은 완료되지 않은 것으로 간주한다.** 모든 판정은 trace에 남는다.

---

## 재현

```bash
pip install -r requirements.txt
pytest                     # 단위 검사 14건
```

**주의 — `pytest` 하나로는 전부 돌지 않는다.** 회귀 스위트 7종 중 3종만 `test_`로 시작하는
함수를 가지고 있고, 나머지 4종(D7~D9 실험 스위트)은 모듈 최상위에서 바로 실행되는 형태다.
pytest는 그 4종을 import하면서 사실상 실행하지만 통과 건수로 세지 않는다. 전부 확인하려면
아래처럼 직접 실행한다.

```bash
for f in tests/test_*.py; do python3 "$f" || echo "FAIL $f"; done
```

| 파일 | pytest 수집 | 직접 실행 |
|---|---:|---|
| `test_policy_reachability.py` | 5건 | 가능 |
| `test_layer_separation.py` | 5건 | 가능 |
| `test_public_api_contract.py` | 4건 | 가능 |
| `test_mcp_tool_schema.py` | 0건 | 가능 (`main()`) |
| `test_indirect_injection.py` | 0건 | 가능 (모듈 최상위 실행) |
| `test_policy_boundary.py` | 0건 | 가능 (모듈 최상위 실행) |
| `test_security_invariants.py` | 0건 | 가능 (모듈 최상위 실행) |

이 불일치는 알려진 결함이며 함수 이름을 `test_`로 정리해 해소할 예정이다.

### 증거 승격

trace 기본 출력은 저장소가 아니라 임시 디렉터리다(`src/lab_paths.py`의 `trace_root()`).
보고서에 인용할 run만 `LAB_TRACE_ROOT`로 출력 위치를 지정해 `evidence/` 아래에 남긴다.

```bash
LAB_TRACE_ROOT=evidence/EXP-W1D1-01 python3 tests/test_mcp_tool_schema.py
```

승격한 run은 그날의 `docs/notes/DayNN_*.md`에서 Experiment ID로 참조한다.

### 환경 기록

Python 3.10 이상(`.python-version`은 3.12.8). 실험 노트에는 아래 두 값을 반드시 남긴다.
그래야 나중에 "이 표가 어느 코드에서 나왔는가"에 답할 수 있다.

```bash
python3 --version          # 예: Python 3.12.8
git rev-parse --short HEAD # 예: 166b00c
```

---

## 공개 계약

이 저장소를 코드로 쓰는 방법은 세 개뿐이다. `agent.__all__`이 그 전부다.

| 이름 | 역할 |
|---|---|
| `execute_tool()` | 도구 제안 하나를 여섯 관문으로 보낸다 |
| `build_runtime()` | 격리된 Runtime 하나를 만든다 |
| `run_agent_loop()` | 모델을 실제 실행 루프에 넣는다 (W1 D4에서 사용) |

그 밖의 이름은 내부 구현이며, 필요한 것은 원래 정의된 모듈에서 직접 가져간다.
`tests/test_public_api_contract.py`가 이 상태를 회귀로 고정한다 — 아무도 쓰지 않는
이름을 공개하면 테스트가 실패한다.

**왜 3개인가.** 이 저장소는 "도구가 실행되는 지점은 `_dispatch()` 하나뿐"이라고
주장한다. 그 주장을 검증하려는 사람은 공개 진입점을 전부 확인해야 하므로, 그 수가
곧 감사 비용이다. 근거는 [`docs/RFC-001_public_api.html`](docs/RFC-001_public_api.html) 참조.

## 저장소 구조

| 경로 | 내용 |
|---|---|
| `src/` | 하니스 단일 소스 트리. Day별 사본 없음 |
| `src/security/` | 보안 도메인 — types, trust, permission, capability, policy, authorization, approval, provenance, tool_schema, evaluator |
| `src/runtime.py` | 유일한 실행 경계. 여섯 단계 순서를 강제한다 |
| `src/agent.py` | 진입점. `execute_tool()`과 model-in-the-loop `run_agent_loop()` |
| `tests/` | 회귀 스위트 7종 |
| `fixtures/` 와 `schemas/` | 실험 입력과 그 계약 |
| `sandbox/` | 합성 데이터와 inert canary. 실제 비밀 없음 |
| `docs/` | 위협 모델, 권한 정책, 데이터 계약, 커리큘럼, 변경 이력 |
| `docs/notes/` | **일자별 연구 노트.** 하루에 하나씩 추가된다 |
| `evidence/` | 보고서가 인용하는 승격된 run만 |
| `archive/v1-daily/` | Day 1~9 원본 폴더. 읽기 전용 보존 |

---

## 저장소 이력

| 태그 | 구조 | 시점 |
|---|---|---|
| `v1.0` | Day1 ~ Day9 폴더가 최상위. 매일 전날을 복사 | Day 9 종료 |
| `v2.0` | 단일 트리. Day 폴더는 `archive/v1-daily/`로 이동 | 개편 후 |

`v1.0` 구조를 그대로 보려면 `git checkout v1.0`. 파일 517개가 내용 동일하게
보존되어 있으므로 아카이브에서도 같은 것을 볼 수 있다.

**Day 번호는 계속 이어진다.** 버전 번호는 코드 구조가 바뀔 때만 올라가고, Day는
연구를 하루 더 한 날마다 늘어난다. 두 숫자는 서로 다른 것을 센다.

---

## 진행 경과와 커리큘럼 대응

| Day | 주제 | 커리큘럼 | 핵심 산출물 |
|---:|---|---|---|
| 1 | Agent loop, 상태 모델 | W1 D1 | 제안과 실행의 분리 |
| 2 | 구조화 logger, trace 계약 | W1 D2 | JSONL 이벤트 스키마 |
| 3 | Filesystem capability 정책 | W1 D3 | 경로 정규화, sandbox 결속 |
| 4 | 입력과 도구 스키마 검증 | W1 D4 | 선언형 `POLICY`, capability 매핑 |
| 5 | Authorization gate, 승인 | W1 D5 | actor-resource 소유권, 1회용 승인 |
| 6 | Observation provenance | W2 D1 | `ObservationEnvelope`, trust 재라벨링 |
| 7 | Indirect prompt injection | W2 D2 | 비신뢰 유래 제안 차단 (D7-E01~E02) |
| 8 | Guardrail, 정책 분리 | W2 D3 | control-plane 불변 검증 (D8-E01~E06) |
| 9 | MCP tool schema, least privilege | W2 D4 | 노출 프로필 3종, schema gate (D9-E01~E09) |

각 날의 가설, 실험, 관측, 반례는 [`docs/notes/`](docs/notes/)에 하루 한 파일로 기록한다.
양식은 [`docs/notes/_TEMPLATE.md`](docs/notes/_TEMPLATE.md)이며, 노트마다 그날 마지막
커밋 해시를 적어 문서와 코드가 서로를 가리키게 한다.

이후 12주 계획은 [`docs/CURRICULUM_12W.md`](docs/CURRICULUM_12W.md)에 있다.

---

## 이번 개정에서 바뀐 것

평가 보고서(`RPT-2026-001`)의 지적을 반영해 Day별 폴더 복사 구조를 단일 트리로 통합하고
32개 항목 중 코드, 문서, 재현성 항목을 처리했다. 항목별 대응은 [`docs/CHANGELOG.md`](docs/CHANGELOG.md) 참조.

가장 중요한 변경 세 가지.

- **경로 인가의 단일 기준화.** 이전에는 schema 정규식, `POLICY` 범위, 소유권 판정이 같은 질문에
  답하면서 서로 어긋났고, 그 결과 `POLICY`의 여러 분기가 어떤 호출로도 도달할 수 없었다.
  이제 schema는 구조적 안전성만, `POLICY`는 범위만, Authorization은 소유권만 판정한다.
  `tests/test_policy_reachability.py`가 도달 불가 분기를 회귀로 막는다.
- **model-in-the-loop 경로 신설.** `run_agent_loop()`가 모델의 tool call을 실제로 받아
  `execute_tool()`로 되돌린다. 이전까지 모든 제안은 사람이 fixture에 적어 넣은 것이었다.
- **증거와 테스트 산출물의 분리.** trace 기본 출력이 임시 디렉터리로 바뀌어, 회귀를 자주
  돌려도 증거 디렉터리가 오염되지 않는다.

---

## 현재 한계

이 저장소가 **아직 말할 수 없는 것**들이다. 할 수 있는 것보다 이쪽이 중요하므로 명시한다.

**1. 모델이 실제로 속는지는 아직 재보지 않았다**

지금까지 확인한 것은 "위험한 도구 호출이 들어오면 정책 엔진이 막는다"까지다.
"AI 모델이 injection 문장을 읽고 실제로 그런 호출을 하게 되는가"는 측정 전이다.
모델을 붙이는 통로(`run_agent_loop()`)는 만들었지만 숫자가 없다. 12주 계획 W1 D4에서 잰다.

**2. 샌드박스 자체가 뚫리는 경우는 다루지 않는다**

파일 경로를 검사해 sandbox 밖으로 나가지 못하게 막는다. 그러나 운영체제나 가상화 계층의
취약점을 이용해 빠져나가는 공격은 범위 밖이다. 그래서 "샌드박스가 안전하다"고 말하지 않고,
**"정해 둔 정책이 실제로 지켜진다"**까지만 주장한다.

**3. 승인 저장소는 프로그램 하나만 돌 때를 전제한다**

같은 승인이 두 번 쓰이지 못하게 막는 장치가 있지만, 프로그램 하나 안에서만 보장된다.
서버 여러 대가 동시에 도는 환경이라면 데이터베이스 수준의 장치로 바꿔야 한다.

**4. MCP 스키마 검사는 필요한 만큼만 만들었다**

JSON Schema 규격 전체가 아니라 실험에 쓰는 부분(필수 인자, 타입, 길이, 패턴)만 구현했다.
실제 MCP 서버와 완전히 호환된다고 주장하지 않는다.

**5. 기록 자체를 위조하는 공격은 아직 실험하지 않았다**

이 저장소는 모든 판정을 trace에 남기고, 그 trace를 근거로 "막혔다"를 증명한다.
그런데 **trace를 조작하는 공격은 다루지 않았다.** 기록을 믿고 다른 것을 검증하면서
정작 기록은 검증하지 않은 셈이다. 남아 있는 논리적 구멍이며 앞으로 메울 대상이다.

---

## 안전 규칙

- 실계정, 실비밀, 실서비스 사용 금지. 외부 네트워크 기본 거부.
- 공격 문자열은 합성 fixture와 inert canary만 사용한다.
- 권한 상승, 우회, 파괴 동작을 실환경에서 재현하지 않는다.
- 발견은 책임 있는 보고 절차로 이동한다.
