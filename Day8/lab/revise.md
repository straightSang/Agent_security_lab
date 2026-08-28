# Day 8 문서 변경 기록 — Guardrail·Policy 분리

## 전체 실행 과정 · 함수 호출표

| 순서 | 호출 (`파일명/함수명`) | 입력 → 출력 | Day 8 역할 |
|---:|---|---|---|
| 1 | `security/fixtures.py/load_indirect_prompt_injection_fixture` | JSON → fixture data | 실험 입력 검증, 권한 부여 없음 |
| 2 | `runtime.py/validate_tool_call` | proposal → canonical arguments | 비신뢰 요청 형식 검증 |
| 3 | `security/capability.py/describe_intent` | validated call → capability/action/resource | capability를 Runtime 코드가 계산 |
| 4 | `security/types.py/ToolIntent` | 실행 후보 값 → 요청 계약 | permission이 아닌 정책 입력 |
| 5 | `security/policy.py/PolicyEngine.evaluate` | ToolIntent → PolicyDecision | outcome/reason/rule_id 독립 계산 |
| 6 | `security/authorization.py/AuthorizationEngine.authorize` | Policy 통과 intent → AuthorizationDecision | actor-resource-action 판단 |
| 7 | `security/approval.py/ApprovalStore` | 승인 필요 intent → 상태 | 승인 record 확인·전이 |
| 8 | `runtime.py/Runtime._dispatch` | 모든 gate 통과 intent → result | 유일한 실제 실행 지점 |
| 9 | `trace_logger.py/TraceLogger.record_*` | 판단·상태·결과 → JSONL | 같은 run의 감사 증거 |
| 10 | `security/evaluator.py/evaluate_run` | trace → metrics | safety·utility·completeness 평가 |

## 변경 목표

```text
untrusted text != Policy rule
ToolIntent != PolicyDecision
Policy ALLOW != Authorization ALLOW
approve() != execute()
DENY != dispatch
```

Day 8은 새로운 Guardrail 엔진을 만드는 날이 아니다. 현재 Runtime 전체가 Guardrail이며, Policy가 독립된 판단 단계로 항상 호출되고 그 결과가 강제되는지 검증한다.

## 문서별 변경

| 파일 | Day 8 변경 |
|---|---|
| `README.md` | Guardrail과 Policy의 관계, Day 8 흐름, D8-E01~E06 |
| `EXP_README.md` | Policy mutation·spoofing·역할 분리 실험과 측정 기준 |
| `ThreatModel0.5.md` | control-plane 변조·Policy bypass 위협과 불변조건 |
| `src/permission_policy.md` | Policy가 독립 control-plane이라는 규칙 |
| `src/schema.md` | ToolIntent/PolicyDecision 계약과 trace 필드 |
| `results/D7_EXPERIMENT_REPORT.md` | Day 7 회귀 증거임을 명시 |

## Day 7에서 유지한 것

- `benign_email.json`, `injected_email.json` fixture
- ObservationEnvelope와 provenance 전파
- `fixture_id`, `rule_id`, seed/decision/result digest
- Dispatcher mock과 evaluator
- Validation → Policy → Authorization → Approval → Dispatcher 순서

Day 7의 구현 내역과 PASS 결과는 [results/D7_EXPERIMENT_REPORT.md](results/D7_EXPERIMENT_REPORT.md)에 보존한다. Day 8 본문에는 필요한 회귀 조건만 남긴다.

## Day 8 추가·수정 예정

| 영역 | 변경 |
|---|---|
| Policy contract | 모든 PolicyDecision의 stable reason/rule_id 확인 |
| mutation fixture | trust·allow rule 변경 주장을 포함한 synthetic data 추가 |
| spoofing fixture | admin actor·가짜 approval ID 주장을 포함한 synthetic data 추가 |
| state evidence | Policy/permission, actor, capability mapping, ApprovalStore 전후 비교 |
| regression test | D8-E01~E06 assertion과 evaluator 실행 |
| report | 기대/실제 결과와 한계 기록 |

현재 이 파일은 문서 기준 변경을 기록한다. 위 항목은 코드와 테스트를 반영하고 실제 실행한 뒤에만 “구현 완료”와 “PASS”로 변경한다.

## Trace 변경 기준

| 필드/event | 목적 | 권한 판단 영향 |
|---|---|---|
| `rule_id` | 적용 정책의 안정적 식별 | 없음, 감사용 |
| `requested_capability` | 요청 capability 명시 | 없음, 계산 결과 기록 |
| `control_plane_digest` | 설정 변조 여부 비교 | 없음, 증거용 |
| `seed_digest` | 시작 sandbox 비교 | 없음 |
| `decision_digest` | Policy 결정 집합 비교 | 없음 |
| `result_digest` | Runtime 결과 비교 | 없음 |

## 호환성과 보존할 불변조건

- 기존 Agent/API 호출 형태를 불필요하게 바꾸지 않는다.
- `fixture_id`, `rule_id`, digest는 권한 토큰이 아니다.
- ToolIntent fingerprint에 실험 라벨을 넣지 않는다.
- Policy DENY는 approval ID를 만들지 않는다.
- Policy 통과 후에도 Authorization과 Approval을 생략하지 않는다.
- 모든 위험 fixture의 Dispatcher 호출은 0회여야 한다.

## 검증 상태

```text
Day 7 regression: 기존 보고서의 PASS를 기준으로 보존
Day 8 D8-E01~E06: 아직 실행 전
```

코드·fixture·test가 추가된 뒤 동일 seed replay와 evaluator 결과를 이 문서 또는 별도 Day 8 결과 보고서에 기록한다.

## 알려진 한계

- 현재 strict provenance Policy는 정상 multi-step workflow를 과도하게 차단할 수 있다.
- local fixture는 실제 MCP/email connector가 아니다.
- in-memory policy/approval 상태는 운영 환경의 영속화·동시성 통제를 대체하지 않는다.
- Dispatcher 단일 경계는 OS/container sandbox를 대체하지 않는다.
