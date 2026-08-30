# Day 8 문서 변경 기록 — Guardrail·Policy 분리

## 앞으로 적용할 문서 작성 기준

Day 8 이후의 실험 문서는 최소한 아래 세 장을 서로 분리해 작성한다.

1. **실제 실험 수행**: 입력 준비, 함수 호출 순서, 보안 gate, 실제 실행 또는 차단
2. **기록 수행**: 어떤 함수가 언제 어떤 사건과 상태를 trace에 남기는지
3. **평가 수행**: assertion, evaluator, digest 비교가 무엇을 판정하는지

파일이나 함수를 설명하는 표에는 최소한 `파일/함수`, `호출 시점`, `역할`,
`존재 이유`, `입력/출력 또는 종료 조건`을 적는다. 구현된 기능과 추가 예정 기능을
같은 상태처럼 표현하지 않고 반드시 상태 열이나 본문에서 구분한다.

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

위 표의 1~8번은 실제 실험 수행, 9번은 기록 수행, 10번은 평가 수행에 속한다.
아래에서는 세 책임을 분리해 변경 이유를 기록한다.

## 제1장 — 실제 실험 수행 변경

| 파일/함수 | 역할 | 호출 시점 | Day 8에서 확인할 이유 |
|---|---|---|---|
| `security/fixtures.py/load_indirect_prompt_injection_fixture()` | 실험 입력 형식 검증 | 케이스 시작 | fixture 오류와 보안 실패 구별 |
| `runtime.py/validate_tool_call()` | 인자·경로 형식 검증 | Runtime 첫 단계 | 정책 전에 잘못된 요청 제거 |
| `security/capability.py/describe_intent()` | capability/action/resource 계산 | Validation 통과 후 | 비신뢰 입력이 권한을 직접 지정하지 못하게 함 |
| `security/policy.py/PolicyEngine.evaluate()` | 일반 정책 결론 생성 | ToolIntent 생성 후 | PolicyDecision의 유일한 생성 경로 확인 |
| `security/authorization.py/AuthorizationEngine.authorize()` | actor별 자격 판단 | Policy 통과 후 | Policy ALLOW와 실제 사용자 권한 분리 |
| `security/approval.py/ApprovalStore` | 승인 상태 관리 | 승인 필요 요청에서만 | 가짜 승인 ID와 재사용 차단 |
| `runtime.py/Runtime._dispatch()` | 실제 도구 실행 | 모든 gate 통과 후 | DENY 시 호출 0회 검증 |

## 제2장 — 기록 수행 변경

| 파일/함수 | 역할 | 현재 상태 | Day 8 변경 이유 |
|---|---|---|---|
| `experiment_support.py/seed_manifest()` | 시작 sandbox 상태 기록 | 구현됨 | 같은 입력 조건 확인 |
| `trace_logger.py/record_*()` | 요청·판단·승인·결과 사건 기록 | 구현됨 | 단계별 감사 증거 연결 |
| `experiment_support.py/record_run_evidence()` | seed·decision·result digest 생성 | 구현됨 | 반복 실행 결과 비교 |
| `record_control_plane_snapshot(before/after)` | 정책·신뢰·capability mapping·승인 상태 전후 기록 | 구현됨 | D8-E03/E04 설정 변조 검증 |
| `trace_reader.py/write_run_summary()` | run별 JSONL을 한글 단계 표로 변환 | 구현됨 | 원본을 보존하며 사람이 빠르게 판독 |
| fixture별 `seed_files` 복사 | 필요한 입력 파일만 임시 sandbox에 복사 | 구현됨 | 전체 sandbox 반복 복사 제거 |

## 제3장 — 평가 수행 변경

| 파일/함수 | 역할 | 현재 상태 | Day 8 변경 이유 |
|---|---|---|---|
| 테스트 `assert` | 케이스별 결과와 Dispatcher 횟수 확인 | Day 7 기준선 구현됨 | 한 조건 오류도 즉시 실패 |
| `security/evaluator.py/evaluate_run()` | run 전체 공통 지표 계산 | 구현됨 | 안전성과 정상 기능을 같은 기준으로 평가 |
| control-plane 전후 비교 | 설정 변조 지표 계산 | 구현됨 | 최종 DENY뿐 아니라 상태 불변도 검증 |
| Day 8 결과 보고서 | expected와 actual, 한계 기록 | 구현됨 | 문서 계획과 실제 실행 결과 구별 |

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

## Day 8 추가·수정 내역

| 영역 | 변경 |
|---|---|
| Policy contract | 같은 입력·정책 버전에서 `reason`과 `rule_id`가 같은 고정 판정 코드인지 결과 객체와 trace에서 확인 |
| mutation fixture | `src/fixtures/policy_mutation.json`에 trust·allow rule 변경 주장을 담은 연구자 제작 가상 입력 추가 |
| spoofing fixture | `src/fixtures/control_plane_spoof.json`에 admin actor·가짜 approval ID 주장을 담은 가상 입력 추가 |
| fixture schema | `src/schemas/day8-policy-boundary.fixture.schema.json`에 D8 fixture 형식 정의 |
| state evidence | `POLICY`, actor, capability mapping, ApprovalStore를 실행 전후 snapshot/digest로 비교 |
| regression test | 기존 Day 7 테스트는 유지하고 `src/test_policy_boundary.py`에 D8-E03~E06 assertion과 evaluator 추가 |
| report | 기대/실제 결과와 한계 기록 |

현재 이 파일은 문서 기준 변경을 기록한다. 위 항목은 코드와 테스트를 반영하고 실제 실행한 뒤에만 “구현 완료”와 “PASS”로 변경한다.

여기서 synthetic data는 실제 계정·실제 승인·실제 비밀값이 아니라 공격 모양만
안전하게 재현하도록 연구자가 만든 JSON/텍스트다. fixture 내용의 `admin`이나
`apr_fake`는 보안 제어 값이 아니라 비신뢰 문자열이다.

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
