# Day 5 실험 보고서 — Authorization Gate와 승인 후 실행

## 1. 보고서 범위

이 보고서는 Day 5 fixture suite인 `D5-E01`~`D5-E09`의 현재 결과를 기록한다.
대상은 로컬 Runtime 경계이며, LLM 강건성 벤치마크나 실제 계정·서비스·비밀값·외부
네트워크를 사용하는 실험은 아니다.

증거는 다음 명령이 만드는 JSONL trace다.

```bash
cd Day5/lab/src
python3 test_runtime.py
```

기본적으로 이벤트는 `traces/trace_D5_EXP.jsonl`에 누적된다. 독립된 실험 trace가
필요하면 `DAY5_TRACE_PATH` 환경변수를 지정한다.

## 2. 모든 fixture에 적용하는 고정 절차

| 단계 | 기록되는 이벤트 | 목적 |
|---|---|---|
| 1 | `seed_snapshot` | temporary sandbox clone을 만들고 파일 `path`, `size`, 내용 SHA-256 manifest 및 `seed_digest`를 기록한다. |
| 2 | `tool_intent` | canonical tool, actor, action, resource, provenance, capability를 기록한다. |
| 3 | `policy_decision` | 일반 정책 판단과 `decision_digest`를 기록한다. |
| 4 | `authorization_decision` | Policy를 통과한 경우 actor-resource-action 판단과 `decision_digest`를 기록한다. |
| 5 | `approval` | 승인이 필요한 경우 `pending` 또는 `consumed` 상태를 기록한다. |
| 6 | `runtime_result` | 최종 status, end stage, `result_digest`를 기록한다. |
| 7 | `experiment_evidence` | 해당 run의 seed/decision/result digest를 한 곳에 다시 기록한다. |

`E05 → E06 → E07`만 같은 in-memory approval record의 상태 전이를 검증하므로
동일 sandbox clone과 Runtime을 공유한다. 그러나 각 E는 별도 `run_id`를 사용한다.
나머지 E는 각자 새로운 clone과 Runtime을 사용한다.

## 3. fixture별 관찰 결과

현재 suite는 2026-08-24에 각 case를 한 번씩 실행했다. 모든 case에서
`print_and_assert_case()`는 `trace_completeness: true`와 `differences: []`를
출력했다. 기대값과 실제값이 다르면 assertion error로 즉시 중단된다.

| ID | 시나리오 | Policy 기대 / 실제 | AuthZ 기대 / 실제 | 최종 Runtime 결과 | 보안 해석 |
|---|---|---|---|---|---|
| D5-E01 | `user-001`이 `data/shared/sharedbook.txt` 읽기 | allow / allow | allow (`SHARED_MEMBER`) | success, `runtime` | shared member 읽기를 허용한다. |
| D5-E02 | `user-002`가 자신의 private 파일 읽기 | allow / allow | allow (`RESOURCE_OWNER`) | success, `runtime` | resource owner 읽기를 허용한다. |
| D5-E03 | `user-001`이 `user-002` private 파일 읽기 | allow / allow | deny (`ACTOR_NOT_RESOURCE_OWNER`) | forbidden, `authorization` | Policy allow만으로 ownership을 우회할 수 없다. |
| D5-E04 | repository에서 유래한 write 요청 | deny / deny | 도달하지 않음 | denied, `policy` | untrusted provenance는 approval·dispatch에 도달하지 못한다. |
| D5-E05 | owner write, 승인 전 | approval_required / approval_required | allow | approval_required, `approval`, pending ID | 승인 요청만 생성되며 Dispatcher는 호출되지 않는다. |
| D5-E06 | 승인 뒤 동일 owner write 재시도 | approval_required / approval_required | allow | success, `runtime`, consumed | 승인 뒤 재시도 한 번만 Dispatcher에 도달한다. |
| D5-E07 | consumed approval ID 재사용 | approval_required / approval_required | allow | approval_required, `approval` | replay 시 Dispatcher mock 호출 횟수는 0이다. |
| D5-E08 | shared non-member 읽기 | allow / allow | deny (`ACTOR_NOT_SHARED_MEMBER`) | forbidden, `authorization` | non-member는 approval 이전에 차단된다. |
| D5-E09 | 승인 뒤 content를 바꾼 write | approval_required / approval_required | allow | approval_required, `approval` | 변경된 content는 fingerprint를 바꾸므로 이전 ID로 dispatch할 수 없다. |

## 4. trace 읽는 방법

정상 shared read인 `D5-E01`의 흐름은 다음과 같다.

```text
seed_snapshot
→ tool_intent
→ policy_decision: allow
→ authorization_decision: allow / SHARED_MEMBER
→ runtime_result: success / end_stage=runtime
→ experiment_evidence
```

cross-user 접근인 `D5-E03`에서는 일반 read capability 자체는 허용되지만,
Authorization이 Dispatcher 이전에 실행을 끝낸다.

```text
policy_decision: allow
→ authorization_decision: deny / ACTOR_NOT_RESOURCE_OWNER
→ runtime_result: forbidden / end_stage=authorization
```

untrusted 지시인 `D5-E04`에서는 Policy가 먼저 거부하므로 authorization 및
approval 이벤트가 나타나지 않는다.

```text
policy_decision: deny / UNTRUSTED_PROVENANCE_CANNOT_AUTHORIZE_TOOL
→ runtime_result: denied / end_stage=policy
```

## 5. digest 해석

- `seed_digest`: 복제된 sandbox의 시작 파일 manifest를 식별한다.
- `decision_digest`: Policy 또는 Authorization 판단 이벤트 payload를 식별한다.
- `result_digest`: 최종 Runtime 결과 이벤트 payload를 식별한다.

이 값들은 감사용 fingerprint이지, 서로 다른 두 실행이 완전히 동일하다는 증명은
아니다. 현재 decision/result payload에는 provenance timestamp가 포함되므로, 같은
설정이라도 실행마다 digest가 달라질 수 있다. 실행 간 행동을 비교할 때는
`policy_decision`, `authorization_decision`, `runtime_status`, `end_stage`,
`reason` 같은 의미 필드를 비교하고, 시작 파일 상태 비교에는 안정적인
`seed_digest`를 사용한다.

## 6. 측정값과 한계

| 확인 항목 | 현재 suite 결과 |
|---|---|
| `trace_completeness` | D5-E01~E09 모두 true |
| expected-versus-actual diff | D5-E01~E09 모두 없음 (`[]`) |
| 위험한 Runtime success | E03, E04, E07, E08, E09에서 없음 |
| consumed ID의 두 번째 dispatch | 없음. E07 Dispatcher mock call count는 0 |
| 변경된 content의 이전 ID dispatch | 없음. E09 Dispatcher mock call count는 0 |

이 실험은 fixture 기반 single-process testbed다. actor identity와 resource registry는
test fixture이며 ApprovalStore는 메모리에 존재한다. 실제 운영에서는 인증된 session,
resource/ACL service, 영속 approval storage, 그리고 `consume()`을 위한 DB transaction
또는 atomic compare-and-set으로 대체해야 한다.

## 7. 범위 밖의 과거 자료

이전 Day4/Lab B 보고서에 있던 반복 LLM prompt-injection 결과는 현재 Day5 trace
계약으로 재실행하지 않았으므로 이 보고서의 정량 결과에 포함하지 않는다. 해당 결과를
비교하려면 현재 구조에서 다시 실행하고 별도 보고서로 기록해야 한다.
