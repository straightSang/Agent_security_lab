# DATA CONTRACT — Runtime 데이터 형식

| 필드 | 값 |
|---|---|
| 버전 | v2.0 (누적) |
| 대체 대상 | Day8 `schema.md` (311줄), Day9 `schema.md` (187줄) |
| 기준 | 코드와 다르면 Python 코드가 최종 기준이다 |

> **왜 하나로 합쳤는가.** Day별로 문서를 새로 쓰는 구조에서 Day9 `schema.md`는 Day8의
> 1~9절(Provenance·ObservationEnvelope·RuntimeResult·JSONL trace 형식)을 잃은 채
> MCP 절만 남았다. 코드는 그 자료형을 여전히 사용하는데 인터페이스 문서만 사라진 상태였다.
> 이 문서는 두 문서를 합쳐 **누적 인터페이스** 하나로 유지한다. 새 Day의 추가분은 맨 끝
> "변경 이력"에만 적고, 본문은 항상 현행 전체를 담는다.

## 문서를 읽는 세 과정

자료형을 한꺼번에 읽지 않는다. 실제 실행 → 기록 → 평가 순서로 구분한다.

## 제1장 — 실제 실험 수행에서 사용하는 자료형

| 자료형 | 생성 주체 | 받는 주체 | 역할 | 존재 이유 |
|---|---|---|---|---|
| `Provenance` | 인증·source adapter | `ToolIntent`, Policy | 요청 출처 표현 | 자연어 내용과 출처를 분리 |
| `ToolProfile` | 신뢰된 설정 | schema gate | 작업별 도구 노출 범위 | 최소권한 노출 |
| `ToolSchemaDecision` | schema gate | Runtime | 노출·인자 인터페이스 판정 | ToolIntent 이전 조기 차단 |
| `ToolIntent` | Runtime | Policy·AuthZ·Approval | 정규화된 실행 요청 | 모든 보안 단계가 같은 요청을 사용 |
| `PolicyDecision` | PolicyEngine | Runtime | 일반 정책 결론 | 요청과 permission을 분리 |
| `AuthorizationDecision` | AuthorizationEngine | Runtime | actor별 자격 결론 | Policy ALLOW와 사용자 권한 분리 |
| `ApprovalState` | ApprovalStore | Runtime | 승인 상태 | pending·approved·consumed 구분 |
| `RuntimeResult` | Runtime | Agent·test harness | 최종 성공·거부·오류 | 종료 단계와 보안 이유 전달 |

## 제2장 — 기록 수행에서 사용하는 자료형

| 자료형·사건 | 생성 주체 | 역할 | 존재 이유 |
|---|---|---|---|
| `ObservationEnvelope` | provenance helper | 결과 내용과 출처·신뢰 연결 | 다음 turn에서 provenance 유실 방지 |
| `tool_schema_decision` 사건 | TraceLogger | 노출·인자 판정 기록 | ToolIntent 전 종료도 추적 |
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
| control-plane before/after | 실험 지원 함수 | 설정 상태 전후 비교 | 정책·승인 상태 변조 확인 |
| `canary_leak` | `evaluate_run()` | inert canary의 sink 도달 여부 | 차단 실패 시 탐지된다는 증명 |

## 1. Runtime 경계

```text
LLM Tool Proposal
  -> MCP schema gate
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

## 9. 회귀 테스트 인터페이스

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
D7 회귀, D8-E03~E09가 모두 PASS했으며, 원본 `trace.jsonl`과 사람이
읽는 `summary.md`를 같은 run 디렉터리에 남겼다.

## 10. Evaluator 입력 인터페이스

`security/evaluation_contract.py/EvaluationContract`는 fixture의 분류와 예상
Policy·Authorization 결과를 검증하여 Evaluator에 전달한다. 파일 fixture는
`security/fixtures.py/IndirectPromptInjectionFixture.evaluation_contract()`가 인터페이스를
자동 생성한다. 따라서 테스트가 `unsafe_fixture=True`나 예상 결정을 중복 작성하지
않는다. JSON fixture가 없는 동적 불변조건 실험은 동일한 인터페이스 객체를 명시적으로
생성한다.

```text
fixture JSON -> loader 검증 -> EvaluationContract -> evaluate_run(trace, contract=...)
```

이 인터페이스는 평가용 정답표이므로 Runtime·Policy에는 전달하지 않는다.

---

## 10. MCP tool schema 인터페이스

### ToolProfile

`security/tool_schema.py`는 작업별 도구 노출 범위를 선언한다. profile은 **신뢰된 설정**이며
모델이나 관측값이 바꿀 수 없다.

| profile | 노출 도구 | 용도 |
|---|---|---|
| `read_only` | calculator, get_time, read_file, list_files | 기본값. 쓰기와 일반 명령 미노출 |
| `write_enabled` | read_only + write_file | 쓰기 실험에서 명시적으로 선택 |
| `legacy_compat` | write_enabled + run_command | 이전 흐름 회귀에서만 |

운영 환경에서는 OAuth token scope가 profile을 정해야 한다. 현재 랩은 이 단계를 test harness
actor/profile로 대체하므로, **검증 가능한 것은 tool-level 최소권한과 Runtime 결속이며**
token 발급·검증·PKCE·resource metadata는 범위 밖이다.

### MCP tool definition

```text
name / description / inputSchema / annotations / _meta
```

`annotations`(`readOnlyHint`, `destructiveHint` 등)는 **표시용 힌트일 뿐 보안 판단에 쓰지 않는다.**
서버가 신뢰하는 것은 `_meta["lab/capability"]`와 자체 catalog뿐이다.
`tools_for_mcp()`는 깊은 복사를 반환하므로, 호출자가 광고본의 description이나 annotation을
바꿔도 Runtime이 신뢰하는 원본 catalog는 변하지 않는다.

### ToolSchemaDecision

```text
allowed / reason / profile / tool_name / declared_capability / schema_digest / detail
```

`reason`은 안정적인 규칙 식별자다. `detail`은 사람이 읽는 세부 사유이며 권한 판단에 쓰이지 않는다.

| reason | 의미 |
|---|---|
| `TOOL_NOT_EXPOSED_IN_PROFILE` | 이 profile에 없는 도구 이름 |
| `MCP_ARGUMENTS_MUST_BE_OBJECT` | 인자가 객체가 아님 |
| `MCP_REQUIRED_ARGUMENT_MISSING` | 필수 인자 누락 (`detail`에 누락 목록) |
| `MCP_ADDITIONAL_ARGUMENT_DENIED` | 선언되지 않은 인자 추가 |
| `MCP_ARGUMENT_TYPE_MISMATCH` | 인자 타입 불일치 |
| `MCP_ARGUMENT_TOO_LONG` | `maxLength` 초과 |
| `MCP_PATH_OUTSIDE_PROFILE_SCOPE` | 절대 경로 또는 `..` 포함 |
| `MCP_ARGUMENT_PATTERN_MISMATCH` | 구조적으로 안전하지 않은 경로 문자열 |
| `MCP_TOOL_SCHEMA_ALLOWED` | 통과 |

### 계층별 역할 분리 (중요)

이 절이 이번 개정의 핵심이다. 세 계층이 같은 질문에 답하지 않는다.

| 계층 | 답하는 질문 | 답하지 않는 질문 |
|---|---|---|
| MCP schema gate | 이 도구를 노출했는가, **인자 인터페이스를 지켰는가**, 경로가 구조적으로 안전한가 | 어느 범위까지 허용되는가 · 이 문자열이 실제로 무엇을 가리키는가 |
| Runtime validation | 이 문자열을 **뒷단계가 쓸 수 있는 실체로 바꿀 수 있는가** | 인자 인터페이스 · 도구 노출 여부 · 범위 |
| `permission.POLICY` | 이 도구가 이 범위에 접근해도 되는가 | 누가 요청했는가 |
| `AuthorizationEngine` | 이 actor가 이 리소스의 소유자·멤버인가 | 범위 규칙 자체 |

### schema gate와 validation의 분리

두 단계는 겹쳐 보이지만 **판정 근거가 다르다.**

| | schema gate | validation |
|---|---|---|
| 판정 근거 | 모델에게 광고한 인터페이스(`inputSchema`) | 실제 파일시스템의 사실 |
| 파일시스템 | 만지지 않는다 | `resolve()`로 만진다 |
| 산출물 | 통과/거부뿐 | `resolved_path`, `command_base` **생성** |
| 전담 검사 | 도구 노출 통제, 길이 제한 | 심볼릭 링크 탈출, 셸 명령 분해 |

심볼릭 링크가 이 분리의 근거다. sandbox 안의 링크가 밖을 가리키면 문자열에는
`..`도 절대 경로도 없어 schema gate는 통과시키고, `resolve()`를 하는 validation만
잡는다. 반대로 미노출 도구와 길이 초과는 validation이 볼 수 없다.

validation은 **인자 인터페이스를 검사하지 않는다.** 선언되지 않은 인자가 들어와도
통과시킨다. 인터페이스 위반을 거부하는 것은 schema gate 하나의 책임이다. 다만 자기
일을 할 수 없으면 거부한다 — 경로를 정규화하려면 문자열 경로가 있어야 하므로,
없거나 타입이 다르면 `PATH_ARGUMENT_UNUSABLE`로 거부한다. **'인터페이스 위반'과 '이
단계가 쓸 수 없는 값'은 다른 사유이며 trace에서 구별된다.**

`tests/test_layer_separation.py`가 이 분리를 회귀로 지킨다.

이전 버전에서는 schema 정규식이 범위까지 결정해 `POLICY`의 여러 분기가 도달 불가 상태였다.
`tests/test_policy_reachability.py`가 이 회귀를 막는다.

## 11. 변경 이력

| 버전 | 변경 |
|---|---|
| v1.0 (Day 8) | Runtime 경계, ToolIntent, Provenance, ObservationEnvelope, RuntimeResult, 복수 observation, Policy/AuthZ/Approval, JSONL trace 형식 확립 |
| v1.1 (Day 9) | MCP tool schema, ToolProfile, ToolSchemaDecision 추가 |
| v2.1 | `ARGUMENT_SPEC` 제거. 인자 인터페이스 검사를 schema gate로 단일화하고 validation은 문자열→실체 변환만 담당. 도구 목록의 단일 기준을 MCP catalog로 통일(`KNOWN_TOOLS`) |
| v2.0 | Day8 1~9절 복원 통합 · schema/POLICY/AuthZ 역할 분리 명시 · `ToolSchemaDecision.detail` 추가 · `EvaluationResult.canary_leak` 추가 · trace 기본 출력을 임시 디렉터리로 이동 |
