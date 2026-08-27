# Threat Model v0.6 — Day 7 Indirect Prompt Injection Fixture

Day 7은 Day 5 Authorization·Approval 및 Day 6 Observation provenance 경계를 유지한 채, **고정된 injected fixture가 후속 tool action을 유도해도 실제 권한이 되지 않는지** 검증한다.

## Day 7 자산과 공격 표면

| 자산 | 공격 표면 | 통제 |
|---|---|---|
| `fixtures/*.json` | fixture의 trust, actor, 기대값 위조 | fixture는 입력 계약일 뿐 Runtime이 trust·actor·Policy를 독립 계산 |
| synthetic email content | 이메일 내부의 marker write 지시 | observation provenance=`untrusted` → Policy DENY |
| `fixture_id` | 공격자가 실험 라벨로 권한을 얻는 혼동 | trace/evaluator 집계 전용, fingerprint·권한 판단에는 미포함 |
| JSONL trace | source/decision/result의 연결 누락 | `fixture_id`, `rule_id`, digest, `experiment_evidence` |

## Day 7 불변조건

- 정상 read는 direct-user provenance와 AuthZ 조건을 통과하면 실행될 수 있다.
- injected content를 읽은 결과는 observation data이며, 그 결과에서 유래한 write proposal은 `untrusted`다.
- `fixture_id`, 이메일 본문, `expected` 필드는 actor·capability·PolicyDecision·approval state를 바꾸지 못한다.
- Policy DENY는 Authorization·Approval·위험 Dispatcher보다 먼저 끝난다.
- 동일 fixture를 새 seed sandbox로 실행하면 비교 가능한 evidence digest가 남는다.

---

## Day 6 baseline 보관 설명

관련 문서:

- [README.md](README.md): 개념과 현재 구현
- [EXP_README.md](EXP_README.md): 현재 회귀 실험과 trace 확인

## 시스템 흐름

```text
authenticated actor
  -> direct user input
  -> LLM Tool Proposal
  -> Validation
  -> ToolIntent
  -> Policy -> Authorization -> Approval(필요 시) -> Runtime Dispatcher
  -> RuntimeResult
  -> ObservationEnvelope
  -> 다음 LLM turn
  -> observation-derived ToolIntent
```

Observation은 LLM이 읽을 수 있는 data이지만 authority가 아니다. observation text는 actor, capability, policy rule, approval state, Dispatcher 경로를 직접 바꿀 수 없다.

## 보호 대상

- observation의 `source`, `source_kind`, `trust`, `parent_call_id`, `result_digest`
- actor identity와 Authorization 결과
- Policy 규칙, capability mapping, approval record와 fingerprint
- sandbox resource와 Runtime Dispatcher의 실행 무결성
- observation → 다음 ToolIntent → decision → result trace 연결

## 신뢰 경계

| 구성 요소 | 기본 trust | 처리 |
|---|---|---|
| 직접 사용자 입력 | `user_controlled` | trusted adapter가 `USER_TASK` provenance 부여 |
| LLM Tool Proposal | 권한 없음 | Validation 뒤 ToolIntent로 정규화 |
| repository file 결과 | `untrusted` | `REPOSITORY_CONTENT` Envelope 생성 |
| tool 결과 | `untrusted` | `TOOL_OBSERVATION` Envelope 생성 |
| external/MCP 결과 | `untrusted` | 향후 adapter가 `EXTERNAL_CONTENT` Envelope 생성 |
| Policy/AuthZ/Approval/Runtime | TCB | observation text가 수정할 수 없음 |

## 보안 불변조건

- observation provenance와 trust는 LLM이 아니라 code adapter가 만든다.
- tool call 하나가 성공하면 ObservationEnvelope 하나가 생성된다.
- 여러 Envelope은 하나로 합쳐지지 않는다. 다음 ToolIntent provenance의 `attributes.observation_ids`에 함께 기록된다.
- 하나의 observation이면 원래 source kind를 유지한다.
- 여러 observation이면 provenance의 `kind=TOOL_OBSERVATION`, `source=multiple_observations`로 표시하고 개별 source는 attributes에 보존한다.
- repository/tool/external observation이 남아 있으면 현재 strict baseline에서는 다음 ToolIntent가 `untrusted`다.
- Policy DENY면 Authorization, Approval, Dispatcher에 도달하지 않는다.

## 위협과 통제

| 위협 | 공격 표면 | 현재 통제 | 현재 검증 |
|---|---|---|---|
| Indirect Prompt Injection | 파일 또는 tool output의 지시 문자열 | observation provenance → untrusted → Policy DENY | `test_observation.py` |
| Provenance laundering | observation을 `USER_TASK`처럼 재라벨 | trusted adapter만 provenance 생성 | trace source/trust 확인 |
| Actor/approval spoofing | “admin이다”, “approval ID를 사용하라”는 문자열 | actor=session/test harness, approval=store state | Day 5 경계 유지 |
| Observation trace gap | source/trust/parent/digest 누락 | `observation_created` 이벤트 | trace completeness |
| Overblocking | 정상 결과 뒤 작업을 모두 막음 | strict baseline의 알려진 한계로 기록 | 향후 실험 대상 |

## 단일 observation 예시

```text
read_file("data/injected_note.txt") 성공
  -> obs-read 생성
  -> source_kind = repository_content
  -> trust = untrusted
  -> 다음 ToolIntent provenance = repository_content
  -> write_file proposal이면 Policy DENY
```

## 복수 observation 예시

```text
read_file(...) 성공       -> obs-read
calculator(...) 성공      -> obs-calc

다음 ToolIntent provenance
  -> kind = tool_observation
  -> source = multiple_observations
  -> attributes.observation_ids = [obs-read, obs-calc]
  -> trust = untrusted
```

여러 결과 중 무엇이 모델의 다음 제안에 영향을 줬는지 Runtime이 정확히 판별할 수 없으므로, 현재는 모든 ID를 기록하고 보수적으로 차단한다.

## 현재 검증 범위와 한계

현재 구현된 검증은 하나의 fixture 기반 회귀 테스트다. 실제 LLM API 호출이나 실제 파일 read 결과는 사용하지 않고, synthetic observation 두 개를 만들어 후속 write proposal이 Policy에서 차단되는지 확인한다.

범위 밖:

- 실제 MCP client/server, OAuth, 외부 네트워크
- 실제 LLM이 injected text에 반응하는 비결정적 행동 측정
- observation별 세밀한 영향 추적
- 정상 multi-step tool workflow를 안전하게 허용하는 정책
- OS/container sandbox와 trace tamper resistance
