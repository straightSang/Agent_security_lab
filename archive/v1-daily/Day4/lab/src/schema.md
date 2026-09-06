# Day 4 스키마와 승인 계약

이 문서는 Agent, Runtime, trace 이벤트, 도구 호출, 승인 상태의 사람이 읽는 계약이다. 코드와 다르면 Python 코드가 최종 기준이다.

## 1. 경계와 책임

```text
인증된 요청
  -> Agent / LLM의 도구 호출 제안
  -> Runtime Validation
  -> ToolIntent -> PolicyDecision
  -> ApprovalStore (필요한 경우에만)
  -> 선택적 legacy authorization -> Runtime Dispatcher
  -> RuntimeResult / LLM Observation
```

LLM은 호출을 *제안*할 수만 있다. capability를 부여하거나, trust를 정하거나, approval ID를 발급하거나, actor를 인증하거나, Runtime을 우회할 수 없다.

## 2. 도구 스키마 (LLM에 제공)

`Agent.py`의 `TOOLS`는 OpenAI Responses API용 function tool 정의다. `strict: true`는 모델이 JSON 모양을 따르게 하지만, 스키마 준수는 authorization이 아니므로 `runtime.validate_tool_call()`이 검사를 다시 한다.

| 도구 | 필수 인자 | Capability | Runtime 동작 |
|---|---|---|---|
| `calculator` | `expression: string` | `calculator.execute` | 안전한 AST 산술만 계산 |
| `get_time` | 없음 | `clock.read` | UTC 시간 반환 |
| `read_file` | `path: string` | `filesystem.read` | sandbox 내부만 읽기 |
| `write_file` | `path: string`, `content: string` | `filesystem.write` | sandbox 내부만 쓰기 |
| `list_files` | `path: string` | `filesystem.list` | sandbox 내부만 나열 |
| `run_command` | `command: string` | `command.read` | shell 없이 논리적 `pwd`, `ls`, `cat`만 |

누락·추가·잘못된 타입의 인자는 validation에서 거부된다. 경로 도구는 `SANDBOX_ROOT` 기준 상대 경로를 쓴다. 즉 `notes.txt`는 맞지만 `sandbox/notes.txt`는 아니다. 기계가 읽는 ToolIntent 입력 계약은 `schemas/tool-call.schema.json`에 있다.

## 3. ToolIntent

`ToolIntent`는 정규화된 작업 제안이며 permission 자체가 아니다.

```json
{
  "run_id": "run_...",
  "call_id": "call_...",
  "actor": "user-001",
  "tool_name": "write_file",
  "arguments": {"path": "output.txt", "content": "summary"},
  "provenance": {"kind": "user_task", "source": "interactive-user"},
  "capability": "filesystem.write",
  "action": "write",
  "resource": "output.txt",
  "agent_step": 2
}
```

`fingerprint()`는 `tool_name`, `arguments`, `actor`, `capability`, `action`, `resource`의 canonical JSON을 hash한다. `run_id`, `call_id`, `agent_step`은 제외하므로 정확히 같은 작업의 재시도는 승인과 일치할 수 있다. fingerprint는 비교용 무결성 값이지 비밀번호나 권한 토큰이 아니다.

## 4. PolicyDecision

```json
{
  "policy_decision": "allow | deny | approval_required",
  "reason": "BASELINE_CAPABILITY_ALLOWED",
  "capability": "filesystem.read",
  "action": "read",
  "resource": "notes.txt",
  "trust": "user_controlled"
}
```

기본 정책은 민감 파일명, unknown capability, repository/tool/external 콘텐츠에서 유래한 도구 실행 권한을 거부한다. **untrusted provenance는 approval 단계 이전에 무조건 `deny`된다. approval ID가 있어도 되살릴 수 없다.**

직접 사용자 유래 요청은 다음 범위에서만 평가된다.

- `read_file`: root file(`notes.txt`) 또는 `data/...`
- `list_files`: sandbox root(`.`) 또는 `data/...`
- `write_file`: root file(`output.txt`)만 가능하며 `approval_required`
- `write_file("data/out.txt")`와 다른 하위 디렉터리 쓰기: 승인 여부와 관계없이 `deny`

실행 설정표는 `security/permission.py`, 설명 문서는 `permission_policy.md`에 있다.

## 5. ApprovalState

```json
{
  "approval_id": "apr_<UUID>",
  "status": "pending",
  "intent_fingerprint": "sha256 hex string",
  "requested_at": "UTC ISO-8601 timestamp",
  "expires_at": "UTC ISO-8601 timestamp",
  "approver": null
}
```

`ApprovalStore.request()`가 `apr_<UUID>`를 만든다. 이것은 Agent ID, 사용자 ID, DID가 아니라 승인 record의 식별자다.

| 상태 | 의미 | Dispatcher 도달 가능? |
|---|---|---:|
| `not_required` | 이 검사에 approval ID가 필요 없었음 | Policy가 allow인 경우만 |
| `invalid` | 제공된 ID에 record가 없음 | 아니오 |
| `pending` | record는 있으나 권한 있는 승인자가 아직 결정하지 않음 | 아니오 |
| `approved` | 승인자가 만료 전 승인함 | fingerprint가 같을 때만 후보 |
| `rejected` | 승인자가 거절함 | 아니오 |
| `expired` | TTL이 지남 | 아니오 |
| `consumed` | 일치한 grant가 dispatch 전에 한 번 소비됨 | 재사용 불가 |

```text
approval_required -> request() -> pending
pending -> approve() -> approved -> consume() -> consumed
pending -> reject() -> rejected
pending/approved -> resolve() 후 TTL 만료 -> expired
```

actor, 도구, path, content, capability, action, resource 중 하나라도 바뀌면 fingerprint가 바뀌므로 새 승인이 필요하다.

### 로컬 실험 흐름

1. 직접 사용자 쓰기 요청은 `approval_required`와 `approval_id: apr_...`를 반환한다.
2. 같은 `Agent_v0.3.2.py` 프로세스에서 `/approve apr_...`를 입력한다.
3. 데모 control이 `demo-admin`으로 `ApprovalStore.approve()`를 호출한다. 이 시점에는 파일을 쓰지 않는다.
4. 정확히 같은 직접 사용자 요청을 반복한다. Runtime이 ID와 fingerprint를 비교하고 grant를 소비한 뒤 dispatch한다.

`demo-admin`은 실험용 이름이지 실제 인증이 아니다.

## 6. 인증된 actor와 approver

현재의 `actor="user-001"`은 lab label일 뿐 인증이 아니다. 실제 서비스에서는 API/backend가 Agent 호출 전에 서명된 session, OAuth/OIDC token, client certificate 등을 검증한다. 그 뒤 검증된 immutable subject claim(예: `user:42`)과 서버 측 role에서 actor를 정한다. 사용자 메시지, 도구 인자, repository 콘텐츠, LLM은 actor를 정하면 안 된다.

승인 endpoint도 `approvals:write` 같은 별도 permission으로 보호한다. endpoint가 `ApprovalStore.approve(id, approver=verified_subject)`를 호출하고 그 주체를 기록한다. 요청 actor라고 해서 자동으로 approver가 되는 것은 아니다.

## 7. RuntimeResult와 LLM Observation

```json
{
  "ok": false,
  "status": "approval_required",
  "end_stage": "approval",
  "data": null,
  "error": {"code": "APPROVAL_REQUIRED", "message": "WRITE_REQUIRES_EXPLICIT_APPROVAL"},
  "meta": {
    "tool_name": "write_file",
    "call_id": "call_...",
    "policy_decision": "approval_required",
    "approval": "pending",
    "approval_id": "apr_..."
  }
}
```

`to_observation()`은 의도적으로 더 작은 LLM 전달용 객체를 만든다. 보안·감사 데이터는 모델 권한이 아니라 trace에 둔다.

## 8. JSONL trace 스키마

각 줄은 JSON 이벤트 하나이며 다음 envelope를 가진다.

```json
{"event_id":"evt_<UUID>","timestamp":"UTC ISO-8601","run_id":"run_...","call_id":"call_... 또는 null","event":"이벤트 이름"}
```

아래 공통 키는 모든 이벤트에 존재한다. 해당 단계에서 아직 모르는 값은 `null`이라 evaluator가 안정적인 형태의 row를 읽을 수 있다.

```text
agent_step, actor, tool_name, arguments, provenance, trust, capability,
action, resource, approval, approval_id, policy_decision, reason,
validation_allowed, runtime_status, end_stage, ok, error_code
```

| 이벤트 | 기록 주체 | 의미 |
|---|---|---|
| `run_start`, `model_request`, `model_response`, `agent_tool_proposal`, `provenance_transition`, `final_response`, `run_end` | AgentEventLogger | LLM loop 감사 |
| `validation` | Runtime | intent 생성 전의 malformed/escape 요청 차단 |
| `tool_intent` | Runtime | 정규화된 요청 |
| `policy_decision` | Runtime | allow/deny/approval-required 결정 |
| `approval` | Runtime | Runtime이 확인한 pending/approved/consumed record |
| `approval_state_changed` | trusted approval control | 명시적 승인 action |
| `runtime_result` | Runtime | 최종 상태와 중단 단계 |

`policy_decision` 이벤트의 `approval`은 `null`이다. 아직 approval record를 만들거나 읽지 않았기 때문이다. 이후 `approval` 이벤트에서 `pending`, `approved`, `consumed`가 된다.

## 9. Approval 호출 위치

1. `runtime.Runtime.execute_tool()`이 `PolicyDecision`을 얻는다.
2. `APPROVAL_REQUIRED`일 때만 `ApprovalStore.resolve(approval_id)`를 호출한다.
3. 일치하는 approved record가 없으면 `ApprovalStore.request()`를 호출하고, pending을 기록한 뒤 `_dispatch()` 전에 반환한다.
4. `Agent_v0.3.2.py:approve_pending_request()`는 `ApprovalStore.approve()`를 호출하는 로컬 데모다.
5. 일치하는 재시도에서만 Runtime이 `_dispatch()` 직전에 `ApprovalStore.consume()`을 호출한다.

파일·웹·도구 출력 유래 명령은 1번의 Policy에서 `deny`되므로 2~5번으로 가지 않는다. 채팅에 `승인`이라고 쓰는 것은 trusted control이 `approve()`를 호출하기 전까지 단순한 모델 입력일 뿐이다.
