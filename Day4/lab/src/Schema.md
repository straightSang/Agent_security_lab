# Day 4 schema and approval contract

This is the human-readable contract for Agent, Runtime, trace events, tool calls and approvals. When it differs from Python code, the code is authoritative.

## Boundary and ownership

```text
authenticated request
  -> Agent / LLM proposes a tool call
  -> Runtime validation
  -> ToolIntent -> PolicyDecision
  -> ApprovalStore (only when required)
  -> optional legacy authorization -> Runtime dispatcher
  -> RuntimeResult / LLM observation
```

The LLM may propose a call. It cannot grant a capability, choose trust, mint an approval ID, authenticate an actor, or bypass Runtime.

## Tool schema (LLM-facing)

`Agent.py` holds `TOOLS`, the OpenAI Responses API function definitions. `strict: true` asks the model to follow their JSON shape, but `runtime.validate_tool_call()` repeats the check because schema compliance is not authorization.

| Tool | Required arguments | Capability | Runtime operation |
|---|---|---|---|
| `calculator` | `expression: string` | `calculator.execute` | safe AST arithmetic only |
| `get_time` | none | `clock.read` | returns UTC time |
| `read_file` | `path: string` | `filesystem.read` | reads only inside sandbox |
| `write_file` | `path: string`, `content: string` | `filesystem.write` | writes only inside sandbox |
| `list_files` | `path: string` | `filesystem.list` | lists only inside sandbox |
| `run_command` | `command: string` | `command.read` | logical `pwd`, `ls`, `cat` only; no shell |

Missing, extra, or wrongly typed arguments fail validation. Path tools use relative paths such as `notes.txt` under `SANDBOX_ROOT`. The machine-readable ToolIntent input contract is in `schemas/tool-call.schema.json`.

## ToolIntent

`ToolIntent` is a normalized proposed operation; it is not permission.

```json
{
  "run_id": "run_...",
  "call_id": "call_...",
  "actor": "user-001",
  "tool_name": "write_file",
  "arguments": {"path": "report.txt", "content": "summary"},
  "provenance": {"kind": "user_task", "source": "interactive-user"},
  "capability": "filesystem.write",
  "action": "write",
  "resource": "report.txt",
  "agent_step": 2
}
```

`fingerprint()` hashes canonical JSON containing `tool_name`, `arguments`, `actor`, `capability`, `action`, and `resource`. It excludes `run_id`, `call_id`, and `agent_step`, so a retry of the same requested operation can match an approval. It is an integrity comparison value, never a password or grant.

## PolicyDecision

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

Current baseline policy denies sensitive filenames, unknown capabilities, and any tool operation authorized by untrusted repository/tool/external content. A user-controlled `filesystem.write` becomes `approval_required`; allow-listed reads and calculations are `allow`.

## ApprovalState

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

`ApprovalStore.request()` creates `apr_<UUID>`. It identifies an approval record, not an Agent ID, user ID, or DID.

| Status | Meaning | Can dispatch? |
|---|---|---:|
| `not_required` | no approval ID was required for this check | only if policy allows |
| `invalid` | supplied ID does not name a record | no |
| `pending` | record exists but nobody authorized it yet | no |
| `approved` | authorized approver accepted before expiry | eligible only when fingerprint matches |
| `rejected` | approver declined it | no |
| `expired` | TTL elapsed | no |
| `consumed` | matching grant was used once before dispatch | no further use |

```text
approval_required -> request() -> pending
pending -> approve() -> approved -> consume() -> consumed
pending -> reject() -> rejected
pending/approved -> resolve() after TTL -> expired
```

Changing actor, tool, path, content, capability, action, or resource changes the fingerprint and requires a new approval.

### Local lab flow

1. A direct user write returns `approval_required` and prints `approval_id: apr_...`.
2. In the same running `Agent_v0.3.2.py` process, type `/approve apr_...`.
3. The demo control calls `ApprovalStore.approve()` as `demo-admin`; it does not write a file yet.
4. Repeat the exact direct user request. Runtime passes the stored ID, compares the fingerprint, consumes the grant, then dispatches the write.

`demo-admin` is only a lab identity, not real authentication.

## Authenticated actor and approver

Current `actor="user-001"` is a label supplied by the lab, not authentication. In a real service, an API/backend verifies a signed session, OAuth/OIDC token, client certificate, or equivalent before the Agent is called. It derives `actor` from the verified immutable subject claim (for example `user:42`) and server-side roles. The user message, tool arguments, repository content, and LLM must never choose actor.

The approval endpoint is separately protected by a role/permission such as `approvals:write`. It calls `ApprovalStore.approve(id, approver=verified_subject)` and records that subject. Being the requesting actor does not automatically make someone an approver.

## RuntimeResult and LLM observation

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

`to_observation()` intentionally creates a smaller model-facing object. Security/audit data belongs in the trace, not in model authority.

## JSONL trace schema

Every line has this envelope:

```json
{"event_id":"evt_<UUID>","timestamp":"UTC ISO-8601","run_id":"run_...","call_id":"call_... or null","event":"event name"}
```

Every event also contains the following common keys; unknown-at-this-stage values are `null` so evaluator rows have a stable shape.

```text
agent_step, actor, tool_name, arguments, provenance, trust, capability,
action, resource, approval, approval_id, policy_decision, reason,
validation_allowed, runtime_status, end_stage, ok, error_code
```

| Event | Owner | Meaning |
|---|---|---|
| `run_start`, `model_request`, `model_response`, `agent_tool_proposal`, `provenance_transition`, `final_response`, `run_end` | AgentEventLogger | LLM-loop audit |
| `validation` | Runtime | malformed/escaping request blocked before intent |
| `tool_intent` | Runtime | normalized request |
| `policy_decision` | Runtime | allow/deny/approval-required decision |
| `approval` | Runtime | pending, approved, or consumed record used by Runtime |
| `approval_state_changed` | trusted approval control | explicit approval action |
| `runtime_result` | Runtime | final status and stop stage |

At `policy_decision`, `approval` is `null`: policy has not read or created an approval record yet. At the later `approval` event it becomes `pending`, `approved`, or `consumed`.

## Exact approval call sites

1. `runtime.Runtime.execute_tool()` gets a `PolicyDecision`.
2. On `APPROVAL_REQUIRED`, it calls `ApprovalStore.resolve(approval_id)`.
3. Without a matching approved record it calls `ApprovalStore.request()`, emits `pending`, and returns before `_dispatch()`.
4. `Agent_v0.3.2.py:approve_pending_request()` is the local demonstration that calls `ApprovalStore.approve()`.
5. On a matching retry Runtime calls `ApprovalStore.consume()` immediately before `_dispatch()`.

A chat message like `승인` changes nothing by itself. It is just model input until a trusted approval-control function calls `approve()`.
