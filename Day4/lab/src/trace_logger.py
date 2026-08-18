"""Append-only JSONL trace with Day 4 security fields on every event."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping

from security.provenance import Provenance
from security.types import ApprovalState, PolicyDecision, RuntimeResult, ToolIntent

# These keys exist on *every* event.  An event that does not know a value yet
# records ``null`` instead of silently changing the trace shape.
TRACE_COMMON_FIELDS = (
    "agent_step",
    "actor",
    "tool_name",
    "arguments",
    "provenance",
    "trust",
    "capability",
    "action",
    "resource",
    "approval",
    "approval_id",
    "policy_decision",
    "reason",
    "validation_allowed",
    "runtime_status",
    "end_stage",
    "ok",
    "error_code",
)


class TraceLogger:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def emit(self, event: str, run_id: str, *, call_id: str | None = None, **fields: Any) -> dict[str, Any]:

        
        record = {
            "event_id": f"evt_{uuid.uuid4().hex}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "run_id": run_id,
            "call_id": call_id,
            "event": event,
            **{name: None for name in TRACE_COMMON_FIELDS},
            **fields,
        }

        with self.path.open("a", encoding="utf-8") as handle:

            handle.write(json.dumps(record, ensure_ascii=True, sort_keys=True, default=str) + "\n")
        return record

    def record_validation(self, run_id: str, tool_name: str, call_id: str, provenance: Provenance, validation: Mapping[str, Any], result: RuntimeResult, *, actor: str | None = None, agent_step: int | None = None) -> None:
        self.emit("validation", run_id, call_id=call_id, agent_step=agent_step, actor=actor, tool_name=tool_name, provenance=provenance.to_dict(), validation_allowed=validation["allowed"], reason=validation.get("reason"), runtime_status=result.status, end_stage=result.end_stage, ok=result.ok, error_code=result.error_code)

    def record_intent(self, intent: ToolIntent) -> None:
        self.emit("tool_intent", intent.run_id, call_id=intent.call_id, agent_step=intent.agent_step, actor=intent.actor, tool_name=intent.tool_name, arguments=dict(intent.arguments), provenance=intent.provenance.to_dict(), capability=intent.capability.value, action=intent.action, resource=intent.resource)

    def record_policy(self, intent: ToolIntent, decision: PolicyDecision) -> None:
        # The policy has selected an outcome, but no approval record has yet
        # been created or resolved.  ``None`` is intentionally distinct from
        # the later concrete states: pending / approved / rejected / expired.
        self.emit("policy_decision", intent.run_id, call_id=intent.call_id, agent_step=intent.agent_step, actor=intent.actor, tool_name=intent.tool_name, provenance=intent.provenance.to_dict(), approval=None, **decision.trace_fields())

    def record_approval(self, intent: ToolIntent, approval: ApprovalState) -> None:
        self.emit("approval", intent.run_id, call_id=intent.call_id, agent_step=intent.agent_step, actor=intent.actor, tool_name=intent.tool_name, provenance=intent.provenance.to_dict(), capability=intent.capability.value, action=intent.action, resource=intent.resource, approval=approval.status.value, approval_id=approval.approval_id)

    def record_result(self, intent: ToolIntent, result: RuntimeResult) -> None:
        security = dict(result.security)
        approval = security.pop("approval", "not_required")
        self.emit("runtime_result", intent.run_id, call_id=intent.call_id, agent_step=intent.agent_step, actor=intent.actor, tool_name=intent.tool_name, provenance=intent.provenance.to_dict(), approval=approval, **security, ok=result.ok, runtime_status=result.status, end_stage=result.end_stage, error_code=result.error_code)

    def iter_events(self, *, run_id: str | None = None) -> Iterator[dict[str, Any]]:

        if not self.path.exists():
            return
        
        with self.path.open(encoding="utf-8") as handle:
            for line in handle:

                line = line.strip()

                if not line:
                    continue

                event = json.loads(line)

                if run_id is None or event["run_id"] == run_id:
                    yield event
