"""모든 이벤트에 Day 4 보안 필드를 갖는 추가 전용 JSONL trace."""

from __future__ import annotations

import json
import uuid
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping

from security.provenance import Provenance
from security.types import ApprovalState, AuthorizationDecision, PolicyDecision, RuntimeResult, ToolIntent

# 이 키들은 모든 이벤트에 존재한다. 아직 값을 알 수 없는 이벤트는 trace 모양을
# 바꾸지 않고 null을 기록한다.
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
    "authorization_decision",
    "authorization_reason",
    "required_approver",
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
        # Policy는 결론을 냈지만 아직 approval record를 만들거나 조회하지 않았다.
        # 따라서 None 은 이후의 pending / approved / rejected / expired와
        # 의도적으로 구별된다.
        self.emit("policy_decision", intent.run_id, call_id=intent.call_id, agent_step=intent.agent_step, actor=intent.actor, tool_name=intent.tool_name, provenance=intent.provenance.to_dict(), approval=None, **decision.trace_fields())

    def record_authorization(self, intent: ToolIntent, decision: AuthorizationDecision) -> None:
        self.emit("authorization_decision", intent.run_id, call_id=intent.call_id, agent_step=intent.agent_step, actor=intent.actor, tool_name=intent.tool_name, provenance=intent.provenance.to_dict(), capability=intent.capability.value, action=intent.action, resource=intent.resource, **decision.trace_fields())

    def record_approval(self, intent: ToolIntent, approval: ApprovalState) -> None:
        self.emit("approval", intent.run_id, call_id=intent.call_id, agent_step=intent.agent_step, actor=intent.actor, tool_name=intent.tool_name, provenance=intent.provenance.to_dict(), capability=intent.capability.value, action=intent.action, resource=intent.resource, approval=approval.status.value, approval_id=approval.approval_id, required_approver=approval.required_approver)

    def record_result(self, intent: ToolIntent, result: RuntimeResult) -> None:
        security = dict(result.security)
        approval = security.pop("approval", "not_required")
        self.emit("runtime_result", intent.run_id, call_id=intent.call_id, agent_step=intent.agent_step, actor=intent.actor, tool_name=intent.tool_name, provenance=intent.provenance.to_dict(), approval=approval, **security, ok=result.ok, runtime_status=result.status, end_stage=result.end_stage, error_code=result.error_code)

    def iter_events(self, *, run_id: str | None = None, strict: bool = False) -> Iterator[dict[str, Any]]:
        """trace 이벤트를 순회한다.

        JSONL 이벤트가 아닌 과거 주석 줄은 기본값에서 warning과 함께 건너뛴다.
        감사 작업에서는 ``strict=True``로 호출해 첫 비JSON 줄에서 즉시 실패시킨다.
        """

        if not self.path.exists():
            return
        comment_lines = 0
        malformed_lines = 0
        with self.path.open(encoding="utf-8") as handle:
            for line in handle:

                line = line.strip()

                if not line:
                    continue

                if line.startswith("//"):
                    if strict:
                        raise ValueError(f"JSONL trace에 주석 줄이 있습니다: {self.path}")
                    comment_lines += 1
                    continue

                try:
                    event = json.loads(line.lstrip("\ufeff"))
                except json.JSONDecodeError as exc:
                    if strict:
                        raise ValueError(f"malformed JSONL trace: {self.path}") from exc
                    malformed_lines += 1
                    continue

                if run_id is None or event["run_id"] == run_id:
                    yield event
        warnings_to_report = []
        if comment_lines:
            warnings_to_report.append(f"JSONL 이벤트가 아닌 주석 {comment_lines}줄")
        if malformed_lines:
            warnings_to_report.append(f"파싱할 수 없는 JSON {malformed_lines}줄")
        if warnings_to_report:
            warnings.warn(
                f"{self.path}에서 {', '.join(warnings_to_report)}을 건너뛰었습니다. "
                "실험 설명은 EXP_LOG.md에 두고, 감사 시에는 strict=True로 다시 확인하세요.",
                RuntimeWarning,
                stacklevel=2,
            )
