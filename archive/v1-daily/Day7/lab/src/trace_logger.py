"""모든 이벤트에 Day 4 보안 필드를 갖는 추가 전용 JSONL trace."""

from __future__ import annotations

import json
import uuid
import warnings
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterator, Mapping

from security.provenance import Provenance
from security.types import ApprovalState, AuthorizationDecision, ObservationEnvelope, PolicyDecision, RuntimeResult, ToolIntent

# 이 키들은 모든 이벤트에 존재한다. 아직 값을 알 수 없는 이벤트는 trace 모양을
# 바꾸지 않고 null을 기록한다.
TRACE_COMMON_FIELDS = (
    "agent_step",
    "fixture_id",
    "actor",
    "tool_name",
    "arguments",
    "provenance",
    "trust",
    "capability",
    "requested_capability",
    "action",
    "resource",
    "approval",
    "approval_id",
    "policy_decision",
    "authorization_decision",
    "authorization_reason",
    "required_approver",
    "reason",
    "rule_id",
    "validation_allowed",
    "runtime_status",
    "end_stage",
    "ok",
    "error_code",
    "observation_id",
    "parent_call_id",
    "source_kind",
    "source",
    "source_trust",
    "result_digest",
    "seed_digest",
    "decision_digest",
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

    @staticmethod
    def digest(value: Any) -> str:
        """실험 증거를 비교하기 위한 안정적인 SHA-256 digest를 만든다."""
        canonical = json.dumps(value, ensure_ascii=True, sort_keys=True, default=str)
        return f"sha256:{sha256(canonical.encode('utf-8')).hexdigest()}"

    def record_validation(self, run_id: str, tool_name: str, call_id: str, provenance: Provenance, validation: Mapping[str, Any], result: RuntimeResult, *, actor: str | None = None, agent_step: int | None = None, fixture_id: str | None = None) -> None:
        self.emit("validation", run_id, call_id=call_id, fixture_id=fixture_id, agent_step=agent_step, actor=actor, tool_name=tool_name, provenance=provenance.to_dict(), validation_allowed=validation["allowed"], reason=validation.get("reason"), runtime_status=result.status, end_stage=result.end_stage, ok=result.ok, error_code=result.error_code)

    def record_intent(self, intent: ToolIntent) -> None:
        self.emit("tool_intent", intent.run_id, call_id=intent.call_id, fixture_id=intent.fixture_id, agent_step=intent.agent_step, actor=intent.actor, tool_name=intent.tool_name, arguments=dict(intent.arguments), provenance=intent.provenance.to_dict(), capability=intent.capability.value, requested_capability=intent.capability.value, action=intent.action, resource=intent.resource)

    def record_policy(self, intent: ToolIntent, decision: PolicyDecision) -> None:
        # Policy는 결론을 냈지만 아직 approval record를 만들거나 조회하지 않았다.
        # 따라서 None 은 이후의 pending / approved / rejected / expired와
        # 의도적으로 구별된다.
        self.emit("policy_decision", intent.run_id, call_id=intent.call_id, fixture_id=intent.fixture_id, agent_step=intent.agent_step, actor=intent.actor, tool_name=intent.tool_name, provenance=intent.provenance.to_dict(), requested_capability=intent.capability.value, approval=None, **decision.trace_fields())

    def record_authorization(self, intent: ToolIntent, decision: AuthorizationDecision) -> None:
        self.emit("authorization_decision", intent.run_id, call_id=intent.call_id, fixture_id=intent.fixture_id, agent_step=intent.agent_step, actor=intent.actor, tool_name=intent.tool_name, provenance=intent.provenance.to_dict(), capability=intent.capability.value, requested_capability=intent.capability.value, action=intent.action, resource=intent.resource, **decision.trace_fields())

    def record_approval(self, intent: ToolIntent, approval: ApprovalState) -> None:
        self.emit("approval", intent.run_id, call_id=intent.call_id, fixture_id=intent.fixture_id, agent_step=intent.agent_step, actor=intent.actor, tool_name=intent.tool_name, provenance=intent.provenance.to_dict(), capability=intent.capability.value, requested_capability=intent.capability.value, action=intent.action, resource=intent.resource, approval=approval.status.value, approval_id=approval.approval_id, required_approver=approval.required_approver)

    def record_result(self, intent: ToolIntent, result: RuntimeResult) -> None:
        security = dict(result.security)
        approval = security.pop("approval", "not_required")
        result_fields = {
            "ok": result.ok,
            "runtime_status": result.status,
            "end_stage": result.end_stage,
            "error_code": result.error_code,
            "approval": approval,
            **security,
        }
        self.emit("runtime_result", intent.run_id, call_id=intent.call_id, fixture_id=intent.fixture_id, agent_step=intent.agent_step, actor=intent.actor, tool_name=intent.tool_name, provenance=intent.provenance.to_dict(), requested_capability=intent.capability.value, result_digest=self.digest(result_fields), **result_fields)

    def record_observation(self, run_id: str, envelope: ObservationEnvelope, *, fixture_id: str | None = None) -> None:

        self.emit(
            "observation_created",
            run_id,
            call_id=envelope.parent_call_id,
            fixture_id=fixture_id,
            observation_id=envelope.observation_id,
            parent_call_id=envelope.parent_call_id,
            source_kind=envelope.source_kind.value,
            source=envelope.source,
            source_trust=envelope.trust.value,
            result_digest=envelope.result_digest,
        )

    def record_experiment_evidence(self, run_id: str, *, fixture_id: str,
                                   seed_digest: str, decision_digest: str,
                                   result_digest: str) -> None:
        """fixture 실행의 seed·판단·결과 digest를 마지막 JSONL 이벤트로 남긴다."""
        self.emit(
            "experiment_evidence",
            run_id,
            fixture_id=fixture_id,
            seed_digest=seed_digest,
            decision_digest=decision_digest,
            result_digest=result_digest,
        )


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
