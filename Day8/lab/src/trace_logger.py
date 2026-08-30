"""사건별 필드만 기록하는 추가 전용 JSONL trace."""

from __future__ import annotations

import json
import uuid
import warnings
from datetime import datetime, timezone
from enum import Enum
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterator, Mapping

from security.provenance import Provenance
from security.types import ApprovalState, AuthorizationDecision, ObservationEnvelope, PolicyDecision, RuntimeResult, ToolIntent

TRACE_BASE_FIELDS = ("event_id", "timestamp", "run_id", "event")

# 모든 사건에 같은 빈 필드를 넣지 않는다. 사건 종류별 필수 필드만 선언하여
# evaluator가 실제 기록 계약을 검사한다.
TRACE_REQUIRED_FIELDS: dict[str, tuple[str, ...]] = {
    "seed_snapshot": ("fixture_id", "seed_manifest", "seed_digest"),
    "control_plane_snapshot": (
        "fixture_id", "phase", "control_plane_digest", "control_plane_state",
    ),
    "validation": ("call_id", "tool_name", "validation_allowed"),
    "tool_intent": (
        "call_id", "actor", "tool_name", "arguments", "provenance",
        "capability", "action",
    ),
    "policy_decision": (
        "call_id", "policy_decision", "reason", "rule_id", "trust",
        "capability", "action",
    ),
    "authorization_decision": (
        "call_id", "authorization_decision", "authorization_reason",
    ),
    "approval": ("call_id", "approval", "approval_id", "required_approver"),
    "runtime_result": ("call_id", "ok", "runtime_status", "end_stage"),
    "observation_created": (
        "call_id", "observation_id", "parent_call_id", "source_kind",
        "source", "source_trust", "result_digest",
    ),
    "experiment_evidence": (
        "fixture_id", "seed_digest", "decision_digest", "result_digest",
    ),
}


def missing_required_fields(event: Mapping[str, Any]) -> tuple[str, ...]:
    """사건 종류에 필요한 필드 중 누락된 이름을 반환한다."""
    missing = [name for name in TRACE_BASE_FIELDS if name not in event]
    missing.extend(
        name
        for name in TRACE_REQUIRED_FIELDS.get(str(event.get("event")), ())
        if name not in event
    )
    return tuple(missing)


class TraceLogger:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def emit(self, event: str, run_id: str, *, call_id: str | None = None, **fields: Any) -> dict[str, Any]:
        record = {
            "event_id": f"evt_{uuid.uuid4().hex}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "run_id": run_id,
            "event": event,
        }
        if call_id is not None:
            record["call_id"] = call_id
        record.update({name: value for name, value in fields.items() if value is not None})

        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True, default=str) + "\n")
        return record

    @classmethod
    def canonicalize(cls, value: Any) -> Any:
        """set·Enum을 포함한 값을 안정적으로 정렬 가능한 JSON 값으로 바꾼다."""
        if isinstance(value, Enum):
            return value.value
        if isinstance(value, Mapping):
            return {
                str(key): cls.canonicalize(item)
                for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
            }
        if isinstance(value, (set, frozenset)):
            return sorted(cls.canonicalize(item) for item in value)
        if isinstance(value, (list, tuple)):
            return [cls.canonicalize(item) for item in value]
        return value

    @classmethod
    def digest(cls, value: Any) -> str:
        """실험 증거를 비교하기 위한 안정적인 SHA-256 digest를 만든다."""
        canonical = json.dumps(
            cls.canonicalize(value),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        return f"sha256:{sha256(canonical.encode('utf-8')).hexdigest()}"

    def record_validation(
        self,
        run_id: str,
        tool_name: str,
        call_id: str,
        provenance: Provenance,
        validation: Mapping[str, Any],
        result: RuntimeResult | None = None,
        *,
        actor: str | None = None,
        agent_step: int | None = None,
        fixture_id: str | None = None,
    ) -> None:
        fields: dict[str, Any] = {
            "fixture_id": fixture_id,
            "agent_step": agent_step,
            "actor": actor,
            "tool_name": tool_name,
            "provenance": provenance.to_dict(),
            "validation_allowed": bool(validation["allowed"]),
            "reason": validation.get("reason"),
        }
        if result is not None:
            fields.update({
                "runtime_status": result.status,
                "end_stage": result.end_stage,
                "ok": result.ok,
                "error_code": result.error_code,
            })
        self.emit("validation", run_id, call_id=call_id, **fields)

    def record_intent(self, intent: ToolIntent) -> None:
        self.emit("tool_intent", intent.run_id, call_id=intent.call_id, fixture_id=intent.fixture_id, agent_step=intent.agent_step, actor=intent.actor, tool_name=intent.tool_name, arguments=dict(intent.arguments), provenance=intent.provenance.to_dict(), capability=intent.capability.value, action=intent.action, resource=intent.resource)

    def record_policy(self, intent: ToolIntent, decision: PolicyDecision) -> None:
        self.emit("policy_decision", intent.run_id, call_id=intent.call_id, fixture_id=intent.fixture_id, agent_step=intent.agent_step, actor=intent.actor, tool_name=intent.tool_name, provenance=intent.provenance.to_dict(), **decision.trace_fields())

    def record_authorization(self, intent: ToolIntent, decision: AuthorizationDecision) -> None:
        self.emit("authorization_decision", intent.run_id, call_id=intent.call_id, fixture_id=intent.fixture_id, actor=intent.actor, tool_name=intent.tool_name, action=intent.action, resource=intent.resource, **decision.trace_fields())

    def record_approval(self, intent: ToolIntent, approval: ApprovalState) -> None:
        self.emit("approval", intent.run_id, call_id=intent.call_id, fixture_id=intent.fixture_id, actor=intent.actor, tool_name=intent.tool_name, action=intent.action, resource=intent.resource, approval=approval.status.value, approval_id=approval.approval_id, required_approver=approval.required_approver)

    def record_result(self, intent: ToolIntent, result: RuntimeResult) -> None:
        security = dict(result.security)
        result_fields = {
            "ok": result.ok,
            "runtime_status": result.status,
            "end_stage": result.end_stage,
            "error_code": result.error_code,
            **security,
        }
        self.emit("runtime_result", intent.run_id, call_id=intent.call_id, fixture_id=intent.fixture_id, actor=intent.actor, tool_name=intent.tool_name, result_digest=self.digest(result_fields), **result_fields)

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
                                   result_digest: str,
                                   control_plane_before_digest: str | None = None,
                                   control_plane_after_digest: str | None = None,
                                   control_plane_mutation: bool | None = None) -> None:
        """fixture 실행의 seed·판단·결과 digest를 마지막 JSONL 이벤트로 남긴다."""
        self.emit(
            "experiment_evidence",
            run_id,
            fixture_id=fixture_id,
            seed_digest=seed_digest,
            decision_digest=decision_digest,
            result_digest=result_digest,
            control_plane_before_digest=control_plane_before_digest,
            control_plane_after_digest=control_plane_after_digest,
            control_plane_mutation=control_plane_mutation,
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
