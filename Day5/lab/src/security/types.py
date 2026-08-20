"""제안·정책·승인·Runtime 사이의 명시적 계약."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from hashlib import sha256
import json
from typing import Any, Mapping


class ProvenanceKind(str, Enum):
    USER_TASK = "user_task"
    REPOSITORY_CONTENT = "repository_content"
    TOOL_OBSERVATION = "tool_observation"
    EXTERNAL_CONTENT = "external_content"
    SYSTEM = "system"


class TrustLabel(str, Enum):
    TRUSTED = "trusted"
    USER_CONTROLLED = "user_controlled"
    UNTRUSTED = "untrusted"


class Capability(str, Enum):
    CALCULATOR_EXECUTE = "calculator.execute"
    CLOCK_READ = "clock.read"
    FILESYSTEM_READ = "filesystem.read"
    FILESYSTEM_WRITE = "filesystem.write"
    FILESYSTEM_LIST = "filesystem.list"
    COMMAND_READ = "command.read"
    UNKNOWN = "unknown"


class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    APPROVAL_REQUIRED = "approval_required"


class AuthorizationOutcome(str, Enum):
    """Actor와 특정 resource의 관계에 대한 Day 5 결론."""

    ALLOW = "allow"
    DENY = "deny"


class ApprovalStatus(str, Enum):
    NOT_REQUIRED = "not_required"
    INVALID = "invalid"
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    CONSUMED = "consumed"


@dataclass(frozen=True)
class ToolIntent:
    """제안된 작업이며, 실행 권한 자체는 아니다."""
    run_id: str
    call_id: str
    actor: str
    tool_name: str
    arguments: Mapping[str, Any]
    provenance: Any
    capability: Capability
    action: str
    resource: str | None
    # Agent는 이 값을 알지만, Runtime 직접 테스트는 값을 모를 수 있다.
    # 감사 메타데이터일 뿐 승인 fingerprint에는 의도적으로 넣지 않는다.
    agent_step: int | None = None

    def fingerprint(self) -> str:
        material = {"tool_name": self.tool_name, "arguments": self.arguments, "actor": self.actor, "capability": self.capability.value, "action": self.action, "resource": self.resource}
        return sha256(json.dumps(material, sort_keys=True, default=str).encode()).hexdigest()


@dataclass(frozen=True)
class PolicyDecision:
    outcome: Decision
    reason: str
    capability: Capability
    action: str
    resource: str | None
    trust: TrustLabel

    def trace_fields(self) -> dict[str, Any]:
        return {"policy_decision": self.outcome.value, "reason": self.reason, "capability": self.capability.value, "action": self.action, "resource": self.resource, "trust": self.trust.value}


@dataclass(frozen=True)
class ApprovalState:
    approval_id: str | None
    status: ApprovalStatus
    intent_fingerprint: str | None = None
    requested_at: str | None = None
    expires_at: str | None = None
    approver: str | None = None
    requested_actor: str | None = None
    required_approver: str | None = None
    resource: str | None = None
    action: str | None = None


@dataclass(frozen=True)
class AuthorizationDecision:
    """Policy 결과와 분리된 actor-resource-action 인가 계약."""

    outcome: AuthorizationOutcome
    reason: str
    actor: str
    action: str
    resource: str | None
    required_approver: str | None = None

    def trace_fields(self) -> dict[str, Any]:
        return {
            "authorization_decision": self.outcome.value,
            "authorization_reason": self.reason,
            "required_approver": self.required_approver,
        }


@dataclass
class RuntimeResult:
    ok: bool
    status: str
    end_stage: str
    tool_name: str
    call_id: str
    data: Any = None
    error_code: str | None = None
    error_message: str | None = None
    security: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def success(cls, tool_name: str, call_id: str, data: Any, *, security: dict[str, Any] | None = None) -> "RuntimeResult":
        return cls(True, "success", "runtime", tool_name, call_id, data=data, security=security or {})

    @classmethod
    def failure(cls, status: str, end_stage: str, tool_name: str, call_id: str, error_code: str, error_message: str, *, security: dict[str, Any] | None = None) -> "RuntimeResult":
        return cls(False, status, end_stage, tool_name, call_id, error_code=error_code, error_message=error_message, security=security or {})

    def to_dict(self) -> dict[str, Any]:
        meta = {"tool_name": self.tool_name, "call_id": self.call_id, **self.security}
        return {"ok": self.ok, "status": self.status, "end_stage": self.end_stage, "data": self.data, "error": None if self.ok else {"code": self.error_code, "message": self.error_message}, "meta": meta}
