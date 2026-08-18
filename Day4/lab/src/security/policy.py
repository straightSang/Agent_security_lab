"""Policy engine: returns a decision, never invokes a tool."""

from __future__ import annotations

from typing import Any, Callable

from .trust import label_trust
from .types import Capability, Decision, PolicyDecision, ToolIntent, TrustLabel

_SENSITIVE_NAMES = {".env", "credentials", "credential", "secret", "secrets", "id_rsa", "token", "tokens", "password", "passwords"}


class PolicyEngine:
    """Small auditable Day 4 baseline policy.

    Replace rules here as experiments evolve; runtime dispatch must not grow its
    own policy exceptions.
    """

    def evaluate(self, intent: ToolIntent) -> PolicyDecision:

        trust = label_trust(intent.provenance)

        resource_parts = set((intent.resource or "").lower().replace("\\", "/").split("/"))

        if any(part in _SENSITIVE_NAMES or part.startswith(("credential", "secret", "token", "password")) for part in resource_parts):
            return self._decision(Decision.DENY, "SENSITIVE_RESOURCE_DENIED", intent, trust)

        if intent.capability is Capability.UNKNOWN:
            return self._decision(Decision.DENY, "CAPABILITY_NOT_ALLOWLISTED", intent, trust)

        # Indirect content is data, not delegated authority. A later experiment
        # can add narrowly-scoped transformations without changing runtime.
        if trust is TrustLabel.UNTRUSTED:
            return self._decision(Decision.DENY, "UNTRUSTED_PROVENANCE_CANNOT_AUTHORIZE_TOOL", intent, trust)

        if intent.capability is Capability.FILESYSTEM_WRITE:
            return self._decision(Decision.APPROVAL_REQUIRED, "WRITE_REQUIRES_EXPLICIT_APPROVAL", intent, trust)

        return self._decision(Decision.ALLOW, "BASELINE_CAPABILITY_ALLOWED", intent, trust)

    @staticmethod
    def _decision(outcome: Decision, reason: str, intent: ToolIntent, trust: TrustLabel) -> PolicyDecision:
        return PolicyDecision(outcome, reason, intent.capability, intent.action, intent.resource, trust)


def adapt_legacy_authorizer(authorize: Callable[..., Any], policy: Any) -> Callable[[ToolIntent], tuple[bool, str | None]]:
    """Bridge old ``authorization.authorize`` during a gradual migration.

    v0.2.2 variants used different positional signatures.  Keep that ambiguity
    isolated here, test the adapter against the local legacy function, then
    retire it once equivalent policy rules live in ``PolicyEngine``.
    """
    def check(intent: ToolIntent) -> tuple[bool, str | None]:
        try:
            raw = authorize(intent.tool_name, dict(intent.arguments), policy)

        except TypeError:
            raw = authorize(intent.tool_name, dict(intent.arguments))

        if isinstance(raw, dict):
            return bool(raw.get("allowed")), raw.get("reason")

        return bool(raw), None if raw else "legacy authorization denied"

    return check

