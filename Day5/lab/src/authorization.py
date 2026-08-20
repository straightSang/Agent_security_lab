"""Day 5 fixture Authorization engine.

This module is deliberately a local stand-in for a resource database/ACL
service.  It accepts only a validated, canonical ``ToolIntent`` from Runtime;
it never accepts actor identity from LLM tool arguments.
"""

from __future__ import annotations

from dataclasses import dataclass

from security.types import (
    AuthorizationDecision,
    AuthorizationOutcome,
    ToolIntent,
)


SHARED_MEMBERS = frozenset({"user-001", "user-003"})
SHARED_APPROVER = "reviewer-001"
KNOWN_ACTORS = frozenset({"user-001", "user-002", "user-003", SHARED_APPROVER})


@dataclass(frozen=True)
class ResourceMetadata:
    """Fixture resource registry result, not a production database model."""

    kind: str
    owner: str | None = None
    members: frozenset[str] = frozenset()


def resolve_resource(resource: str | None) -> ResourceMetadata:
    """Resolve a canonical sandbox path to small Day 5 ownership metadata."""
    normalized = (resource or "").replace("\\", "/").strip("/")
    if normalized.startswith("data/shared/"):
        return ResourceMetadata("shared", members=SHARED_MEMBERS)
    if normalized.startswith("data/"):
        parts = normalized.split("/")
        if len(parts) >= 3 and parts[1].startswith("user-"):
            return ResourceMetadata("private", owner=parts[1])
    if normalized in {"", ".", "notes.txt"}:
        return ResourceMetadata("public_read")
    return ResourceMetadata("unregistered")


class AuthorizationEngine:
    """Authorize validated actor/resource/action combinations for the Lab.

    Private owner writes and shared member writes are authorized *to request*
    a write, but both return a required approver.  Policy then makes the
    operation ``APPROVAL_REQUIRED``; Runtime creates no approval record unless
    this method returns ALLOW.
    """

    def authorize(self, intent: ToolIntent) -> AuthorizationDecision:
        if intent.actor not in KNOWN_ACTORS:
            return self._deny(intent, "UNKNOWN_ACTOR")
        if intent.actor == SHARED_APPROVER:
            return self._deny(intent, "REVIEWER_HAS_NO_TOOL_ACCESS")

        metadata = resolve_resource(intent.resource)
        if metadata.kind == "public_read":
            if intent.action in {"read", "list", "pwd", "calculate"}:
                return self._allow(intent, "PUBLIC_READ_RESOURCE")
            return self._deny(intent, "PUBLIC_RESOURCE_WRITE_NOT_AUTHORIZED")

        if metadata.kind == "private":
            if metadata.owner != intent.actor:
                return self._deny(intent, "ACTOR_NOT_RESOURCE_OWNER")
            if intent.action == "write":
                # Requirement 4: the resource owner must explicitly approve
                # their own write request before it can be dispatched.
                return self._allow(intent, "RESOURCE_OWNER_SELF_APPROVAL_REQUIRED", required_approver=intent.actor)
            return self._allow(intent, "RESOURCE_OWNER")

        if metadata.kind == "shared":
            if intent.actor not in metadata.members:
                return self._deny(intent, "ACTOR_NOT_SHARED_MEMBER")
            if intent.action == "write":
                # A shared folder has no single owner.  The Lab therefore uses
                # a designated reviewer; production would use a team ACL.
                return self._allow(intent, "SHARED_WRITE_REQUIRES_REVIEWER", required_approver=SHARED_APPROVER)
            return self._allow(intent, "SHARED_MEMBER")

        return self._deny(intent, "RESOURCE_NOT_REGISTERED")

    @staticmethod
    def _allow(intent: ToolIntent, reason: str, *, required_approver: str | None = None) -> AuthorizationDecision:
        return AuthorizationDecision(AuthorizationOutcome.ALLOW, reason, intent.actor, intent.action, intent.resource, required_approver)

    @staticmethod
    def _deny(intent: ToolIntent, reason: str) -> AuthorizationDecision:
        return AuthorizationDecision(AuthorizationOutcome.DENY, reason, intent.actor, intent.action, intent.resource)
