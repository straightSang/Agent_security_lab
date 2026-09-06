"""Provenance는 지시 또는 observation이 어디서 왔는지 나타내는 메타데이터다."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .types import ProvenanceKind


@dataclass(frozen=True)
class Provenance:
    kind: ProvenanceKind
    source: str
    parent_event_id: str | None = None
    received_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind.value, "source": self.source, "parent_event_id": self.parent_event_id, "received_at": self.received_at, "attributes": self.attributes}


def direct_user_provenance(source: str = "interactive-user") -> Provenance:
    return Provenance(ProvenanceKind.USER_TASK, source)


def repository_provenance(path: str, *, parent_event_id: str | None = None) -> Provenance:
    return Provenance(ProvenanceKind.REPOSITORY_CONTENT, path, parent_event_id)


def observation_provenance(tool_name: str, *, parent_event_id: str | None = None) -> Provenance:
    return Provenance(ProvenanceKind.TOOL_OBSERVATION, tool_name, parent_event_id)


def external_provenance(url_or_service: str, *, parent_event_id: str | None = None) -> Provenance:
    return Provenance(ProvenanceKind.EXTERNAL_CONTENT, url_or_service, parent_event_id)
