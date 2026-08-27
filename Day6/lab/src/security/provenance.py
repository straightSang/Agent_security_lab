"""Provenance와 Day 6 observation provenance 생성 함수.

관측값의 content는 LLM에 data로 전달할 수 있지만, source/trust/observation ID는
이 모듈과 Runtime이 만든 메타데이터다. 모델 출력으로 덮어쓰지 않는다.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any, Sequence
from uuid import uuid4

from .trust import label_trust
from .types import ObservationEnvelope, ProvenanceKind


@dataclass(frozen=True)
class Provenance:
    kind: ProvenanceKind
    source: str
    # 기존 trace와의 호환을 위해 필드명은 유지한다. Day 6에서 담기는 값은
    # Runtime event ID가 아니라 원본 tool call ID다.
    parent_event_id: str | None = None
    received_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "source": self.source,
            "parent_event_id": self.parent_event_id,
            "received_at": self.received_at,
            "attributes": self.attributes,
        }


def direct_user_provenance(source: str = "interactive-user") -> Provenance:
    return Provenance(ProvenanceKind.USER_TASK, source)


def repository_provenance(path: str, *, parent_event_id: str | None = None) -> Provenance:
    return Provenance(ProvenanceKind.REPOSITORY_CONTENT, path, parent_event_id)


def observation_provenance(tool_name: str, *, parent_event_id: str | None = None) -> Provenance:
    return Provenance(ProvenanceKind.TOOL_OBSERVATION, tool_name, parent_event_id)


def external_provenance(url_or_service: str, *, parent_event_id: str | None = None) -> Provenance:
    return Provenance(ProvenanceKind.EXTERNAL_CONTENT, url_or_service, parent_event_id)


_OBSERVATION_SOURCE_KINDS = {
    ProvenanceKind.REPOSITORY_CONTENT,
    ProvenanceKind.TOOL_OBSERVATION,
    ProvenanceKind.EXTERNAL_CONTENT,
}


def make_observation(
    *,
    source_kind: ProvenanceKind,
    source: str,
    content: str,
    parent_call_id: str,
) -> ObservationEnvelope:
    """성공한 tool 결과로 변경 불가능한 observation record를 만든다."""
    if source_kind not in _OBSERVATION_SOURCE_KINDS:
        raise ValueError(f"unsupported observation source kind: {source_kind}")

    return ObservationEnvelope(
        observation_id=f"obs_{uuid4().hex}",
        parent_call_id=parent_call_id,
        source_kind=source_kind,
        source=source,
        trust=label_trust(source_kind),
        result_digest=f"sha256:{sha256(content.encode('utf-8')).hexdigest()}",
        content=content,
    )


def provenance_for_observations(
    envelopes: Sequence[ObservationEnvelope],
) -> Provenance:
    """현재 모델 문맥에 남아 있는 모든 observation ID를 다음 Intent에 전파한다.

    하나의 envelope이면 원래 source kind를 유지한다. 둘 이상이면 그 집합이
    tool observation 문맥임을 표현하고, 모든 원본 ID·source·call ID를
    attributes에 남긴다. 현재 Day 6 baseline에서는 이 세 source kind 모두
    untrusted이므로 하나라도 남아 있으면 다음 ToolIntent는 untrusted다.
    """
    if not envelopes:
        raise ValueError("at least one observation envelope is required")

    if len(envelopes) == 1:
        envelope = envelopes[0]
        kind = envelope.source_kind
        source = envelope.source
        parent_call_id = envelope.parent_call_id
    else:
        kind = ProvenanceKind.TOOL_OBSERVATION
        source = "multiple_observations"
        parent_call_id = envelopes[-1].parent_call_id

    return Provenance(
        kind=kind,
        source=source,
        parent_event_id=parent_call_id,
        attributes={
            "observation_ids": [envelope.observation_id for envelope in envelopes],
            "parent_call_ids": [envelope.parent_call_id for envelope in envelopes],
            "sources": [envelope.source for envelope in envelopes],
            "source_kinds": [envelope.source_kind.value for envelope in envelopes],
        },
    )
