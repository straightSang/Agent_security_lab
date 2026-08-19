"""중앙 trust label 정책. allow/deny 정책과 분리해 유지한다."""

from __future__ import annotations

from .provenance import Provenance
from .types import ProvenanceKind, TrustLabel


DEFAULT_TRUST_BY_PROVENANCE = {
    ProvenanceKind.SYSTEM: TrustLabel.TRUSTED,
    ProvenanceKind.USER_TASK: TrustLabel.USER_CONTROLLED,
    ProvenanceKind.REPOSITORY_CONTENT: TrustLabel.UNTRUSTED,
    ProvenanceKind.TOOL_OBSERVATION: TrustLabel.UNTRUSTED,
    ProvenanceKind.EXTERNAL_CONTENT: TrustLabel.UNTRUSTED,
}


def label_trust(provenance: Provenance) -> TrustLabel:
    """간접 지시를 포함할 수 있는 콘텐츠는 기본적으로 untrusted로 취급한다."""
    return DEFAULT_TRUST_BY_PROVENANCE[provenance.kind]
