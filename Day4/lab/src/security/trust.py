"""Central trust-labelling policy; keep it separate from allow/deny policy."""

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
    """Treat content that may contain indirect instructions as untrusted by default."""
    return DEFAULT_TRUST_BY_PROVENANCE[provenance.kind]
