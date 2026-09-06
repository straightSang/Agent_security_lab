"""Day 7 indirect-prompt-injection fixture의 작은 입력 계약.

fixture는 Policy에 권한을 부여하지 않는다. test harness가 fixture의 source와
기대값을 읽어 Runtime 호출을 구성할 뿐, trust는 provenance kind에서 별도로
계산되고 실제 allow/deny는 PolicyEngine이 결정한다.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, Mapping

from .types import ProvenanceKind


@dataclass(frozen=True)
class IndirectPromptInjectionFixture:
    fixture_id: str
    category: str
    user_task: str
    source_kind: ProvenanceKind
    source: str
    content: str
    expected: Mapping[str, Any]
    attack_proposal: Mapping[str, Any] | None = None


def load_indirect_prompt_injection_fixture(path: Path) -> IndirectPromptInjectionFixture:
    """JSON fixture를 읽고 실험에 필요한 최소 형식만 검증한다."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("fixture root must be an object")

    required = {"fixture_id", "category", "user_task", "observation", "expected"}
    missing = required - set(raw)
    if missing:
        raise ValueError(f"fixture missing fields: {', '.join(sorted(missing))}")

    observation = raw["observation"]
    if not isinstance(observation, dict):
        raise ValueError("fixture observation must be an object")
    for key in ("source_kind", "source", "content"):
        if key not in observation or not isinstance(observation[key], str):
            raise ValueError(f"fixture observation.{key} must be a string")

    try:
        source_kind = ProvenanceKind(observation["source_kind"])
    except ValueError as exc:
        raise ValueError("fixture observation.source_kind is not supported") from exc
    if source_kind not in {
        ProvenanceKind.REPOSITORY_CONTENT,
        ProvenanceKind.TOOL_OBSERVATION,
        ProvenanceKind.EXTERNAL_CONTENT,
    }:
        raise ValueError("Day 7 observation fixture must be an indirect source")

    proposal = raw.get("attack_proposal")
    if proposal is not None:
        if not isinstance(proposal, dict) or not isinstance(proposal.get("tool_name"), str) or not isinstance(proposal.get("arguments"), dict):
            raise ValueError("fixture attack_proposal requires tool_name and arguments")

    if not isinstance(raw["expected"], dict):
        raise ValueError("fixture expected must be an object")

    return IndirectPromptInjectionFixture(
        fixture_id=str(raw["fixture_id"]),
        category=str(raw["category"]),
        user_task=str(raw["user_task"]),
        source_kind=source_kind,
        source=observation["source"],
        content=observation["content"],
        expected=raw["expected"],
        attack_proposal=proposal,
    )
