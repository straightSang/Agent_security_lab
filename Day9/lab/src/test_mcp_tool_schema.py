"""Day 9 MCP tool schema·least privilege fixture 실험."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from Agent import execute_tool
from experiment_support import make_experiment_runtime, record_run_evidence
from security.evaluator import evaluate_run
from security.provenance import direct_user_provenance, repository_provenance
from security.tool_schema import (
    LEGACY_COMPAT_PROFILE,
    READ_ONLY_PROFILE,
    WRITE_ENABLED_PROFILE,
    get_tool_profile,
    profile_snapshot,
)


SOURCE_DIR = Path(__file__).resolve().parent
FIXTURE_PATH = SOURCE_DIR / "fixtures" / "mcp_least_privilege.json"
TRACE_BASE = SOURCE_DIR / "traces" / "trace_D9_EXP.jsonl"
ACTOR = "user-001"


def load_suite() -> list[dict]:
    raw = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    assert raw["suite_id"] == "D9-MCP-LEAST-PRIVILEGE"
    cases = raw["cases"]
    assert isinstance(cases, list) and cases
    fixture_ids = [case["fixture_id"] for case in cases]
    assert len(fixture_ids) == len(set(fixture_ids))
    return cases


results: dict[str, dict] = {}

for case in load_suite():
    fixture_id = case["fixture_id"]
    expected = case["expected"]
    profile = get_tool_profile(case["profile"])
    experiment = make_experiment_runtime(
        fixture_id,
        trace_path=TRACE_BASE,
        seed_files=case["seed_files"],
        tool_profile=profile,
    )
    provenance = (
        repository_provenance("synthetic-injected-content")
        if fixture_id == "D9-E02"
        else direct_user_provenance("fixture-harness")
    )

    with patch.object(
        experiment.runtime,
        "_dispatch",
        wraps=experiment.runtime._dispatch,
    ) as dispatch:
        result = execute_tool(
            case["tool_name"],
            case["arguments"],
            call_id=f"call-{fixture_id.lower()}",
            run_id=experiment.run_id,
            actor=ACTOR,
            provenance=provenance,
            fixture_id=fixture_id,
            runtime=experiment.runtime,
        )
        assert dispatch.call_count == expected["dispatch_count"]

    assert result["status"] == expected["runtime_status"]
    assert result["meta"]["tool_schema_decision"] == expected["schema_decision"]
    if "end_stage" in expected:
        assert result["end_stage"] == expected["end_stage"]
    if "reason" in expected:
        assert result["meta"]["tool_schema_reason"] == expected["reason"]
    if "policy_decision" in expected:
        assert result["meta"]["policy_decision"] == expected["policy_decision"]
    if "authorization_decision" in expected:
        assert (
            result["meta"]["authorization_decision"]
            == expected["authorization_decision"]
        )

    events = list(
        experiment.runtime.trace.iter_events(
            run_id=experiment.run_id,
            strict=True,
        )
    )
    schema_event = [
        event for event in events if event["event"] == "tool_schema_decision"
    ][-1]
    assert schema_event["tool_profile"] == case["profile"]
    assert schema_event["tool_schema_decision"] == expected["schema_decision"]

    expected_schema_allowed = expected["schema_decision"] == "allow"
    evaluation = evaluate_run(
        events,
        expected_decision=expected.get("policy_decision"),
        expected_authorization=expected.get("authorization_decision"),
        expected_schema_allowed=expected_schema_allowed,
        unsafe_fixture=case["category"] == "unsafe",
    )
    assert evaluation.schema_bypass is False
    assert evaluation.schema_false_block is False
    assert evaluation.trace_completeness is True

    if not expected_schema_allowed:
        call_events = [
            event for event in events
            if event.get("call_id") == f"call-{fixture_id.lower()}"
        ]
        assert not any(
            event["event"] in {
                "tool_intent", "policy_decision", "authorization_decision", "approval"
            }
            for event in call_events
        )

    results[fixture_id] = {
        **record_run_evidence(experiment),
        **evaluation.to_dict(),
        "dispatch_count": dispatch.call_count,
    }


profile_metrics = {
    profile.name: {
        **profile_snapshot(profile),
        "exposed_tool_count": len(profile.exposed_tools),
        "write_exposed": "write_file" in profile.exposed_tools,
        "generic_command_exposed": "run_command" in profile.exposed_tools,
    }
    for profile in (
        READ_ONLY_PROFILE,
        WRITE_ENABLED_PROFILE,
        LEGACY_COMPAT_PROFILE,
    )
}

assert profile_metrics["read_only"]["exposed_tool_count"] == 4
assert profile_metrics["read_only"]["write_exposed"] is False
assert profile_metrics["write_enabled"]["generic_command_exposed"] is False

print(json.dumps({"cases": results, "profiles": profile_metrics}, ensure_ascii=False, indent=2))
print("Day 9 MCP least-privilege schema tests: PASS")
