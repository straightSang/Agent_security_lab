"""Day 9 MCP tool schema·least privilege fixture 실험."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

import runtime as runtime_module
from Agent import execute_tool
from experiment_support import make_experiment_runtime, record_run_evidence
from security.evaluator import evaluate_run
from security.provenance import direct_user_provenance, repository_provenance
from security.tool_schema import (
    LEGACY_COMPAT_PROFILE,
    MCP_TOOL_CATALOG,
    READ_ONLY_PROFILE,
    WRITE_ENABLED_PROFILE,
    get_tool_profile,
    profile_snapshot,
    tools_for_mcp,
)

SOURCE_DIR = Path(__file__).resolve().parent
FIXTURE_PATH = SOURCE_DIR / "fixtures" / "mcp_least_privilege.json"
TRACE_BASE = SOURCE_DIR / "traces" / "trace_D9_EXP.jsonl"
ACTOR = "user-001"


def load_suite() -> list[dict[str, Any]]:
    """사례 JSON을 읽고 사례 번호의 중복을 먼저 거부한다."""
    raw = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    assert raw["suite_id"] == "D9-MCP-LEAST-PRIVILEGE"
    cases = raw["cases"]
    assert isinstance(cases, list) and cases
    fixture_ids = [case["fixture_id"] for case in cases]
    assert len(fixture_ids) == len(set(fixture_ids))
    return cases


def run_case(case: dict[str, Any]) -> dict[str, Any]:
    """E01~E06 한 건의 seed→실행→trace→평가→증거 기록을 완료한다."""
    fixture_id = case["fixture_id"]
    expected = case["expected"]
    expected_calls = expected["gate_calls"]
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

    # 결과만 확인하면 내부 gate가 잘못 호출되어도 놓칠 수 있다. 각 mock은
    # 보안 단계의 실제 호출 횟수를 세며 fixture의 gate_calls와 대조한다.
    with (
        patch.object(runtime_module, "validate_tool_call", wraps=runtime_module.validate_tool_call) as validation,
        patch.object(experiment.runtime.policy, "evaluate", wraps=experiment.runtime.policy.evaluate) as policy,
        patch.object(experiment.runtime.authorizer, "authorize", wraps=experiment.runtime.authorizer.authorize) as authorization,
        patch.object(experiment.runtime.approvals, "resolve", wraps=experiment.runtime.approvals.resolve) as approval_resolve,
        patch.object(experiment.runtime.approvals, "request", wraps=experiment.runtime.approvals.request) as approval_request,
        patch.object(experiment.runtime, "_dispatch", wraps=experiment.runtime._dispatch) as dispatch,
    ):
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
        actual_calls = {
            "validation": validation.call_count,
            "policy": policy.call_count,
            "authorization": authorization.call_count,
            "approval_resolve": approval_resolve.call_count,
            "approval_request": approval_request.call_count,
        }
        assert actual_calls == expected_calls
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
        assert result["meta"]["authorization_decision"] == expected["authorization_decision"]

    events = list(experiment.runtime.trace.iter_events(run_id=experiment.run_id, strict=True))
    schema_event = [event for event in events if event["event"] == "tool_schema_decision"][-1]
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
        call_events = [event for event in events if event.get("call_id") == f"call-{fixture_id.lower()}"]
        assert not any(
            event["event"] in {"tool_intent", "policy_decision", "authorization_decision", "approval"}
            for event in call_events
        )

    return {
        **record_run_evidence(experiment),
        **evaluation.to_dict(),
        "gate_calls": actual_calls,
        "dispatch_count": dispatch.call_count,
    }


def check_advertised_schema_isolation() -> None:
    """모델에 전달한 schema/annotation 변경이 원본 보안 설정을 바꾸지 못함을 검사한다."""
    before = profile_snapshot(READ_ONLY_PROFILE)
    advertised = tools_for_mcp(READ_ONLY_PROFILE)
    advertised_read = next(tool for tool in advertised if tool["name"] == "read_file")
    advertised_read["annotations"]["readOnlyHint"] = False
    advertised_read["inputSchema"]["additionalProperties"] = True
    advertised_read["_meta"]["lab/capability"] = "filesystem.write"

    assert profile_snapshot(READ_ONLY_PROFILE) == before
    assert MCP_TOOL_CATALOG["read_file"]["annotations"]["readOnlyHint"] is True
    assert MCP_TOOL_CATALOG["read_file"]["inputSchema"]["additionalProperties"] is False
    assert MCP_TOOL_CATALOG["read_file"]["_meta"]["lab/capability"] == "filesystem.read"


def main() -> None:
    """모든 사례와 정적 schema 격리 불변조건을 실행한다."""
    results = {case["fixture_id"]: run_case(case) for case in load_suite()}
    check_advertised_schema_isolation()
    profile_metrics = {
        profile.name: {
            **profile_snapshot(profile),
            "exposed_tool_count": len(profile.exposed_tools),
            "write_exposed": "write_file" in profile.exposed_tools,
            "generic_command_exposed": "run_command" in profile.exposed_tools,
        }
        for profile in (READ_ONLY_PROFILE, WRITE_ENABLED_PROFILE, LEGACY_COMPAT_PROFILE)
    }
    assert profile_metrics["read_only"]["exposed_tool_count"] == 4
    assert profile_metrics["read_only"]["write_exposed"] is False
    assert profile_metrics["write_enabled"]["generic_command_exposed"] is False
    print(json.dumps({"cases": results, "profiles": profile_metrics}, ensure_ascii=False, indent=2))
    print("Day 9 MCP least-privilege schema tests: PASS")


if __name__ == "__main__":
    main()
