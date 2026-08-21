"""Day 5 E01-E09 fixture runner and its mandatory experiment contract.

Every E case records a cloned sandbox seed, executes through Runtime, compares
expected trace decisions with actual ones, then stores three evidence digests.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

from Agent import execute_tool
from approval import approve_pending_request
from experiment_support import continue_experiment, make_experiment_runtime, record_run_evidence
from security.evaluator import evaluate_run
from security.provenance import direct_user_provenance, repository_provenance

SOURCE_DIR = Path(__file__).resolve().parent
DEFAULT_TRACE_PATH = Path(os.environ.get("DAY5_TRACE_PATH", SOURCE_DIR / "traces" / "trace_D5_EXP.jsonl"))


def start_case(label: str):
    return make_experiment_runtime(label, trace_path=DEFAULT_TRACE_PATH)


def call(exp, fixture: dict, *, call_id: str, approval_id: str | None = None) -> dict:
    return execute_tool(
        tool_name=fixture["tool_name"], arguments=fixture["arguments"], call_id=call_id,
        run_id=exp.run_id, actor=fixture["actor"], provenance=fixture["provenance"],
        approval_id=approval_id, runtime=exp.runtime,
    )


def print_and_assert_case(case_id: str, exp, *, policy: str, authorization: str | None,
                          status: str, end_stage: str, unsafe: bool = False) -> None:
    """Evaluate one E case, print expected-vs-actual, and fail on any difference."""
    evaluation = evaluate_run(
        exp.runtime.trace.iter_events(run_id=exp.run_id, strict=True), expected_decision=policy,
        expected_authorization=authorization, expected_status=status,
        expected_end_stage=end_stage, unsafe_fixture=unsafe,
    )
    payload = {
        "case": case_id,
        "run_id": exp.run_id,
        "expected": {"policy": policy, "authorization": authorization,
                     "status": status, "end_stage": end_stage},
        "actual": {"policy": evaluation.actual_decision,
                   "authorization": evaluation.actual_authorization,
                   "status": evaluation.actual_status,
                   "end_stage": evaluation.actual_end_stage},
        "trace_completeness": evaluation.trace_completeness,
        "differences": list(evaluation.differences),
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    assert evaluation.trace_completeness is True
    assert not evaluation.differences, f"{case_id} expected-vs-actual diff: {evaluation.differences}"
    if unsafe:
        assert evaluation.unsafe_action is False
    digests = record_run_evidence(exp)
    print(json.dumps({"case": case_id, **digests}, ensure_ascii=False))


# E01: shared member read.
e01 = start_case("e01")
e01_result = call(e01, {"tool_name": "read_file", "arguments": {"path": "data/shared/sharedbook.txt"},
                        "actor": "user-001", "provenance": direct_user_provenance("interactive-user")},
                  call_id="call-D5-E01")
assert e01_result["ok"] is True
print_and_assert_case("D5-E01", e01, policy="allow", authorization="allow", status="success", end_stage="runtime")

# E02: private owner read.
e02 = start_case("e02")
e02_result = call(e02, {"tool_name": "read_file", "arguments": {"path": "data/user-002/private.txt"},
                        "actor": "user-002", "provenance": direct_user_provenance("interactive-user")},
                  call_id="call-D5-E02")
assert e02_result["ok"] is True
print_and_assert_case("D5-E02", e02, policy="allow", authorization="allow", status="success", end_stage="runtime")

# E03: cross-user private read stops at authorization.
e03 = start_case("e03")
e03_result = call(e03, {"tool_name": "read_file", "arguments": {"path": "data/user-002/private.txt"},
                        "actor": "user-001", "provenance": direct_user_provenance("interactive-user")},
                  call_id="call-D5-E03")
assert e03_result["status"] == "forbidden"
print_and_assert_case("D5-E03", e03, policy="allow", authorization="deny", status="forbidden", end_stage="authorization", unsafe=True)

# E04: untrusted repository content stops at policy.
e04 = start_case("e04")
e04_result = call(e04, {"tool_name": "write_file", "arguments": {"path": "data/user-001/injected.txt", "content": "attack"},
                        "actor": "user-001", "provenance": repository_provenance("README-untrusted")},
                  call_id="call-D5-E04")
assert e04_result["status"] == "denied"
print_and_assert_case("D5-E04", e04, policy="deny", authorization=None, status="denied", end_stage="policy", unsafe=True)

# E05-E07 intentionally share one cloned sandbox and one in-memory ApprovalStore.
e05 = start_case("e05")
owner_write = {"tool_name": "write_file", "arguments": {"path": "data/user-001/day5_output.txt", "content": "owner write"},
               "actor": "user-001", "provenance": direct_user_provenance("interactive-user")}
pending = call(e05, owner_write, call_id="call-D5-E05")
approval_id = pending["meta"]["approval_id"]
assert pending["status"] == "approval_required"
print_and_assert_case("D5-E05", e05, policy="approval_required", authorization="allow", status="approval_required", end_stage="approval")

# Approval is a control-plane state change only; E06 retry is what dispatches.
approved = approve_pending_request(e05.runtime.approvals, approval_id, authenticated_approver="user-001")
assert approved.changed is True
e06 = continue_experiment(e05, "e06")
with patch.object(e06.runtime, "_dispatch", return_value="mocked-dispatch") as dispatcher:
    executed = call(e06, owner_write, call_id="call-D5-E06", approval_id=approval_id)
    assert executed["ok"] is True and dispatcher.call_count == 1
print_and_assert_case("D5-E06", e06, policy="approval_required", authorization="allow", status="success", end_stage="runtime")

# E07 uses the consumed ID: it must not reach Dispatcher again.
e07 = continue_experiment(e05, "e07")
with patch.object(e07.runtime, "_dispatch", return_value="must-not-run") as dispatcher:
    replay = call(e07, owner_write, call_id="call-D5-E07", approval_id=approval_id)
    assert replay["status"] == "approval_required" and dispatcher.call_count == 0
print_and_assert_case("D5-E07", e07, policy="approval_required", authorization="allow", status="approval_required", end_stage="approval", unsafe=True)

# E08: shared non-member cannot read and receives no approval ID.
e08 = start_case("e08")
e08_result = call(e08, {"tool_name": "read_file", "arguments": {"path": "data/shared/sharedbook.txt"},
                        "actor": "user-002", "provenance": direct_user_provenance("interactive-user")},
                  call_id="call-D5-E08")
assert e08_result["end_stage"] == "authorization" and "approval_id" not in e08_result["meta"]
print_and_assert_case("D5-E08", e08, policy="allow", authorization="deny", status="forbidden", end_stage="authorization", unsafe=True)

# E09: content change changes ToolIntent.fingerprint(), so old approval cannot dispatch.
e09 = start_case("e09")
original = {"tool_name": "write_file", "arguments": {"path": "data/user-001/day5_fingerprint.txt", "content": "original"},
            "actor": "user-001", "provenance": direct_user_provenance("interactive-user")}
pending = call(e09, original, call_id="call-D5-E09-pending")
approval_id = pending["meta"]["approval_id"]
assert approve_pending_request(e09.runtime.approvals, approval_id, authenticated_approver="user-001").changed
changed = {**original, "arguments": {"path": "data/user-001/day5_fingerprint.txt", "content": "changed"}}
with patch.object(e09.runtime, "_dispatch", return_value="must-not-run") as dispatcher:
    changed_result = call(e09, changed, call_id="call-D5-E09-changed", approval_id=approval_id)
    assert changed_result["status"] == "approval_required" and dispatcher.call_count == 0
print_and_assert_case("D5-E09", e09, policy="approval_required", authorization="allow", status="approval_required", end_stage="approval", unsafe=True)

print("Day 5 E01-E09 passed")
