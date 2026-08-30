"""Day 8 보안 경계의 우회 경로를 고정하는 회귀 검사.

각 동적 검사는 독립 Runtime·sandbox·trace를 사용하며 seed, 평가, 최종
증거 요약을 남긴다. 이 파일은 외부 API나 실제 서비스에 연결하지 않는다.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
from unittest.mock import patch

from Agent import execute_tool
from approval import approve_pending_request
from experiment_support import make_experiment_runtime, record_run_evidence
from security.evaluator import evaluate_run
from security.provenance import direct_user_provenance, repository_provenance
from security.types import ApprovalStatus


SOURCE_DIR = Path(__file__).resolve().parent
TRACE_BASE = SOURCE_DIR / "traces" / "trace_D8_INVARIANTS.jsonl"
ACTOR = "user-001"


def assert_no_direct_dispatch_call() -> None:
    """Runtime 구현 이외의 Python 코드가 _dispatch()를 직접 호출하지 않는지 검사한다."""
    violations: list[str] = []
    for path in SOURCE_DIR.rglob("*.py"):
        if path.name == "runtime.py" or "venv" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "_dispatch"
            ):
                violations.append(f"{path.relative_to(SOURCE_DIR)}:{node.lineno}")
    assert not violations, f"Runtime 밖의 직접 _dispatch 호출: {violations}"


def assert_no_legacy_authorizer() -> None:
    """제거한 이전 인가 연결 이름이 실행 소스에 남아 있지 않은지 검사한다."""
    forbidden_names = ("legacy_authorizer", "adapt_legacy_authorizer")
    violations: list[str] = []
    for path in SOURCE_DIR.rglob("*.py"):
        if path.name == Path(__file__).name or "venv" in path.parts:
            continue
        text = path.read_text(encoding="utf-8")
        for name in forbidden_names:
            if name in text:
                violations.append(f"{path.relative_to(SOURCE_DIR)}:{name}")
    assert not violations, f"이전 인가 연결이 남아 있음: {violations}"


def check_policy_deny_short_circuit() -> dict:
    """Policy DENY 뒤에는 인가·승인·실행이 모두 호출되지 않아야 한다."""
    experiment = make_experiment_runtime(
        "D8-E07", trace_path=TRACE_BASE, seed_files=()
    )
    runtime = experiment.runtime
    with (
        patch.object(runtime.authorizer, "authorize", wraps=runtime.authorizer.authorize) as authorize,
        patch.object(runtime.approvals, "resolve", wraps=runtime.approvals.resolve) as resolve,
        patch.object(runtime.approvals, "request", wraps=runtime.approvals.request) as request,
        patch.object(runtime, "_dispatch", wraps=runtime._dispatch) as dispatch,
    ):
        result = execute_tool(
            "write_file",
            {"path": "data/user-001/policy-denied.txt", "content": "blocked"},
            call_id="call-d8-i01-policy-deny",
            run_id=experiment.run_id,
            actor=ACTOR,
            provenance=repository_provenance("synthetic-untrusted-input"),
            fixture_id="D8-E07",
            runtime=runtime,
        )
    assert result["end_stage"] == "policy"
    assert authorize.call_count == 0
    assert resolve.call_count == 0
    assert request.call_count == 0
    assert dispatch.call_count == 0
    assert "approval_id" not in result["meta"]
    evaluation = evaluate_run(
        runtime.trace.iter_events(run_id=experiment.run_id, strict=True),
        expected_decision="deny",
        unsafe_fixture=True,
    )
    assert evaluation.policy_bypass is False
    assert evaluation.trace_completeness is True
    return {**record_run_evidence(experiment), **evaluation.to_dict()}


def check_authorization_deny_short_circuit() -> dict:
    """AuthZ DENY 뒤에는 승인 번호나 실제 실행이 없어야 한다."""
    experiment = make_experiment_runtime(
        "D8-E08",
        trace_path=TRACE_BASE,
        seed_files=("data/user-002/private.txt",),
    )
    runtime = experiment.runtime
    with (
        patch.object(runtime.approvals, "resolve", wraps=runtime.approvals.resolve) as resolve,
        patch.object(runtime.approvals, "request", wraps=runtime.approvals.request) as request,
        patch.object(runtime, "_dispatch", wraps=runtime._dispatch) as dispatch,
    ):
        result = execute_tool(
            "read_file",
            {"path": "data/user-002/private.txt"},
            call_id="call-d8-i02-authz-deny",
            run_id=experiment.run_id,
            actor=ACTOR,
            provenance=direct_user_provenance("fixture-harness"),
            fixture_id="D8-E08",
            runtime=runtime,
        )
    assert result["end_stage"] == "authorization"
    assert result["meta"]["policy_decision"] == "allow"
    assert result["meta"]["authorization_decision"] == "deny"
    assert resolve.call_count == 0
    assert request.call_count == 0
    assert dispatch.call_count == 0
    assert "approval_id" not in result["meta"]
    evaluation = evaluate_run(
        runtime.trace.iter_events(run_id=experiment.run_id, strict=True),
        expected_decision="allow",
        expected_authorization="deny",
    )
    assert evaluation.authorization_false_allow is False
    assert evaluation.trace_completeness is True
    return {**record_run_evidence(experiment), **evaluation.to_dict()}


def check_approval_consume_and_replay() -> dict:
    """승인된 동일 intent는 consume 뒤 한 번만 실행되어야 한다."""
    experiment = make_experiment_runtime(
        "D8-E09", trace_path=TRACE_BASE, seed_files=()
    )
    runtime = experiment.runtime
    arguments = {
        "path": "data/user-001/approved-once.txt",
        "content": "one dispatch only",
    }

    with patch.object(runtime, "_dispatch", wraps=runtime._dispatch) as pending_dispatch:
        pending = execute_tool(
            "write_file",
            arguments,
            call_id="call-d8-i03-pending",
            run_id=experiment.run_id,
            actor=ACTOR,
            provenance=direct_user_provenance("fixture-harness"),
            fixture_id="D8-E09",
            runtime=runtime,
        )
    assert pending["status"] == "approval_required"
    assert pending_dispatch.call_count == 0
    approval_id = pending["meta"]["approval_id"]
    control = approve_pending_request(
        runtime.approvals,
        approval_id,
        authenticated_approver=ACTOR,
    )
    assert control.changed is True
    assert control.state.status is ApprovalStatus.APPROVED

    call_order: list[str] = []
    original_consume = runtime.approvals.consume
    original_dispatch = runtime._dispatch

    def tracked_consume(*args, **kwargs):
        call_order.append("consume")
        return original_consume(*args, **kwargs)

    def tracked_dispatch(*args, **kwargs):
        call_order.append("dispatch")
        return original_dispatch(*args, **kwargs)

    with (
        patch.object(runtime.approvals, "consume", side_effect=tracked_consume) as consume,
        patch.object(runtime, "_dispatch", side_effect=tracked_dispatch) as dispatch,
    ):
        success = execute_tool(
            "write_file",
            arguments,
            call_id="call-d8-i03-approved",
            run_id=experiment.run_id,
            actor=ACTOR,
            provenance=direct_user_provenance("fixture-harness"),
            approval_id=approval_id,
            fixture_id="D8-E09",
            runtime=runtime,
        )
    assert success["ok"] is True
    assert success["meta"]["approval"] == "consumed"
    assert consume.call_count == 1
    assert dispatch.call_count == 1
    assert call_order == ["consume", "dispatch"]

    with patch.object(runtime, "_dispatch", wraps=runtime._dispatch) as replay_dispatch:
        replay = execute_tool(
            "write_file",
            arguments,
            call_id="call-d8-i03-replay",
            run_id=experiment.run_id,
            actor=ACTOR,
            provenance=direct_user_provenance("fixture-harness"),
            approval_id=approval_id,
            fixture_id="D8-E09",
            runtime=runtime,
        )
    assert replay["ok"] is False
    assert replay["status"] == "approval_required"
    assert replay_dispatch.call_count == 0
    assert runtime.approvals.resolve(approval_id).status is ApprovalStatus.CONSUMED
    assert (experiment.sandbox_root / arguments["path"]).read_text(
        encoding="utf-8"
    ) == arguments["content"]

    evaluation = evaluate_run(
        runtime.trace.iter_events(run_id=experiment.run_id, strict=True),
        expected_decision="approval_required",
        expected_authorization="allow",
    )
    assert evaluation.approval_bypass is False
    assert evaluation.trace_completeness is True
    return {
        **record_run_evidence(experiment),
        **evaluation.to_dict(),
        "consume_before_dispatch": call_order == ["consume", "dispatch"],
        "successful_dispatch_count": 1,
        "replay_dispatch_count": replay_dispatch.call_count,
    }


assert_no_direct_dispatch_call()
assert_no_legacy_authorizer()

results = {
    "D8-E07": check_policy_deny_short_circuit(),
    "D8-E08": check_authorization_deny_short_circuit(),
    "D8-E09": check_approval_consume_and_replay(),
}

print(json.dumps(results, ensure_ascii=False, indent=2))
print("Day 8 security invariant tests: PASS")
