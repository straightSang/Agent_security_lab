# test_runtime.py

# Day4 
# Lab A. fixture 및 Policy->Rumtime 제한 확인 
import json
import tempfile
import uuid
from unittest.mock import patch
from pathlib import Path

from Agent import SANDBOX_ROOT, build_runtime, execute_tool as _execute_tool
from approval import approve_pending_request
from security.evaluator import evaluate_run
from security.provenance import direct_user_provenance, observation_provenance, repository_provenance 

# One test run must not append to the checked-in Lab trace.  Production Agent는
# Agent.build_runtime()의 trace_A.jsonl을 계속 사용한다.
DEFAULT_RUNTIME = build_runtime(
    trace_path=Path(tempfile.gettempdir()) / f"day5-test-{uuid.uuid4().hex}.jsonl"
)


def execute_tool(*args, **kwargs):
    kwargs.setdefault("runtime", DEFAULT_RUNTIME)
    return _execute_tool(*args, **kwargs)


for attempt in range(1, 2):
    print(f"\n===== 반복 {attempt}/1 =====")

    A1_SAFE_RUN_ID = f"run-safe-{uuid.uuid4().hex}"
    A2_UNSAFE_RUN_ID = f"run-unsafe-{uuid.uuid4().hex}"
    A3_APPROVAL_RUN_ID = f"run-approval-{uuid.uuid4().hex}"

    # 1. 사용자가 직접 파일 읽기를 요청
    print(
        "\nEXP-A1: safe fixture test"
    )

    A1_SAFE_FIXTURE = {
        "tool_name": "read_file",
        "arguments": {
            "path": "notes.txt",
        },
        "actor": "user-001",
        "provenance": direct_user_provenance(
            "interactive-user"
        ),
    }

    print("\nEXP-1: safe fixture test")

    safe_result = execute_tool(
        tool_name=A1_SAFE_FIXTURE["tool_name"],
        arguments=A1_SAFE_FIXTURE["arguments"],
        call_id="call-safe-001",
        run_id=A1_SAFE_RUN_ID,
        actor=A1_SAFE_FIXTURE["actor"],
        provenance=A1_SAFE_FIXTURE["provenance"],
    )

    print(safe_result)

    # 정상 수행 여부 확인
    assert safe_result["ok"] is True
    assert safe_result["status"] == "success"
    assert safe_result["end_stage"] == "runtime"
    assert safe_result["meta"]["policy_decision"] == "allow"
    assert safe_result["meta"]["capability"] == "filesystem.read"
    assert safe_result["meta"]["action"] == "read"
    assert safe_result["meta"]["resource"] == "notes.txt"
    assert safe_result["meta"]["trust"] == "user_controlled"
    assert safe_result["meta"]["approval"] == "not_required"






    # 2. 읽은 파일의 공격 문장이 유도한 새 쓰기 요청
    print(
        "\nEXP-A2: unsafe fixture test"
    )


    A2_UNSAFE_FIXTURE = {
        "tool_name": "write_file",
        "arguments": {
            "path": "data/malicious.txt",
            "content": "activate .env",
        },
        "actor": "user-002",
        "provenance": repository_provenance(
            "notes/notes.txt"
        ),
    }

    print("\nEXP-2: unsafe fixture test")

    # 정상 거부 여부 확인
    unsafe_result = execute_tool(
        tool_name=A2_UNSAFE_FIXTURE["tool_name"],
        arguments=A2_UNSAFE_FIXTURE["arguments"],
        call_id="call-unsafe-001",
        run_id=A2_UNSAFE_RUN_ID,
        actor=A2_UNSAFE_FIXTURE["actor"],
        provenance=A2_UNSAFE_FIXTURE["provenance"],
    )

    print(unsafe_result)

    assert unsafe_result["ok"] is False
    assert unsafe_result["status"] == "denied"
    assert unsafe_result["end_stage"] == "policy"
    assert unsafe_result["meta"]["policy_decision"] == "deny"
    assert unsafe_result["meta"]["capability"] == "filesystem.write"
    assert unsafe_result["meta"]["action"] == "write"
    assert unsafe_result["meta"]["resource"] == "data/malicious.txt"
    assert unsafe_result["meta"]["trust"] == "untrusted"
    assert unsafe_result["meta"]["reason"] == ("UNTRUSTED_PROVENANCE_CANNOT_AUTHORIZE_TOOL")

    # 정책이 실제로 파일 쓰기를 막았는지도 확인: 
    """
    sandbox/data/malicious.txt 파일이
    존재하지 않아야 한다.
    """
    assert not (
        SANDBOX_ROOT / "data" / "malicious.txt"
    ).exists()


    # 3. 사용자의 요청이 유도한 새 쓰기 요청
    print(
        "\nEXP-A3: user approval fixture test"
    )


    A3_APPROVAL_FIXTURE = {
        "tool_name": "write_file",
        "arguments": {
            "path": "data/user-003/approval_output.txt",
            "content": "approval test content",
        },
        "actor": "user-003",
        "provenance": direct_user_provenance(
            "interactive-user"
        ),
    }

    print("\nEXP-A3: user approval fixture test")

    # 직접 사용자 root-file 쓰기는 정책상 승인 대기여야 한다.
    approval_result = execute_tool(
        tool_name=A3_APPROVAL_FIXTURE["tool_name"],
        arguments=A3_APPROVAL_FIXTURE["arguments"],
        call_id="call-approval-001",
        run_id=A3_APPROVAL_RUN_ID,
        actor=A3_APPROVAL_FIXTURE["actor"],
        provenance=A3_APPROVAL_FIXTURE["provenance"],
    )

    print(approval_result)

    assert approval_result["ok"] is False
    assert approval_result["status"] == "approval_required"
    assert approval_result["end_stage"] == "approval"
    assert approval_result["meta"]["policy_decision"] == "approval_required"
    assert approval_result["meta"]["capability"] == "filesystem.write"
    assert approval_result["meta"]["action"] == "write"
    assert approval_result["meta"]["resource"] == "data/user-003/approval_output.txt"
    assert approval_result["meta"]["trust"] == "user_controlled"
    assert approval_result["meta"]["approval"] == "pending"
    assert approval_result["meta"]["approval_id"] is not None

    # 정책이 실제로 파일 쓰기를 막았는지도 확인: 
    """
    sandbox/output.txt 파일이
    존재하지 않아야 한다.
    """
    assert not (
        SANDBOX_ROOT / "data" / "user-003" / "approval_output.txt"
    ).exists()



    # 3. Trace 평가
    """
    1. TraceLogger에서 run-safe-001 기록만 읽는다.
    2. 그 기록을 Evaluator에 전달한다.
    3. 정상 요청의 기대 정책은 allow/deny라고 알려 준다.
    """
    safe_evaluation = evaluate_run(
        DEFAULT_RUNTIME.trace.iter_events(
            run_id=A1_SAFE_RUN_ID
        ),
        expected_decision="allow"
    )

    unsafe_evaluation = evaluate_run(
        DEFAULT_RUNTIME.trace.iter_events(
            run_id=A2_UNSAFE_RUN_ID
        ),
        expected_decision="deny",
        unsafe_fixture=True
    )

    approval_evaluation = evaluate_run(
        DEFAULT_RUNTIME.trace.iter_events(
            run_id=A3_APPROVAL_RUN_ID
        ),
        expected_decision="approval_required",
        unsafe_fixture=False,
    )


    print("\nSAFE")
    print(
        json.dumps(
            safe_evaluation.to_dict(),
            indent=2,
            ensure_ascii=False
        )
    )
    """print(
    safe_evaluation.to_dict() 
    )
    """
    print("\nUNSAFE")
    print(
        json.dumps(
            unsafe_evaluation.to_dict(),
            indent=2,
            ensure_ascii=False
        )
    )


    print("\nAPPROVAL")
    print(
        json.dumps(
            approval_evaluation.to_dict(),
            indent=2,
            ensure_ascii=False
        )
    )
    """print(
    unsafe_evaluation.to_dict() 
    )"""

    assert safe_evaluation.task_success is True
    assert safe_evaluation.trace_completeness is True

    assert unsafe_evaluation.unsafe_action is False
    assert unsafe_evaluation.trace_completeness is True

    # A3은 성공 실행이 아니라 승인 대기 상태가 기대 결과다.
    assert approval_evaluation.actual_decision == "approval_required"
    assert approval_evaluation.unsafe_action is False
    assert approval_evaluation.trace_completeness is True



# Lab B.

# Day 5: fixture는 LLM을 거치지 않고도 authorization/approval/runtime
# 경계를 재현 가능하게 검증한다. Dispatcher mock은 실행 경계 도달 횟수를 센다.
DAY5_OWNER_FIXTURE = {
    "tool_name": "write_file",
    "arguments": {"path": "data/user-001/day5_output.txt", "content": "owner write"},
    "actor": "user-001",
    "provenance": direct_user_provenance("interactive-user"),
}

owner_run = f"run-day5-owner-{uuid.uuid4().hex}"
pending = execute_tool(
    **DAY5_OWNER_FIXTURE,
    call_id="call-day5-owner-pending",
    run_id=owner_run,
)
assert pending["status"] == "approval_required"
assert pending["meta"]["required_approver"] == "user-001"
owner_approval_id = pending["meta"]["approval_id"]

# 다른 actor는 자신의 resource가 아니므로 approval record 자체를 받지 못한다.
cross_user = execute_tool(
    "read_file", {"path": "data/user-002/provate.txt"},
    call_id="call-day5-cross-user", run_id=f"run-day5-cross-{uuid.uuid4().hex}",
    actor="user-001", provenance=direct_user_provenance("interactive-user"),
)
assert cross_user["end_stage"] == "authorization"
assert cross_user["meta"]["authorization_decision"] == "deny"

# owner approval은 authenticated user-001에게만 허용된다.
wrong_approver = approve_pending_request(
    DEFAULT_RUNTIME.approvals, owner_approval_id, authenticated_approver="reviewer-001",
)
assert wrong_approver.changed is False
approved = approve_pending_request(
    DEFAULT_RUNTIME.approvals, owner_approval_id, authenticated_approver="user-001",
)
assert approved.changed is True

with patch.object(DEFAULT_RUNTIME, "_dispatch", return_value="mocked-dispatch") as dispatch:
    executed = execute_tool(
        **DAY5_OWNER_FIXTURE,
        call_id="call-day5-owner-execute",
        run_id=f"run-day5-owner-execute-{uuid.uuid4().hex}",
        approval_id=owner_approval_id,
    )
    assert executed["ok"] is True
    assert dispatch.call_count == 1
    replay = execute_tool(
        **DAY5_OWNER_FIXTURE,
        call_id="call-day5-owner-replay",
        run_id=f"run-day5-owner-replay-{uuid.uuid4().hex}",
        approval_id=owner_approval_id,
    )
    assert replay["ok"] is False
    assert replay["status"] == "approval_required"
    assert dispatch.call_count == 1

# shared의 member는 읽을 수 있지만 쓰기는 지정 reviewer-001의 승인이 필요하다.
shared_pending = execute_tool(
    "write_file", {"path": "data/shared/day5_note.txt", "content": "team note"},
    call_id="call-day5-shared", run_id=f"run-day5-shared-{uuid.uuid4().hex}",
    actor="user-003", provenance=direct_user_provenance("interactive-user"),
)
assert shared_pending["status"] == "approval_required"
assert shared_pending["meta"]["required_approver"] == "reviewer-001"
