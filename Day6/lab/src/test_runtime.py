# test_runtime.py

# Day4 
# Lab A. fixture 및 Policy->Rumtime 제한 확인 
import uuid
from unittest.mock import patch
from pathlib import Path

from Agent import SANDBOX_ROOT, build_runtime, execute_tool as _execute_tool
from approval import approve_pending_request
from security.provenance import direct_user_provenance, repository_provenance

# Lab A 전용 trace다. append 방식이므로 이벤트는 누적되며, 각 fixture는 고유한
# run_id로 구분한다. Production Agent는 Agent.build_runtime()의 trace_A.jsonl을 쓴다.


SOURCE_DIR = Path(__file__).resolve().parent

DEFAULT_TRACE_PATH = SOURCE_DIR/"traces"/"trace_D5_EXP.jsonl"

# 각 fixture는 아래처럼 명시적으로 ``runtime=...``을 전달한다. E05/E06/E07만
# 하나의 ApprovalStore 상태를 공유해야 하므로 같은 Runtime을 쓴다.
execute_tool = _execute_tool


for attempt in range(1, 2):
    print(f"\n===== 반복 {attempt}/1 =====")

    D5_E01_RUN_ID = f"run-e1-{uuid.uuid4().hex}"
    D5_E02_RUN_ID = f"run-e2-{uuid.uuid4().hex}"
    D5_E03_RUN_ID = f"run-e3-{uuid.uuid4().hex}"
    D5_E04_RUN_ID = f"run-e4-{uuid.uuid4().hex}"
    D5_E05_RUN_ID = f"run-e5-{uuid.uuid4().hex}"  # E05, E06, E07 공유

    D5_E08_RUN_ID = f"run-e8-{uuid.uuid4().hex}"
    D5_E09_RUN_ID = f"run-e9-{uuid.uuid4().hex}"

    # 1. 사용자가 공유 폴더의 파일 읽기를 요청
    TEST_RUNTIME = build_runtime(trace_path=DEFAULT_TRACE_PATH)

    print(
        "\nEXP-E01: 사용자가 공유 폴더의 파일 읽기를 요청"
    )

    D5_E01_FIXTURE = {
        "tool_name": "read_file",
        "arguments": {
            "path": "data/shared/sharedbook.txt",
        },
        "actor": "user-001",
        "provenance": direct_user_provenance(
            "interactive-user"
        )
    }
    D5_E01_result = execute_tool(
        tool_name=D5_E01_FIXTURE["tool_name"],
        arguments=D5_E01_FIXTURE["arguments"],
        call_id="call-D5-E01",
        run_id=D5_E01_RUN_ID,
        actor=D5_E01_FIXTURE["actor"],
        provenance=D5_E01_FIXTURE["provenance"],
        runtime=TEST_RUNTIME
    )

    print(D5_E01_result)

    # E01 정상 수행 여부 확인
    assert D5_E01_result["ok"] is True
    assert D5_E01_result["status"] == "success"
    assert D5_E01_result["end_stage"] == "runtime"
    assert D5_E01_result["meta"]["policy_decision"] == "allow"
    assert D5_E01_result["meta"]["capability"] == "filesystem.read"
    assert D5_E01_result["meta"]["action"] == "read"
    assert D5_E01_result["meta"]["resource"] == "data/shared/sharedbook.txt"
    assert D5_E01_result["meta"]["trust"] == "user_controlled"
    assert D5_E01_result["meta"]["approval"] == "not_required"



#========================


    # 2. 사용자가 자신이 소유자인 폴더의 파일 읽기를 요청
    # 현재는 path 이름 == owner 이름이지만, 실제로는 DB에 resource owner를 등록해둬야 한다. 
    TEST_RUNTIME = build_runtime(trace_path=DEFAULT_TRACE_PATH)

    print(
        "\nEXP-E02: 사용자가 owner 파일 읽기를 요청"
    )

    D5_E02_FIXTURE = {
        "tool_name": "read_file",
        "arguments": {
            "path": "data/user-002/private.txt",
        },
        "actor": "user-002",
        "provenance": direct_user_provenance(
            "interactive-user"
        )
    }
    D5_E02_result = execute_tool(
        tool_name=D5_E02_FIXTURE["tool_name"],
        arguments=D5_E02_FIXTURE["arguments"],
        call_id="call-D5-E02",
        run_id=D5_E02_RUN_ID,
        actor=D5_E02_FIXTURE["actor"],
        provenance=D5_E02_FIXTURE["provenance"],
        runtime=TEST_RUNTIME
    )

    print(D5_E02_result)

    # E02 정상 수행 여부 확인
    assert D5_E02_result["ok"] is True
    assert D5_E02_result["status"] == "success"
    assert D5_E02_result["end_stage"] == "runtime"
    assert D5_E02_result["meta"]["policy_decision"] == "allow"
    assert D5_E02_result["meta"]["capability"] == "filesystem.read"
    assert D5_E02_result["meta"]["action"] == "read"
    assert D5_E02_result["meta"]["resource"] == "data/user-002/private.txt"
    assert D5_E02_result["meta"]["trust"] == "user_controlled"
    assert D5_E02_result["meta"]["approval"] == "not_required"


# ========================

    # 3. user-001이 user-002의 private file을 읽으려 한다.
    # Policy의 data read scope는 통과하지만 Authorization이 owner mismatch를 막는다.
    TEST_RUNTIME = build_runtime(trace_path=DEFAULT_TRACE_PATH)
    print("\nEXP-E03: cross-user private file read 차단")
    D5_E03_FIXTURE = {
        "tool_name": "read_file",
        "arguments": {"path": "data/user-002/private.txt"},
        "actor": "user-001",
        "provenance": direct_user_provenance("interactive-user"),
    }
    with patch.object(TEST_RUNTIME, "_dispatch", return_value="must-not-run") as dispatch:
        D5_E03_result = execute_tool(
            tool_name=D5_E03_FIXTURE["tool_name"],
            arguments=D5_E03_FIXTURE["arguments"],
            call_id="call-D5-E03",
            run_id=D5_E03_RUN_ID,
            actor=D5_E03_FIXTURE["actor"],
            provenance=D5_E03_FIXTURE["provenance"],
            runtime=TEST_RUNTIME,
        )
        assert dispatch.call_count == 0
    print(D5_E03_result)
    assert D5_E03_result["ok"] is False
    assert D5_E03_result["status"] == "forbidden"
    assert D5_E03_result["end_stage"] == "authorization"
    assert D5_E03_result["meta"]["policy_decision"] == "allow"
    assert D5_E03_result["meta"]["authorization_decision"] == "deny"
    assert D5_E03_result["meta"]["reason"] == "BASELINE_CAPABILITY_ALLOWED"
    assert D5_E03_result["meta"]["authorization_reason"] == "ACTOR_NOT_RESOURCE_OWNER"
    assert "approval_id" not in D5_E03_result["meta"]


    # 4. repository content에서 유래한 write 제안은 AuthZ 전에 Policy가 막는다.
    TEST_RUNTIME = build_runtime(trace_path=DEFAULT_TRACE_PATH)
    print("\nEXP-E04: untrusted provenance write 차단")
    D5_E04_FIXTURE = {
        "tool_name": "write_file",
        "arguments": {"path": "data/user-001/untrusted.txt", "content": "do not write"},
        "actor": "user-001",
        "provenance": repository_provenance("data/user-001/notes.txt"),
    }
    with patch.object(TEST_RUNTIME, "_dispatch", return_value="must-not-run") as dispatch:
        D5_E04_result = execute_tool(
            tool_name=D5_E04_FIXTURE["tool_name"],
            arguments=D5_E04_FIXTURE["arguments"],
            call_id="call-D5-E04",
            run_id=D5_E04_RUN_ID,
            actor=D5_E04_FIXTURE["actor"],
            provenance=D5_E04_FIXTURE["provenance"],
            runtime=TEST_RUNTIME,
        )
        assert dispatch.call_count == 0
    print(D5_E04_result)
    assert D5_E04_result["ok"] is False
    assert D5_E04_result["end_stage"] == "policy"
    assert D5_E04_result["meta"]["policy_decision"] == "deny"
    assert D5_E04_result["meta"]["reason"] == "UNTRUSTED_PROVENANCE_CANNOT_AUTHORIZE_TOOL"
    assert "authorization_decision" not in D5_E04_result["meta"]


    # 5. owner write의 첫 요청: Runtime이 pending approval record를 생성한다.
    # E06/E07은 이 Runtime의 ApprovalStore와 approval ID를 이어서 사용한다.
    APPROVAL_RUNTIME = build_runtime(trace_path=DEFAULT_TRACE_PATH)
    print("\nEXP-E05: owner write의 pending approval 생성")
    D5_E05_FIXTURE = {
        "tool_name": "write_file",
        "arguments": {"path": "data/user-001/day5_owner.txt", "content": "approved content"},
        "actor": "user-001",
        "provenance": direct_user_provenance("interactive-user"),
    }
    with patch.object(APPROVAL_RUNTIME, "_dispatch", return_value="must-not-run") as dispatch:
        D5_E05_result = execute_tool(
            tool_name=D5_E05_FIXTURE["tool_name"],
            arguments=D5_E05_FIXTURE["arguments"],
            call_id="call-D5-E05",
            run_id=D5_E05_RUN_ID,
            actor=D5_E05_FIXTURE["actor"],
            provenance=D5_E05_FIXTURE["provenance"],
            runtime=APPROVAL_RUNTIME,
        )
        assert dispatch.call_count == 0
    print(D5_E05_result)
    assert D5_E05_result["status"] == "approval_required"
    assert D5_E05_result["end_stage"] == "approval"
    assert D5_E05_result["meta"]["policy_decision"] == "approval_required"
    assert D5_E05_result["meta"]["authorization_decision"] == "allow"
    assert D5_E05_result["meta"]["approval"] == "pending"
    assert D5_E05_result["meta"]["required_approver"] == "user-001"
    D5_E05_APPROVAL_ID = D5_E05_result["meta"]["approval_id"]


    # 6. actor 본인이 승인한 뒤 같은 Intent와 approval ID를 재시도한다.
    print("\nEXP-E06: 승인된 동일 Intent를 한 번 실행")
    control = approve_pending_request(
        APPROVAL_RUNTIME.approvals,
        D5_E05_APPROVAL_ID,
        authenticated_approver="user-001",
    )
    assert control.changed is True
    assert control.state.status.value == "approved"
    with patch.object(APPROVAL_RUNTIME, "_dispatch", return_value="mocked owner write") as dispatch:
        D5_E06_result = execute_tool(
            tool_name=D5_E05_FIXTURE["tool_name"],
            arguments=D5_E05_FIXTURE["arguments"],
            call_id="call-D5-E06",
            run_id=D5_E05_RUN_ID,
            actor=D5_E05_FIXTURE["actor"],
            provenance=D5_E05_FIXTURE["provenance"],
            approval_id=D5_E05_APPROVAL_ID,
            runtime=APPROVAL_RUNTIME,
        )
        assert dispatch.call_count == 1
    print(D5_E06_result)
    assert D5_E06_result["ok"] is True
    assert D5_E06_result["meta"]["approval"] == "consumed"


    # 7. consumed ID의 재사용: Runtime은 새 pending request로 돌려도 Dispatcher는 부르지 않는다.
    print("\nEXP-E07: consumed approval ID replay 차단")
    with patch.object(APPROVAL_RUNTIME, "_dispatch", return_value="must-not-run") as dispatch:
        D5_E07_result = execute_tool(
            tool_name=D5_E05_FIXTURE["tool_name"],
            arguments=D5_E05_FIXTURE["arguments"],
            call_id="call-D5-E07",
            run_id=D5_E05_RUN_ID,
            actor=D5_E05_FIXTURE["actor"],
            provenance=D5_E05_FIXTURE["provenance"],
            approval_id=D5_E05_APPROVAL_ID,
            runtime=APPROVAL_RUNTIME,
        )
        assert dispatch.call_count == 0
    print(D5_E07_result)
    assert D5_E07_result["ok"] is False
    assert D5_E07_result["status"] == "approval_required"
    assert D5_E07_result["meta"]["approval"] == "pending"
    assert D5_E07_result["meta"]["approval_id"] != D5_E05_APPROVAL_ID


    # 8. shared member write는 허용 가능한 요청이지만 reviewer-001의 승인이 필요하다.
    TEST_RUNTIME = build_runtime(trace_path=DEFAULT_TRACE_PATH)
    print("\nEXP-E08: shared member write의 reviewer approval 요청")
    D5_E08_FIXTURE = {
        "tool_name": "write_file",
        "arguments": {"path": "data/shared/day5_team.txt", "content": "team note"},
        "actor": "user-003",
        "provenance": direct_user_provenance("interactive-user"),
    }
    with patch.object(TEST_RUNTIME, "_dispatch", return_value="must-not-run") as dispatch:
        D5_E08_result = execute_tool(
            tool_name=D5_E08_FIXTURE["tool_name"],
            arguments=D5_E08_FIXTURE["arguments"],
            call_id="call-D5-E08",
            run_id=D5_E08_RUN_ID,
            actor=D5_E08_FIXTURE["actor"],
            provenance=D5_E08_FIXTURE["provenance"],
            runtime=TEST_RUNTIME,
        )
        assert dispatch.call_count == 0
    print(D5_E08_result)
    assert D5_E08_result["status"] == "approval_required"
    assert D5_E08_result["meta"]["authorization_decision"] == "allow"
    assert D5_E08_result["meta"]["authorization_reason"] == "SHARED_WRITE_REQUIRES_REVIEWER"
    assert D5_E08_result["meta"]["required_approver"] == "reviewer-001"


    # 9. approved ID라도 content가 바뀌면 fingerprint가 달라 새 approval이 필요하다.
    FINGERPRINT_RUNTIME = build_runtime(trace_path=DEFAULT_TRACE_PATH)
    print("\nEXP-E09: changed content fingerprint 재사용 차단")
    D5_E09_ORIGINAL = {
        "tool_name": "write_file",
        "arguments": {"path": "data/user-001/day5_fingerprint.txt", "content": "original"},
        "actor": "user-001",
        "provenance": direct_user_provenance("interactive-user"),
    }
    D5_E09_PENDING = execute_tool(
        tool_name=D5_E09_ORIGINAL["tool_name"],
        arguments=D5_E09_ORIGINAL["arguments"],
        call_id="call-D5-E09-pending",
        run_id=D5_E09_RUN_ID,
        actor=D5_E09_ORIGINAL["actor"],
        provenance=D5_E09_ORIGINAL["provenance"],
        runtime=FINGERPRINT_RUNTIME,
    )
    D5_E09_APPROVAL_ID = D5_E09_PENDING["meta"]["approval_id"]
    approve_pending_request(
        FINGERPRINT_RUNTIME.approvals,
        D5_E09_APPROVAL_ID,
        authenticated_approver="user-001",
    )
    D5_E09_CHANGED_FIXTURE = {
        **D5_E09_ORIGINAL,
        "arguments": {"path": "data/user-001/day5_fingerprint.txt", "content": "changed"},
    }
    with patch.object(FINGERPRINT_RUNTIME, "_dispatch", return_value="must-not-run") as dispatch:
        D5_E09_result = execute_tool(
            tool_name=D5_E09_CHANGED_FIXTURE["tool_name"],
            arguments=D5_E09_CHANGED_FIXTURE["arguments"],
            call_id="call-D5-E09-changed",
            run_id=D5_E09_RUN_ID,
            actor=D5_E09_CHANGED_FIXTURE["actor"],
            provenance=D5_E09_CHANGED_FIXTURE["provenance"],
            approval_id=D5_E09_APPROVAL_ID,
            runtime=FINGERPRINT_RUNTIME,
        )
        assert dispatch.call_count == 0
    print(D5_E09_result)
    assert D5_E09_result["ok"] is False
    assert D5_E09_result["status"] == "approval_required"
    assert D5_E09_result["meta"]["approval_id"] != D5_E09_APPROVAL_ID


print("\nDay 5 E01~E09 fixture tests: PASS")
