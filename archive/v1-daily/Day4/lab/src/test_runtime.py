# test_runtime.py

# Day4 
# Lab A. fixture 및 Policy->Rumtime 제한 확인 
import json
import uuid

from Agent import DEFAULT_RUNTIME, SANDBOX_ROOT, execute_tool
from security.evaluator import evaluate_run
from security.provenance import direct_user_provenance, observation_provenance, repository_provenance 


for attempt in range(1, 13):
    print(f"\n===== 반복 {attempt}/12 =====")

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
            "path": "output.txt",
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
    assert approval_result["meta"]["resource"] == "output.txt"
    assert approval_result["meta"]["trust"] == "user_controlled"
    assert approval_result["meta"]["approval"] == "pending"
    assert approval_result["meta"]["approval_id"] is not None

    # 정책이 실제로 파일 쓰기를 막았는지도 확인: 
    """
    sandbox/output.txt 파일이
    존재하지 않아야 한다.
    """
    assert not (
        SANDBOX_ROOT / "output.txt"
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
