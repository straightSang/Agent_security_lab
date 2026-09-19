# Day 9 변경 뒤에도 기존 보안 경계가 우회되지 않는지 확인하는 회귀 검사.
#
# 각 동적 검사는 독립적인 Runtime, sandbox, trace를 사용하며 seed, 평가, 최종 증거 요약을 남긴다.
# 이 파일은 외부 API나 실제 서비스에 연결하지 않는다.


from __future__ import annotations

# [경로 부트스트랩] src/를 import 경로에 넣는 일은 아래 프로젝트 import보다 반드시
# 먼저 일어나야 한다. 이 파일은 모듈 최상위에서 바로 실행되는 형태라 진입점 블록이
# 없고, 그래서 경로 설정을 넣을 다른 자리가 없다. pytest로 돌릴 때는 루트
# conftest.py가 같은 일을 하므로 여기서는 중복을 피한다.
#
# 이 블록 때문에 아래 import가 파일 최상단에 오지 못하므로 E402를 끈다.
# ruff: noqa: E402
import sys
from pathlib import Path

if str(Path(__file__).resolve().parents[1] / "src") not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import ast
import json
from unittest.mock import patch

from agent import execute_tool
from approval_control import approve_pending_request
from experiment_support import make_experiment_runtime, record_run_evidence
from lab_paths import trace_root
from security.evaluator import evaluate_run, CANARY_MARKER
from security.provenance import direct_user_provenance, repository_provenance
from security.types import ApprovalStatus, AuthorizationDecision, AuthorizationOutcome
from security.tool_schema import validate_tool_schema, MCP_TOOL_CATALOG, READ_ONLY_PROFILE
# [C-02] 단일 트리 구조에서 fixture/schema는 저장소 루트에 있다.
# [C-03] trace 기본 출력은 저장소가 아니라 tmp다(lab_paths.trace_root()).
PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIR = PROJECT_ROOT / "src"
TRACE_BASE = trace_root() / "trace_D9_INVARIANTS.jsonl"
ACTOR = "user-001"


# 함수이름: assert_no_direct_dispatch_call
# 인자: 없음
# 반환값:
#     None: 반환값 없음
#     AssertionError: Runtime 밖에서 _dispatch()를 부르는 코드가 있을 때 발생
# 기능 설명:
#     소스 전체를 AST로 훑어 _dispatch()를 직접 호출하는 곳이 없는지 확인한다.
#
#     실행 시점 검사로는 "이번 실행에서 우회가 없었다"만 알 수 있다. 코드에
#     우회 경로가 존재하는지는 소스를 봐야 한다. "유일한 실행 경계"라는 주장은
#     구조에 대한 주장이므로 구조로 검증한다.
def assert_no_direct_dispatch_call() -> None:
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


# 함수이름: assert_no_legacy_authorizer
# 인자: 없음
# 반환값:
#     None: 반환값 없음
#     AssertionError: 옛 인가 경로가 남아 있을 때 발생
# 기능 설명:
#     이전 버전의 인가 함수가 코드에 남아 있지 않은지 확인한다.
#
#     쓰지 않는 옛 경로가 남아 있으면 나중에 누군가 그것을 다시 호출한다. 죽은
#     코드는 삭제되기 전까지 잠재적 우회 경로다.
def assert_no_legacy_authorizer() -> None:
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


# 함수이름: check_policy_deny_short_circuit
# 인자: 없음
# 반환값:
#     dict: 실험 증거와 평가 결과
#     AssertionError: Policy DENY 뒤에 후속 관문이 호출될 때 발생
# 기능 설명:
#     [D9-E07] Policy가 거부한 뒤 Authorization·승인·Dispatcher가 0회
#     호출되는지 확인한다.
#
#     거부 뒤에 후속 단계가 돌면 그 단계들이 부작용을 남길 수 있다. 예를 들어
#     승인 저장소를 건드리면 거부된 요청에 승인 ID가 발급된다. 거부는 그 자리에서
#     끝나야 한다.
def check_policy_deny_short_circuit() -> dict:
    experiment = make_experiment_runtime(
        "D9-E07", trace_path=TRACE_BASE, seed_files=()
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
            call_id="call-d9-e07-policy-deny",
            run_id=experiment.run_id,
            actor=ACTOR,
            provenance=repository_provenance("synthetic-untrusted-input"),
            fixture_id="D9-E07",
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
    assert evaluation.canary_leak is False, "카나리 탐지기가 유출 건을 놓침"
    return {**record_run_evidence(experiment), **evaluation.to_dict()}


# 함수이름: check_authorization_deny_short_circuit
# 인자: 없음
# 반환값:
#     dict: 실험 증거와 평가 결과
#     AssertionError: AuthZ DENY 뒤에 승인 ID가 발급되거나 실행될 때 발생
# 기능 설명:
#     [D9-E08] 인가가 거부한 뒤 승인 레코드가 만들어지지 않는지 확인한다.
#
#     자격이 없는 actor에게 승인 ID가 발급되면, 승인자를 속이거나 다른 경로로
#     승인을 얻어 실행할 여지가 생긴다. 자격 없는 요청은 승인 대상 자체가 되면
#     안 된다.
def check_authorization_deny_short_circuit() -> dict:
    experiment = make_experiment_runtime(
        "D9-E08",
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
            call_id="call-d9-e08-authz-deny",
            run_id=experiment.run_id,
            actor=ACTOR,
            provenance=direct_user_provenance("fixture-harness"),
            fixture_id="D9-E08",
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
    assert evaluation.canary_leak is False, "카나리 탐지기가 유출 건을 놓침"
    
    return {**record_run_evidence(experiment), **evaluation.to_dict()}



# 함수이름: check_approval_consume_and_replay
# 인자: 없음
# 반환값:
#     dict: 실험 증거와 평가 결과. consume/dispatch 호출 순서를 포함한다
#     AssertionError: 소비 순서가 어긋나거나 재사용이 실행될 때 발생
# 기능 설명:
#     [D9-E09] 승인이 dispatch 직전에 1회만 소비되고, 같은 ID 재제출은
#     실행되지 않는지 확인한다.
#
#         1. 승인 전에는 실행되지 않는다      (dispatch 0회)
#         2. consume이 dispatch보다 먼저다    (call_order 검사)
#         3. 같은 ID 재제출은 실행되지 않는다 (replay dispatch 0회)
#
#     dispatch 뒤에 소비하면 그 사이에 같은 승인으로 또 실행할 수 있는 창이
#     생긴다. 순서 자체가 방어다.
def check_approval_consume_and_replay() -> dict:
    experiment = make_experiment_runtime(
        "D9-E09", trace_path=TRACE_BASE, seed_files=()
    )
    runtime = experiment.runtime
    arguments = {
        "path": "data/user-001/approved-once.txt",
        "content": "one dispatch only"
    }

    with patch.object(runtime, "_dispatch", wraps=runtime._dispatch) as pending_dispatch:
        pending = execute_tool(
            "write_file",
            arguments,
            call_id="call-d9-e09-pending",
            run_id=experiment.run_id,
            actor=ACTOR,
            provenance=direct_user_provenance("fixture-harness"),
            fixture_id="D9-E09",
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

    # 함수이름: tracked_consume
    # 인자:
    #     *args, **kwargs: ApprovalStore.consume()에 그대로 전달된다
    # 반환값:
    #     tuple[ApprovalState, bool]: 원래 consume()의 반환값 그대로
    # 기능 설명:
    #     consume 호출 시각을 call_order에 남기는 얇은 래퍼다. 동작은 바꾸지
    #     않고 순서만 관측한다.
    #
    #     "consume이 dispatch보다 먼저"라는 것이 replay 차단의 핵심이다.
    #     호출 횟수만 세면 순서가 뒤바뀐 경우를 잡지 못한다.
    def tracked_consume(*args, **kwargs):
        call_order.append("consume")
        return original_consume(*args, **kwargs)


    # 함수이름: tracked_dispatch
    # 인자:
    #     *args, **kwargs: Runtime._dispatch()에 그대로 전달된다
    # 반환값:
    #     str: 원래 _dispatch()의 반환값 그대로
    # 기능 설명:
    #     dispatch 호출 시각을 call_order에 남기는 얇은 래퍼다.
    #     tracked_consume과 짝을 이뤄 소비-실행 순서를 검증한다.
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
            call_id="call-d9-e09-approved",
            run_id=experiment.run_id,
            actor=ACTOR,
            provenance=direct_user_provenance("fixture-harness"),
            approval_id=approval_id,
            fixture_id="D9-E09",
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
            call_id="call-d9-e09-replay",
            run_id=experiment.run_id,
            actor=ACTOR,
            provenance=direct_user_provenance("fixture-harness"),
            approval_id=approval_id,
            fixture_id="D9-E09",
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
    assert evaluation.canary_leak is False, "카나리 탐지기가 유출 건을 놓침"

    return {
        **record_run_evidence(experiment),
        **evaluation.to_dict(),
        "consume_before_dispatch": call_order == ["consume", "dispatch"],
        "successful_dispatch_count": 1,
        "replay_dispatch_count": replay_dispatch.call_count,
    }


# 함수이름: check_write_no_create_directory
# 인자: 없음
# 반환값:
#     dict: 실험 증거와 평가 결과.
#     AssertionError: 쓰기가 성공하거나 디렉터리가 생겼을 때 발생
# 기능 설명:
#     [D9-E10] 선언되지 않은 디렉터리에 쓰기를 시도했을 때 쓰기가 거부되고,
#     그 디렉터리도 생기지 않는지 확인한다.

#     [방어 성공 확인 조건]
#         1. 쓰기 실패
#         2. 디렉터리가 생성되지 않았다. **중요**
#       
#     [테스트가 왜 필요한가]
#       현재 AuthorizationEngine은 data/{actor}/ 라는 형식의 디렉터리 이름으로 
#       리소스 소유권 및 접근권한을 판정한다. 쓰기가 디렉터리를 만들 수 있으면 소유자 영역을 
#       스스로 만들어 낼 수 있게 되고, Authorization 규칙이 무의미해진다.
#
def check_write_no_create_directory() -> dict:
    experiment = make_experiment_runtime(
            "D9-E10", trace_path=TRACE_BASE, seed_files=()
        )
    runtime = experiment.runtime

    # target_dir: 선언되지 않은 폴더
    target_dir = experiment.sandbox_root / "data" / "user-001" / "subdir"
    assert not target_dir.exists(), "폴더 생성됨: test broken"

    # 경로는 세 번 쓰이므로 한 곳에만 적는다. 흩어지면 반드시 어긋난다.
    arguments = {
        "path": "data/user-001/subdir/notes.txt",
        "content": "선언되지 않은 디렉터리",
    }

    # 1. 승인요청 만들기
    result = execute_tool(
        "write_file",
        arguments,
        call_id="call-d9-e10-pending",
        run_id=experiment.run_id,
        actor=ACTOR,
        provenance=direct_user_provenance("fixture-harness"),
        fixture_id="D9-E10",
        runtime=runtime
    )
    assert result["status"] == "approval_required", result["status"]
    approval_id = result["meta"]["approval_id"]

    # 2. 승인하기
    approve_pending_request(
        runtime.approvals, approval_id, authenticated_approver=ACTOR
    )

    # 3. 승인을 들고 재시도. approval_id가 있어야 승인 관문을 지나 _write_file까지 간다.
    with patch.object(runtime, "_dispatch", wraps=runtime._dispatch) as dispatch:
        result_2 = execute_tool(
            "write_file",
            arguments,
            call_id="call-d9-e10-approved",
            run_id=experiment.run_id,
            actor=ACTOR,
            provenance=direct_user_provenance("fixture-harness"),
            approval_id=approval_id,
            fixture_id="D9-E10",
            runtime=runtime
        )


    # 1) 쓰기에 실패한 게 맞는지 확인
    assert result_2["ok"] is False, "선언되지 않은 디렉터리에 쓰기가 성공했다"
    assert result_2["end_stage"] == "runtime", result_2["end_stage"]

    # 2) 디렉터리가 안 생긴 게 맞는지 확인 **중요**
    assert not target_dir.exists(), "도구가 선언되지 않은 디렉터리를 만들었다"

    # 3) 방어의 위치를 고정한다.
    #    이 요청은 관문 다섯 개를 모두 정당하게 통과한다(자기 폴더 + 승인 완료).
    #    따라서 _dispatch는 반드시 한 번 불려야 하고, 막히는 지점은 그 안쪽이다.
    #    0이 나오면 방어가 관문 쪽으로 옮겨진 것이므로 이 테스트의 전제가 달라진다.
    assert dispatch.call_count == 1, (
        f"관문을 다 통과했으므로 실행 시도는 1회여야 한다 (실제 {dispatch.call_count}회)"
    )

    return {
        **record_run_evidence(experiment),
        "target_dir_created": target_dir.exists(),
        "dispatch_count": dispatch.call_count,
        "final_status": result_2["status"]
    }

# 함수이름: check_internal_invariant_violation_recorded
# 인자: 없음
# 반환값:
#     dict: 실험 증거와 평가 결과.
#     AssertionError: 쓰기가 성공하거나 디렉터리가 생겼을 때 발생
# 기능 설명:
#     [D9-E11] AuthorizationEngine은 쓰기에 대해 항상 required_approver를 붙여서 
#       ALLOW를 낸다. 따라서 ALLOW 결정이 났음에도 승인자가 없는 쓰기 동작은 정상 실행 경로가 아니다.
#       이 분기를 검사하기 위해서는 인가 엔진을 가짜로 대체해야 하며, 이를 통해 
#       에러 상황에서도 로그가 정상 기록되는지 확인한다.
#       * 16번 불변조건: 내부 불변조건 위반의 경우도 중단시키지 않고 결과와 trace를 남긴 뒤 거부하도록 한다. *
#     

#     [확인 조건]
#         1. 예외로 죽지 않고 결과가 반환되었다
#         2. trace에 기록이 남았다 **중요**
#       
#     [테스트가 왜 필요한가]
#       이상현상이 발생한 순간의 로그(증거)가 남아있어야 사후 원인 파악 및 대처가 가능하다. 
#
def check_internal_invariant_violation_recorded() -> dict:
    experiment = make_experiment_runtime("D9-E11", trace_path=TRACE_BASE, seed_files=())
    runtime = experiment.runtime

    # 가짜 판정서 
    forced = AuthorizationDecision( 
        outcome=AuthorizationOutcome.ALLOW, reason="FORCED_TEST", actor=ACTOR, 
        action="write", resource="data/user-001/invariant.txt", required_approver=None )

    with patch.object(runtime.authorizer, "authorize", return_value=forced):
        result = execute_tool(
            "write_file", {"path": "data/user-001/invariant.txt", "content": "모순상태"}, 
            call_id="call-d9-e11-invariant",            
            run_id=experiment.run_id,
            actor=ACTOR,
            provenance=direct_user_provenance("fixture-harness"),
            fixture_id="D9-E11",
            runtime=runtime )

    # 가짜 판정서를 넣었을 때

    # 1) 예외로 인해 종료되지 않았음
    assert result["ok"] is False
    assert result["status"] == "internal_invariant_violation"
    assert result["end_stage"] == "approval"
    assert result["error"]["code"] == "MISSING_REQUIRED_APPROVER" # types.pt::to_dict() 참조

    # 2) trace에 기록이 남음
    events = list(runtime.trace.iter_events(run_id=experiment.run_id, strict=True))
    assert any(e["event"] == "runtime_result" for e in events), ("불변조건 위반이 trace에 기록되지 않고 있다")

    evaluation = evaluate_run(events, expected_decision="allow")
    assert evaluation.canary_leak is False, "카나리 탐지기가 유출 건을 놓침"
    assert evaluation.trace_completeness is True, "가짜 이벤트 필수 필드가 누락됨. 수정 필요." 

    return {
        **record_run_evidence(experiment),
        "event_count": len(events),
        "final_status":result["status"]
    }


# 13번 불변조건
# 함수이름: test_canary_detector_catched_leak
# 반환값:
#     None: 반환값 없음
#     AssertionError: 카나리가 있는데 canary_leak=False 로 오판정할 때 발생
# 기능 설명:
#      [13번] 카나리가 유출된 실행에서 canary_leak=True가 맞는지 확인한다.
def test_canary_detector_catched_leak() -> None:
    run_id = "run-canary-test"
    call_id = "call-canary-test"

    events = [

        {   
            "event": "tool_schema_decision",
            "event_id": "evt_canary_1",
            "timestamp": "2026-09-13T00:00:00+00:00",
            "run_id": run_id,
            "call_id": call_id,
            "tool_schema_decision": "allow",
            "tool_schema_reason": "MCP_TOOL_SCHEMA_ALLOWED",
            "tool_profile": "read_only",
            "tool_schema_digest": "sha256:test"
        },
        {
            "event": "policy_decision",
            "event_id": "evt_canary_2",
            "timestamp": "2026-09-13T00:00:01+00:00",
            "run_id": run_id,
            "call_id": call_id,
            "policy_decision": "allow",
            "reason": "TEST",
            "rule_id": "TEST",
            "trust": "user_controlled",
            "capability": "filesystem.read",
            "action": "read"
        },
        {
            "event": "runtime_result",
            "event_id": "evt_canary_3",
            "timestamp": "2026-09-13T00:00:02+00:00",
            "run_id": run_id,
            "call_id": call_id,
            "ok": True,
            "runtime_status": "ok",
            "end_stage": "dispatch",
            "data": f"leaked: {CANARY_MARKER}"
        }
    ]   

    evaluation = evaluate_run(events, expected_decision="allow")
    assert evaluation.canary_leak is True, "카나리 탐지기가 유출 건을 놓침"
    assert evaluation.trace_completeness is True, "가짜 이벤트 필수 필드가 누락됨. 수정 필요." 


# 13번 불변조건
# 함수이름: test_canary_detector_reports_clean_run
# 인자: 없음
# 반환값:
#     None: 반환값 없음
#     AssertionError: 카나리가 유출되지 않았는데 canary_leak=True 로 오판정할 때 발생
# 기능 설명:
#      [13번] 카나리가 유출되지 않은 실행에서 canary_leak=False가 맞는지 확인한다.
#       test_canary_dtector_catches_leak은 카나리가 유출된 실행에서 canary_leak=True가 맞는지 확인한다.
#       둘 중 하나만 있으면 canary_leak이 항상 같은 값을 반환해도 통과한다.
def test_canary_detector_reports_clean_run() -> None:
    run_id = "run-canary-clean"
    call_id = "call-canary-clean"

    events = [
        {
            "event": "tool_schema_decision",
            "event_id": "evt_clean_1",
            "timestamp": "2026-09-13T00:00:00+00:00",
            "run_id": run_id,
            "call_id": call_id,
            "tool_schema_decision": "allow",
            "tool_schema_reason": "MCP_TOOL_SCHEMA_ALLOWED",
            "tool_profile": "read_only",
            "tool_schema_digest": "sha256:test"
        },
        {
            "event": "policy_decision",
            "event_id": "evt_1",
            "timestamp": "2026-09-13T00:00:01+00:00",
            "run_id": run_id,
            "call_id": call_id,
            "policy_decision": "allow",
            "reason": "TEST",
            "rule_id": "TEST",
            "trust": "user_controlled",
            "capability": "filesystem.read",
            "action": "read"
        },
        {
            "event": "runtime_result",
            "event_id": "evt_3",
            "timestamp": "2026-09-13T00:00:02+00:00",
            "run_id": run_id,
            "call_id": call_id,
            "ok": True,
            "runtime_status": "ok",
            "end_stage": "dispatch",
            "data": "카나리 없음. 테스트용"
        }
    ]

    evaluation = evaluate_run(events, expected_decision="allow")
    assert evaluation.canary_leak is False, "카나리가 없는데 유출로 판정함."
    assert evaluation.trace_completeness is True



# 13번 불변조건
# 함수이름: check_blocked_secret_read_not_leak
# 인자: 없음
# 반환값:
#     None: 반환값 없음
#     AssertionError: 읽기가 성공하거나 카나리가 leak됐을 때 발생한다.
# 기능 설명:
#      [D9-E12] sandbox/secret/dome.env 읽기가 막히고, 그 과정에서 카나리가 trace에 기록되지는 않는지 확인한다.
#      막혔어도 카나리가 샐 수 있으므로 확인해야 한다. 
def check_blocked_secret_read_not_leak() -> dict:
    experiment = make_experiment_runtime(
        "D9-E12",
        trace_path=TRACE_BASE,
        seed_files=("secret/dome.env",)  # 카나리가 들어있는 파일
    )
    runtime = experiment.runtime

    with patch.object(runtime, "_dispatch", wraps=runtime._dispatch) as dispatch:
        result = execute_tool(
            "read_file",
            {"path": "secret/dome.env"},
            call_id="call-d9-e12-secret-read",
            run_id=experiment.run_id,
            actor=ACTOR,
            provenance=direct_user_provenance("fixture_harness"),
            fixture_id="D9-E12",
            runtime=runtime
        )

    # 1) .env 파일의 읽기가 거부되었는지 확인
    assert result["ok"] is False, ".env 파일 읽기가 성공했다. 코드 수정 요망."
    assert dispatch.call_count == 0, "표면적으로는 파일 읽기가 차단되었으나 실제로는 실행되었다."

    # 2) 카나리가 trace로 새지 않았다.
    evaluation = evaluate_run(
        runtime.trace.iter_events(run_id=experiment.run_id, strict=True),
        expected_decision="deny",
        unsafe_fixture=True
    )
    assert evaluation.canary_leak is False, "차단됐는데 카나리가 새어나갔다."
    assert evaluation.trace_completeness is True

    return {**record_run_evidence(experiment), **evaluation.to_dict()}


# 7번 불변 조건
# 함수이름: test_legacy_compat_not_default
# 인자: 없음
# 반환값:
#     None: 반환값 없음
#     AssertionError: legacy_compat 을 기본 인자로 쓰는 함수가 있을 때 발생한다. 
# 기능 설명:
#      [7번] src/의 함수 중 하나가 LEGACY_COMPAT_PROFILE을 기본인자로 사용하고 있지는 않은지 확인한다. 
#       
#      [기존 규칙과의 차이점] 불변조건 7번은 LEGACY_COMPAT_PROFILE는 회귀(test)조건에서만 명시적인 형태로
#       사용한다는 조건이 붙는다. 하지만 이는 코드가 판단할 수 없다. 따라서 LEGACY_COMPAT_PROFILE는 
#       절대 기본값으로 써서는 안 된다. 기본값이 되는 순간 모든 권한을 허용하는 것이 기본값이 되기 때문이다. 
#          
#       [한계] 이 함수는 LEGACY_COMPAT_PROFILE이 기본값으로 설정되어 있는지 아닌지만 판단한다.
def test_legacy_compat_not_default() -> None:
    violations: list[str] = []

    for path in SOURCE_DIR.rglob("*.py"):
        if "venv" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            defaults = list(node.args.defaults) + list(node.args.kw_defaults)
            for default in defaults:
                if default is None:
                    continue
                if isinstance(default, ast.Name) and default.id == "LEGACY_COMPAT_PROFILE":
                    violations.append(
                        f"{path.relative_to(SOURCE_DIR)}:{node.lineno} {node.name}()"
                    )

    assert not violations, (
        "legacy_compat이 기본 인자로 쓰이고 있다. 당장 기본 프로필 권한 설정을 변경하라."
        ":\n  - " + "\n  - ".join(violations)
    )

# 4번 불변 조건
# 함수이름: test_annotation_not_read_policy
# 인자: 없음
# 반환값:
#     None: 반환값 없음
#     AssertionError: 판정 모듈이 annotations를 참조할 때 발생한다. 
# 기능 설명:
#      [4번] 권한을 판정하는 모듈이 MCP annotations를 읽지는 않는지 확인한다.
#
#       readOnlyHint 같은 값은 도구를 제공하는 쪽이 스스로 적은 항목에 불과하다.
#       서버가 신뢰해야 하는 것은 _meta의 capability와 자체 catalog 뿐이어야 한다.
#
#      [검사 대상에서 tool_schema.py가 제외된 이유]
#       해당 파일은 catalog 정의 자체를 담고 있기 때문에 annotation을 갖고있는 것이 정상이다.
#       문제는 그 값을 갖고 있는 것이 아니라 판정에 사용하는 것이다.
def test_annotation_not_read_policy() -> None:
    decision_modules = (
        "policy.py", "authorization.py", "permission.py",
        "capability.py", "approval.py", "trust.py"
    )
    violations: list[str] = []

    for path in (SOURCE_DIR / "security").rglob("*.py"):
        if path.name not in decision_modules:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            # "annotations" 라는 문자열 상수를 사용하는 곳
            if isinstance(node, ast.Constant) and node.value == "annotations":
                violations.append(f"{path.name}:{node.lineno}")
            # .annotations 속성 접근
            if isinstance(node, ast.Attribute) and node.attr == "annotations":
                violations.append(f"{path.name}:{node.lineno}")

    assert not violations, (
        "판정 모듈이 annotations를 참조한다. 도구의 자기소개가 권한의 근거가 되고 있다."
        "\n  - " + "\n  - ".join(violations)
    )


# 4번 불변 조건
# 함수이름: test_flipping_annotation_not_change_decision
# 인자: 없음
# 반환값:
#     None: 반환값 없음
#     AssertionError: annotations를 바꿨더니 판정이 달라질 때 발생한다. 
# 기능 설명:
#      [4번] catalog의 annotations를 반대로 뒤집어도 schema gate의 판정이 달라지지 않는지 확인한다.
#
#       정적 검사(test_annotation_not_read_policy)와 짝을 이룬다.
#       정적 검사는 "코드에 없다"는 것을, 이 함수는 "실제로 영향을 미치지 않는다"는 것을 확인한다.
def test_flipping_annotation_not_change_decision() -> None:
    args = {"path": "data/user-001/notes.txt"}

    before = validate_tool_schema(READ_ONLY_PROFILE, "read_file", args)

    original = MCP_TOOL_CATALOG["read_file"]["annotations"]["readOnlyHint"]

    try:
        MCP_TOOL_CATALOG["read_file"]["annotations"]["readOnlyHint"] = not original
        after = validate_tool_schema(READ_ONLY_PROFILE, "read_file", args)

    finally:
        MCP_TOOL_CATALOG["read_file"]["annotations"]["readOnlyHint"] = original

    assert before.allowed == after.allowed, "annotations가 판정을 바꿨다."
    assert before.reason == after.reason, "annotations가 사유를 바꿨다." 
# ===========================================================================
# pytest 진입점
#
# 위의 check_* 함수 다섯 개는 각자 자기 Runtime과 sandbox를 만든다. 
# 즉 이미 독립된 실험이며, 아래는 pytest 수행용이다.
#
# [왜 나누는가]
#     하나로 묶여 있으면 첫 검사가 실패한 순간 나머지는 실행되지 않는다.
#     무엇이 깨졌는지뿐만이 아니라 무엇이 아직 멀쩡한지도 확인하기 위함이다.
#
# [증거 합본은 main()에 남긴다]
#     세 동적 검사는 dict를 반환하고, 그 합본이 보고서가 인용하는 단위다.
#     pytest는 반환값을 쓰지 않으므로 합본은 main()에서만 만든다.
# ===========================================================================


# 함수이름: test_no_direct_dispatch_call
# 인자: 없음
# 반환값:
#     None: 반환값 없음
#     AssertionError: Runtime 밖에서 _dispatch()를 부르는 코드가 있을 때 발생
# 기능 설명:
#     소스를 실행하지 않고 AST로만 확인하는 정적 검사다. 아래 동적 검사들과
#     실패 원인이 전혀 다르므로 따로 센다.
def test_no_direct_dispatch_call() -> None:
    assert_no_direct_dispatch_call()


# 함수이름: test_no_legacy_authorizer
# 인자: 없음
# 반환값:
#     None: 반환값 없음
#     AssertionError: 옛 인가 경로가 남아 있을 때 발생
# 기능 설명:
#     죽은 우회 경로가 소스에 남아 있지 않은지 확인하는 정적 검사다.
def test_no_legacy_authorizer() -> None:
    assert_no_legacy_authorizer()


# 함수이름: test_policy_deny_short_circuits
# 인자: 없음
# 반환값:
#     None: 반환값 없음
#     AssertionError: Policy DENY 뒤에 후속 관문이 호출될 때 발생
# 기능 설명:
#     [D9-E07] Policy 거부 뒤 AuthZ, 승인, Dispatcher가 0회 호출되는지 본다.
def test_policy_deny_short_circuits() -> None:
    check_policy_deny_short_circuit()


# 함수이름: test_authorization_deny_short_circuits
# 인자: 없음
# 반환값:
#     None: 반환값 없음
#     AssertionError: AuthZ DENY 뒤에 승인 ID가 발급될 때 발생
# 기능 설명:
#     [D9-E08] 자격 없는 요청이 승인 대상 자체가 되지 않는지 본다.
def test_authorization_deny_short_circuits() -> None:
    check_authorization_deny_short_circuit()


# 함수이름: test_approval_consumed_once_and_replay_blocked
# 인자: 없음
# 반환값:
#     None: 반환값 없음
#     AssertionError: 소비 순서가 어긋나거나 재사용이 실행될 때 발생
# 기능 설명:
#     [D9-E09] 승인이 dispatch 직전에 1회만 소비되고 재제출은 막히는지 본다.
def test_approval_consumed_once_and_replay_blocked() -> None:
    check_approval_consume_and_replay()


# 함수이름: test_write_no_create_directory
# 인자: 없음
# 반환값:
#     None: 반환값 없음
#     AssertionError: 쓰기 작업이 성공하거나 디렉터리가 생성됐을 때 발생
# 기능 설명:
#     [D9-E10] 존재하지 않는 디렉터리에 쓰기 작업을 시도할 때 디렉터리가 새로 생성되지는 않는지 확인한다.
def test_write_no_create_directory() -> None:
    check_write_no_create_directory()


# 함수이름: test_internal_invariant_violation_recorded
# 인자: 없음
# 반환값:
#     None: 반환값 없음
#     AssertionError: 
#           1. ALLOW 결정이 났음에도 승인자가 없는 쓰기 동작이 정상실행됐을 때
#           2. 실패 사유가 MISSING_REQUIRED)APPROVER가 아니다
#           3. trace에 결과가 기록되지 않았다
# 기능 설명:
#     [D9-E11] AuthorizationOutcome.ALLOW 임에도 APPROVER=None 일 때, 
#      예외로 인해 죽지않고, 거부 결과와 trace를 남기는지 확인한다.  
def test_internal_invariant_violation_recorded() -> None:
    check_internal_invariant_violation_recorded()


def test_blocked_secret_read_not_leak() -> None:
    check_blocked_secret_read_not_leak()


# 함수이름: main
# 인자: 없음
# 반환값:
#     None: 반환값 없음
# 기능 설명:
#     직접 실행 진입점. pytest가 세는 다섯 검사를 같은 순서로 돌리되, 세 동적
#     검사의 반환값을 모아 증거 합본을 출력한다.
#
#     pytest는 테스트 함수의 반환값을 버리므로 합본을 만들 수 없다. 보고서에
#     인용할 JSON이 필요할 때는 이 경로를 쓴다.
def main() -> None:
    assert_no_direct_dispatch_call()
    assert_no_legacy_authorizer()

    results = {
        "D9-E07": check_policy_deny_short_circuit(),
        "D9-E08": check_authorization_deny_short_circuit(),
        "D9-E09": check_approval_consume_and_replay(),
        "D9-E10": check_write_no_create_directory(),
        "D9-E11": check_internal_invariant_violation_recorded(),
        "D9-E12": check_blocked_secret_read_not_leak()
    }

    print(json.dumps(results, ensure_ascii=False, indent=2))
    print("Day 9 security invariant tests: PASS")


if __name__ == "__main__":
    main()
