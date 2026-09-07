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
from security.evaluator import evaluate_run
from security.provenance import direct_user_provenance, repository_provenance
from security.types import ApprovalStatus

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
        "content": "one dispatch only",
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
    return {
        **record_run_evidence(experiment),
        **evaluation.to_dict(),
        "consume_before_dispatch": call_order == ["consume", "dispatch"],
        "successful_dispatch_count": 1,
        "replay_dispatch_count": replay_dispatch.call_count,
    }

# ===========================================================================
# pytest 진입점
#
# 위의 check_* 함수 다섯 개는 각자 자기 Runtime과 sandbox를 만든다. 
# 즉 이미 독립된 실험이며, 아래는 pytest 수행용이다.
#
# [왜 다섯으로 나누는가]
#     하나로 묶여 있으면 첫 검사가 실패한 순간 나머지 넷은 실행되지 않는다.
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
    }

    print(json.dumps(results, ensure_ascii=False, indent=2))
    print("Day 9 security invariant tests: PASS")


if __name__ == "__main__":
    main()
