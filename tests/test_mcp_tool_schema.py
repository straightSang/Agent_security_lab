# Day 9 MCP tool schema, least privilege fixture 실험.


from __future__ import annotations

# [경로 부트스트랩] src/를 import 경로에 넣는 일은 아래 프로젝트 import보다 반드시
# 먼저 일어나야 한다. 이 파일에는 __main__ 진입점이 있지만 경로 설정이 아예 없어서
# 직접 실행이 ModuleNotFoundError로 끝났다. pytest로 돌릴 때는 루트 conftest.py가
# 같은 일을 하므로 여기서는 중복을 피한다.
#
# 이 블록 때문에 아래 import가 파일 최상단에 오지 못하므로 E402를 끈다.
# ruff: noqa: E402
import json
import sys
from pathlib import Path
from typing import Any
from unittest.mock import patch

if str(Path(__file__).resolve().parents[1] / "src") not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import runtime as runtime_module
from agent import execute_tool
from experiment_support import make_experiment_runtime, record_run_evidence
from lab_paths import trace_root
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

# [C-02] 단일 트리 구조에서 fixture/schema는 저장소 루트에 있다.
# [C-03] trace 기본 출력은 저장소가 아니라 tmp다(lab_paths.trace_root()).
PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIR = PROJECT_ROOT / "src"
FIXTURE_PATH = PROJECT_ROOT / "fixtures" / "mcp_least_privilege.json"
TRACE_BASE = trace_root() / "trace_D9_EXP.jsonl"
ACTOR = "user-001"


# 함수이름: load_suite
# 인자: 없음
# 반환값:
#     dict: fixtures/mcp_least_privilege.json 전체
# 기능 설명:
#     D9 실험 케이스 묶음을 읽는다. 케이스 정의를 코드가 아니라 파일에 두는
#     이유는, 실행할 때마다 조건이 달라지지 않게 하고 fixture 해시를 증거에
#     포함시키기 위해서다.
def load_suite() -> list[dict[str, Any]]:
    raw = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    assert raw["suite_id"] == "D9-MCP-LEAST-PRIVILEGE"
    cases = raw["cases"]
    assert isinstance(cases, list) and cases
    fixture_ids = [case["fixture_id"] for case in cases]
    assert len(fixture_ids) == len(set(fixture_ids))
    return cases


# 함수이름: run_case
# 인자:
#     case (dict): fixture의 케이스 하나
# 반환값:
#     dict: 실험 증거와 평가 결과를 합친 dict
#     AssertionError: 기대와 다른 판정이나 호출 횟수일 때 발생
# 기능 설명:
#     케이스 하나를 실행하고 기대값과 대조한다.
#
#     최종 결과만 보면 "차단됐다"는 알 수 있어도 "그 뒤 단계가 불필요하게
#     호출됐는가"는 알 수 없다. 각 관문을 mock으로 감싸 호출 횟수를 세고
#     fixture의 expected.gate_calls와 비교한다.
#
#     schema에서 거부된 호출에 Policy 사건이 생긴다면, 조기 종료가 실제로는
#     일어나지 않았다는 뜻이다. 공격 표면이 설계보다 넓다.
def run_case(case: dict[str, Any]) -> dict[str, Any]:
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


# 함수이름: check_advertised_schema_isolation
# 인자: 없음
# 반환값:
#     dict: 원본 catalog와 프로필 스냅샷 비교 결과
#     AssertionError: 광고본 변조가 원본에 반영될 때 발생
# 기능 설명:
#     모델에게 광고한 schema/annotation 사본을 바꿔도 원본 catalog가 변하지
#     않는지 확인한다.
#
#     tools_for_mcp()가 얕은 복사를 반환하면 중첩된 inputSchema나 annotations를
#     통해 원본이 오염된다. 그러면 "서버가 자체 catalog로 다시 검사한다"는
#     전제가 무너진다. 신뢰의 근거가 되는 데이터는 밖에서 만질 수 없어야 한다.
def check_advertised_schema_isolation() -> None:
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


# 함수이름: test_mcp_tool_schema
# 인자: 없음
# 반환값:
#     None: 반환값 없음. 결과 JSON을 출력한다
# 기능 설명:
#     D9-E01~E06 본 실험과 광고본 격리 검사를 순서대로 실행한다.
# 함수이름: collect_profile_metrics
# 인자: 없음
#
#     dict: 프로필 이름별 노출 지표. profile_snapshot에 세 항목을 더한다
# 기능 설명:
#     프로필 3종이 각각 무엇을 노출하는지 한 표로 만든다.
#
#         exposed_tool_count       몇 개를 노출했나
#         write_exposed            쓰기 도구가 열려 있나
#         generic_command_exposed  임의 명령 실행이 열려 있나
#
#     이 dict는 검사의 입력이자 보고서의 인용 단위다. 그래서 판정과 분리해
#     따로 만든다.
def collect_profile_metrics() -> dict:
    return {
        profile.name: {
            **profile_snapshot(profile),
            "exposed_tool_count": len(profile.exposed_tools),
            "write_exposed": "write_file" in profile.exposed_tools,
            "generic_command_exposed": "run_command" in profile.exposed_tools,
        }
        for profile in (READ_ONLY_PROFILE, WRITE_ENABLED_PROFILE, LEGACY_COMPAT_PROFILE)
    }


# ===========================================================================
# pytest 진입점
#
# 성격이 다른 세 검사를 따로 센다.
#
#     1. fixture 케이스 6건   실제로 도구를 호출해 gate 동작을 본다 (동적)
#     2. 광고 스키마 격리      노출된 스키마가 내부 인터페이스를 바꾸지 않는지 (정적)
#     3. 프로필 노출 개수      최소권한 원칙이 지켜지는지 (정적)
#
# [왜 셋으로만 나누는가]
#     1번의 6건은 fixture가 정해 주는 데이터이므로 원래는 pytest.mark.parametrize로
#     6건을 따로 세는 것이 맞다. 다만 그렇게 하면 이 파일이 pytest 없이는 돌지
#     않게 된다. 지금은 직접 실행도 유지하는 쪽을 택했다.
#
#     parametrize로 옮기는 시점은 "직접 실행을 포기해도 된다"고 판단할 때다.
# ===========================================================================


# 함수이름: test_least_privilege_cases
# 인자: 없음
# 반환값:
#     None: 반환값 없음
#     AssertionError: fixture가 기대한 gate 동작과 실제가 다를 때 발생
# 기능 설명:
#     [D9-E01~E06] fixture가 정의한 여섯 케이스를 실제로 실행한다.
#
#     프로필별로 도구를 호출해 보고, 노출되지 않은 도구가 막히는지와 인자 인터페이스
#     위반이 schema gate에서 걸리는지를 확인한다.
def test_least_privilege_cases() -> None:
    for case in load_suite():
        run_case(case)


# 함수이름: test_advertised_schema_is_isolated
# 인자: 없음
# 반환값:
#     None: 반환값 없음
#     AssertionError: 광고용 스키마가 내부 인터페이스에 영향을 줄 때 발생
# 기능 설명:
#     MCP 서버가 밖으로 내보이는 도구 목록이 내부 판정 기준을 바꾸지 않는지
#     확인한다.
#
#     노출용 표현과 집행용 인터페이스가 같은 객체를 공유하면, 표시를 고치는 순간
#     권한이 함께 바뀐다. 둘은 분리되어 있어야 한다.
def test_advertised_schema_is_isolated() -> None:
    check_advertised_schema_isolation()


# 함수이름: test_profile_exposure_counts
# 인자: 없음
# 반환값:
#     None: 반환값 없음
#     AssertionError: 프로필이 필요 이상으로 도구를 노출할 때 발생
# 기능 설명:
#     최소권한 원칙이 프로필 정의에서 지켜지는지 확인한다.
#
#         read_only      도구 4개, 쓰기 없음
#         write_enabled  임의 명령 실행 없음
#
#     노출 자체가 공격 표면이다. 프로필에 도구를 하나 더 넣는 것은 모델이
#     제안할 수 있는 행동을 하나 더 여는 것과 같다.
def test_profile_exposure_counts() -> None:
    metrics = collect_profile_metrics()
    assert metrics["read_only"]["exposed_tool_count"] == 4
    assert metrics["read_only"]["write_exposed"] is False
    assert metrics["write_enabled"]["generic_command_exposed"] is False


# 함수이름: main
# 인자: 없음
# 반환값:
#     None: 반환값 없음
# 기능 설명:
#     직접 실행 진입점. 세 검사를 돌리고 케이스별 증거와 프로필 지표를 하나로
#     모아 출력한다.
#
#     pytest 경로에서는 이 합본이 만들어지지 않는다. run_case()가 돌려주는
#     dict를 테스트 함수가 버리기 때문이다. 보고서에 인용할 JSON이 필요하면
#     이쪽으로 돌린다.
def main() -> None:
    results = {case["fixture_id"]: run_case(case) for case in load_suite()}
    check_advertised_schema_isolation()
    profile_metrics = collect_profile_metrics()

    assert profile_metrics["read_only"]["exposed_tool_count"] == 4
    assert profile_metrics["read_only"]["write_exposed"] is False
    assert profile_metrics["write_enabled"]["generic_command_exposed"] is False

    print(json.dumps({"cases": results, "profiles": profile_metrics}, ensure_ascii=False, indent=2))
    print("Day 9 MCP least-privilege schema tests: PASS")


if __name__ == "__main__":
    main()
