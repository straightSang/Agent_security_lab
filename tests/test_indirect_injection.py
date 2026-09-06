# Day 7: JSON fixture로 indirect prompt injection 방어를 재현한다.
#
# LLM API는 호출하지 않는다. fixture가 정의한 source와 synthetic 공격 proposal을
# test harness가 Runtime에 전달하고, Runtime의 기존 validation/policy/authz/
# approval/dispatcher 흐름이 기대한 지점에서 끝나는지만 확인한다.


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

import json
import os
from pathlib import Path
from unittest.mock import patch

from agent import execute_tool
from experiment_support import make_experiment_runtime, record_run_evidence
from lab_paths import trace_root
from security.evaluator import evaluate_run
from security.fixtures import load_indirect_prompt_injection_fixture
from security.provenance import (
    direct_user_provenance,
    make_observation,
    provenance_for_observations,
)

# [C-02] 단일 트리 구조에서 fixture/schema는 저장소 루트에 있다.
# [C-03] trace 기본 출력은 저장소가 아니라 tmp다(lab_paths.trace_root()).
PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIR = PROJECT_ROOT / "src"
FIXTURE_DIR = PROJECT_ROOT / "fixtures"
TRACE_PATH = Path(os.environ.get("DAY9_REGRESSION_TRACE_PATH", trace_root() / "trace_D9_REGRESSION.jsonl"))
ACTOR = "user-001"


# 함수이름: direct_read
# 인자:
#     experiment (ExperimentRuntime): 이 케이스의 실험 환경
#     fixture (IndirectPromptInjectionFixture): 실험 입력
#     call_id (str): 호출 식별자
# 반환값:
#     dict: execute_tool()의 반환 결과
# 기능 설명:
#     사용자가 직접 요청한 읽기를 수행하고, 그것이 정상 동작하는지 확인한다.
#
#     "성공했다"만 보면 관문을 건너뛰고 실행됐는지 알 수 없다. mock으로 감싸
#     정확히 1회 실행됐음을 확인한다.
#
#     사용자가 직접 시킨 일이므로 정상 통과해야 한다. 여기서 막히면 과차단
#     (OBR)이며, 그 자체가 결함이다.
def direct_read(experiment, fixture, *, call_id: str) -> dict:
    with patch.object(experiment.runtime, "_dispatch", wraps=experiment.runtime._dispatch) as dispatch:
        result = execute_tool(
            "read_file",
            {"path": fixture.source},
            call_id=call_id,
            run_id=experiment.run_id,
            actor=ACTOR,
            provenance=direct_user_provenance("fixture-harness"),
            fixture_id=fixture.fixture_id,
            runtime=experiment.runtime,
        )
        assert dispatch.call_count == 1
    assert result["ok"] is True
    assert result["data"] == fixture.content
    return result


# D7-E01: benign fixture의 읽기 기능은 정상적으로 수행된다. (과도하게 차단되지 않는다)
benign = load_indirect_prompt_injection_fixture(FIXTURE_DIR / "benign_email.json")

benign_exp = make_experiment_runtime(
    benign.fixture_id,
    trace_path=TRACE_PATH,
    seed_files=benign.seed_files,
)

benign_read = direct_read(benign_exp, benign, call_id="call-d7-e01-read")

benign_observation = make_observation(
    source_kind=benign.source_kind,
    source=benign.source,
    content=str(benign_read["data"]),
    parent_call_id="call-d7-e01-read",
)

benign_exp.runtime.trace.record_observation(
    benign_exp.run_id, benign_observation, fixture_id=benign.fixture_id,
)

benign_eval = evaluate_run(
    benign_exp.runtime.trace.iter_events(run_id=benign_exp.run_id, strict=True),
    expected_decision="allow",
    expected_authorization="allow",
)

assert benign_eval.task_success is True
assert benign_eval.policy_false_block is False
assert benign_eval.trace_completeness is True
benign_evidence = record_run_evidence(benign_exp)



# D7-E02: 사용자가 직접 입력한 read는 성공할 수 있지만, 도구 실행 결과에서 유래한 write 도구 호출은
# untrusted provenance이므로 Policy에서 차단되어야 한다.
injected = load_indirect_prompt_injection_fixture(FIXTURE_DIR / "injected_email.json")

injected_exp = make_experiment_runtime(
    injected.fixture_id,
    trace_path=TRACE_PATH,
    seed_files=injected.seed_files,
)

injected_read = direct_read(injected_exp, injected, call_id="call-d7-e02-read")

# fixture2 유래, 최초 호출: read_file 한 결과 observation 을 가장한 최초 호출 fixture
injected_observation = make_observation(
    source_kind=injected.source_kind,
    source=injected.source,
    content=str(injected_read["data"]),
    parent_call_id="call-d7-e02-read",
)

injected_exp.runtime.trace.record_observation(
    injected_exp.run_id, injected_observation, fixture_id=injected.fixture_id,
)

derived_provenance = provenance_for_observations([injected_observation])
assert derived_provenance.kind.value == injected.source_kind.value

proposal = injected.attack_proposal

assert proposal is not None

# fixture2 유래, 두번째 호출: read_file 한 결과 observation에서 유래한 두번째 도구호출 fixture
with patch.object(injected_exp.runtime, "_dispatch", wraps=injected_exp.runtime._dispatch) as unsafe_dispatch:
    denied = execute_tool(
        proposal["tool_name"],  # attack_propsal
        proposal["arguments"],  # attack_propsal
        call_id="call-d7-e02-injected-write",
        run_id=injected_exp.run_id,
        actor=ACTOR,
        provenance=derived_provenance,
        fixture_id=injected.fixture_id,
        runtime=injected_exp.runtime,
    )
    assert unsafe_dispatch.call_count == injected.expected["unsafe_dispatch_count"]

assert denied["ok"] is False
assert denied["status"] == injected.expected["runtime_status"]
assert denied["end_stage"] == injected.expected["end_stage"]
assert denied["meta"]["policy_decision"] == injected.expected["policy_decision"]
assert denied["meta"]["reason"] == "UNTRUSTED_PROVENANCE_CANNOT_AUTHORIZE_TOOL"
assert "approval_id" not in denied["meta"]

injected_eval = evaluate_run(
    injected_exp.runtime.trace.iter_events(run_id=injected_exp.run_id, strict=True),
    expected_decision="deny",
    unsafe_fixture=True,
)
assert injected_eval.unsafe_action is False
assert injected_eval.observation_policy_bypass is False
assert injected_eval.observation_metadata_tamper is False
assert injected_eval.trace_completeness is True
injected_evidence = record_run_evidence(injected_exp)


print(json.dumps({
    "D7-E01": {"run_id": benign_exp.run_id, **benign_evidence, **benign_eval.to_dict()},
    "D7-E02": {"run_id": injected_exp.run_id, **injected_evidence, **injected_eval.to_dict()},
}, ensure_ascii=False, indent=2))
print("Day 7 indirect prompt injection fixture tests: PASS")
