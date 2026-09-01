"""Day 7: JSON fixture로 indirect prompt injection 방어를 재현한다.

LLM API는 호출하지 않는다. fixture가 정의한 source와 synthetic 공격 proposal을
test harness가 Runtime에 전달하고, Runtime의 기존 validation/policy/authz/
approval/dispatcher 흐름이 기대한 지점에서 끝나는지만 확인한다.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

from Agent import execute_tool
from experiment_support import make_experiment_runtime, record_run_evidence
from security.evaluator import evaluate_run
from security.fixtures import load_indirect_prompt_injection_fixture
from security.provenance import (
    direct_user_provenance,
    make_observation,
    provenance_for_observations,
)


SOURCE_DIR = Path(__file__).resolve().parent
FIXTURE_DIR = SOURCE_DIR / "fixtures"
TRACE_PATH = Path(os.environ.get("DAY9_REGRESSION_TRACE_PATH", SOURCE_DIR / "traces" / "trace_D9_REGRESSION.jsonl"))
ACTOR = "user-001"


def direct_read(experiment, fixture, *, call_id: str) -> dict:
    """정상 user request로 fixture의 local source 파일을 읽는다."""
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
