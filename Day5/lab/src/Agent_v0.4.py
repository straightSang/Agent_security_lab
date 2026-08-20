"""Day 5 approval UX loop.  Agent_v0.3.2.py는 변경하지 않는다.

이 파일은 인증 시스템이 아니라 테스트용 control-plane
입력이다. 
실제 운영에서는 IdP/session이 확인한 identity를 넘겨야 한다.
"""

from __future__ import annotations

import json
import os
import uuid
from typing import Any

from Agent import DEFAULT_RUNTIME as DAY5_RUNTIME, TOOLS, to_observation
from approval import approve_pending_request as approve_control
from security.provenance import direct_user_provenance

LAB_ACTOR = os.getenv("LAB_ACTOR", "user-001")
_APPROVED_APPROVAL_IDS: dict[str, str] = {}
_PENDING_APPROVAL_RUNS: dict[str, str] = {}


def approve_pending_request(approval_id: str, *, authenticated_approver: str) -> dict[str, Any]:
    """승인 record만 approved로 바꾼다. dispatcher는 여기서 호출하지 않는다."""

    control = approve_control(
        DAY5_RUNTIME.approvals,
        approval_id,
        authenticated_approver=authenticated_approver,
    )

    state = control.state

    run_id = _PENDING_APPROVAL_RUNS.get(approval_id, f"approval-control-{approval_id}")

    DAY5_RUNTIME.trace.emit(
        "approval_state_changed",
        run_id,
        actor=authenticated_approver,
        approval=state.status.value,
        approval_id=approval_id,
        required_approver=state.required_approver,
        reason=control.reason
    )

    if control.changed and state.requested_actor:
        _APPROVED_APPROVAL_IDS[state.requested_actor] = approval_id

    return {
        "approval_id": approval_id,
        "state": state.status.value,
        "changed": control.changed,
        "reason": control.reason,
        "requested_actor": state.requested_actor,
        "required_approver": state.required_approver,
    }


def execute_proposal(proposal: dict[str, Any], *, actor: str = LAB_ACTOR, run_id: str | None = None, step: int = 1) -> dict[str, Any]:
    """검증된 LLM function proposal을 Runtime 경계로 보낸다."""
   
    active_run = run_id or f"run_{uuid.uuid4().hex}"

    result = DAY5_RUNTIME.execute_tool(
        tool_name=str(proposal["name"]),
        arguments=dict(proposal["arguments"]),
        call_id=str(proposal.get("call_id") or f"call_{uuid.uuid4().hex}"),
        run_id=active_run,
        actor=actor,
        provenance=direct_user_provenance("interactive-user"),
        approval_id=_APPROVED_APPROVAL_IDS.get(actor),
        agent_step=step,
    ).to_dict()

    meta = result["meta"]

    if result["status"] == "approval_required" and meta.get("approval_id"):
        _PENDING_APPROVAL_RUNS[meta["approval_id"]] = active_run

    if result["ok"] and meta.get("approval") == "consumed":
        _APPROVED_APPROVAL_IDS.pop(actor, None)

    return result


def run_responses_agent(user_input: str, *, actor: str = LAB_ACTOR) -> str:
    """선택적 Responses API loop. 외부 모델은 proposal만 만들며 실행하지 않는다."""
    from openai import OpenAI  # optional dependency; tests do not import this path

    api_key = os.environ.get("OPENAI_API_KEY")

    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is required for the API loop")
    client = OpenAI(api_key=api_key)

    response = client.responses.create(
        model=os.getenv("MODEL", "gpt-5.5"), input=user_input, tools=TOOLS,
    )

    outputs: list[dict[str, Any]] = []

    for item in response.output:

        if item.type != "function_call":
            continue

        outputs.append(execute_proposal({
            "name": item.name,
            "arguments": json.loads(item.arguments),
            "call_id": item.call_id,

        }, actor=actor))

    return json.dumps([to_observation(result) for result in outputs], ensure_ascii=False)


if __name__ == "__main__":
    print("Day 5 Lab. /approve <approval_id> [authenticated_approver], /quit")

    while True:
        line = input(f"{LAB_ACTOR}> ").strip()

        if line in {"/quit", "/exit"}:
            break

        if line.startswith("/approve "):
            parts = line.split()

            if len(parts) not in {2, 3}:
                print("usage: /approve <approval_id> [authenticated_approver]")
                continue

            approver = parts[2] if len(parts) == 3 else LAB_ACTOR
            print(approve_pending_request(parts[1], authenticated_approver=approver))
            continue

        print(run_responses_agent(line, actor=LAB_ACTOR))
