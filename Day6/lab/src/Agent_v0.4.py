"""Day 5 approval UX loop.  Agent_v0.3.2.py는 변경하지 않는다.

이 파일은 인증 시스템이 아니라 테스트용 control-plane
입력이다. 
실제 운영에서는 IdP/session이 확인한 identity를 넘겨야 한다.
"""

from __future__ import annotations

from pathlib import Path

from dotenv import load_dotenv
from openai import OpenAI

import json
import os
import uuid
from typing import Any

from Agent import DEFAULT_RUNTIME as DAY5_RUNTIME, TOOLS, to_observation
from approval import approve_pending_request as approve_control
import security.provenance as DEFAULT_PROVENANCE

load_dotenv()

LAB_ACTOR = os.getenv("LAB_ACTOR", "user-001")
MODEL = os.getenv("MODEL", "gpt-5.5")
_APPROVED_APPROVAL_IDS: dict[str, str] = {}
_PENDING_APPROVAL_RUNS: dict[str, str] = {}


def normalize_terminal_text(text: str) -> str:
    """WSL terminal의 surrogateescape 입력을 정상 UTF-8로 복구한다."""
    try:
        return text.encode("utf-8", "surrogateescape").decode("utf-8")
    except UnicodeError:
        return text.encode("utf-8", "backslashreplace").decode("utf-8")


class AgentEventLogger:
    """Runtime trace와 같은 JSONL에 LLM loop 이벤트를 추가 기록한다."""

    def __init__(self, *, run_id: str) -> None:
        self.run_id = run_id
        self.step = 0

    def next_step(self) -> None:
        self.step += 1

    def log(self, event: str, payload: dict[str, Any] | None = None, **fields: Any) -> None:
        record = {"agent_step": self.step, **(payload or {}), **fields}
        call_id = record.pop("call_id", None)
        if call_id is None and isinstance(record.get("data"), dict):
            call_id = record["data"].get("call_id")
        DAY5_RUNTIME.trace.emit(event, self.run_id, call_id=call_id, **record)

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


def execute_proposal(
    proposal: dict[str, Any], *, actor: str = LAB_ACTOR,
    run_id: str | None = None, step: int = 1,
    provenance: DEFAULT_PROVENANCE.Provenance | None = None,
) -> dict[str, Any]:
    """검증된 LLM function proposal을 유일한 Runtime 경계로 보낸다."""
    active_run = run_id or f"run_{uuid.uuid4().hex}"

    result = DAY5_RUNTIME.execute_tool(
        tool_name=str(proposal["name"]),
        arguments=dict(proposal["arguments"]),
        call_id=str(proposal.get("call_id") or f"call_{uuid.uuid4().hex}"),
        run_id=active_run,
        actor=actor,
        provenance=provenance or DEFAULT_PROVENANCE.direct_user_provenance("interactive-user"),
        approval_id=_APPROVED_APPROVAL_IDS.get(actor),
        agent_step=step,
    ).to_dict()

    meta = result["meta"]

    if result["status"] == "approval_required" and meta.get("approval_id"):
        _PENDING_APPROVAL_RUNS[meta["approval_id"]] = active_run

    if result["ok"] and meta.get("approval") == "consumed":
        _APPROVED_APPROVAL_IDS.pop(actor, None)

    return result


def run_agent(
    user_input: str, *, actor: str = LAB_ACTOR,
    initial_provenance: DEFAULT_PROVENANCE.Provenance | None = None,
) -> str:
    """Day 4의 반복 Agent loop에 Day 5 승인 UX를 결합한다.

    모델의 tool call은 실행 권한이 아니다. 모든 제안은 Runtime으로 가고,
    Runtime observation은 다시 Responses API에 전달되어 최종 자연어 답변을 만든다.
    """
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is required for the API loop")
    client = OpenAI(api_key=api_key)

    user_input = normalize_terminal_text(user_input)
    current_provenance = initial_provenance or DEFAULT_PROVENANCE.direct_user_provenance(
        "interactive-user"
    )
    run_id = f"run_{uuid.uuid4().hex}"
    logger = AgentEventLogger(run_id=run_id)
    logger.log("run_start", {"actor": actor, "user_input": user_input})
    print(f"[RUN ID] {run_id}")

    input_items: list[Any] = [{"role": "user", "content": user_input}]
    while True:
        logger.next_step()
        logger.log("model_request", {"input_items": input_items})
        print(f"\n============= STEP {logger.step} =============")

        response = client.responses.create(
            model=MODEL,
            instructions=(
                "You are a minimal tool-using agent. Use tools whenever "
                "external information or calculation is required. You may "
                "use multiple tools sequentially."
            ),
            tools=TOOLS,
            input=input_items,
        )
        logger.log(
            "model_response",
            {
                "response_id": response.id,
                "output_text": response.output_text,
                "output": [item.model_dump() for item in response.output],
            },
        )

        # function_call 객체를 보존하고, 아래에서 function_call_output을 추가한다.
        input_items += response.output
        tool_called = False
        next_provenance = current_provenance

        for item in response.output:
            if item.type != "function_call":
                continue
            tool_called = True
            tool_name = item.name
            arguments = json.loads(item.arguments)
            intent_provenance = current_provenance
            logger.log(
                "agent_tool_proposal",
                {
                    "tool": {"name": tool_name, "arguments": arguments},
                    "provenance_at_proposal": intent_provenance.to_dict(),
                },
                call_id=item.call_id,
            )
            print("\n[TOOL CALL]")
            print("name      :", tool_name)
            print("arguments :", arguments)

            runtime_result = execute_proposal(
                {"name": tool_name, "arguments": arguments, "call_id": item.call_id},
                actor=actor,
                run_id=run_id,
                step=logger.step,
                provenance=intent_provenance,
            )
            observation = to_observation(runtime_result)
            print("\n[RUNTIME RESULT]")
            print(runtime_result)
            print("\n[OBSERVATION]")
            print(observation)

            input_items.append(
                {
                    "type": "function_call_output",
                    "call_id": item.call_id,
                    "output": json.dumps(observation, ensure_ascii=False),
                }
            )

            # 다음 LLM turn의 도구 제안은 읽은 file observation의 영향을 받았을
            # 수 있으므로 보수적으로 untrusted repository provenance로 전이한다.
            if tool_name == "read_file" and runtime_result["ok"]:
                next_provenance = DEFAULT_PROVENANCE.repository_provenance(
                    arguments["path"], parent_event_id=item.call_id,
                )
                logger.log(
                    "provenance_transition",
                    {
                        "from": intent_provenance.to_dict(),
                        "to": next_provenance.to_dict(),
                        "reason": "successful_read_file_observation",
                    },
                    call_id=item.call_id,
                )

        current_provenance = next_provenance
        if not tool_called:
            logger.log("final_response", {"content": response.output_text})
            logger.log("run_end", {"status": "success"})
            print("\n[FINAL RESPONSE]")
            print(response.output_text)
            return response.output_text


# 이전 v0.4 이름을 호출한 코드와의 호환 별칭이다.
run_responses_agent = run_agent


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

        run_agent(line, actor=LAB_ACTOR)
