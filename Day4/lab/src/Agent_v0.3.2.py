"""Day 4 Agent 실행 loop.

v0.2.2의 Responses API loop를 유지하되, 모든 도구 제안은 Day 4 Runtime에
위임한다. 이 파일을 ``Agent.py``, ``runtime.py``, ``security/`` 패키지 옆에
두고 Agent_v0.2.2.py 대신 실행한다.
"""

from __future__ import annotations

import json
import os
import uuid
from typing import Any

from dotenv import load_dotenv
from openai import OpenAI

# Agent.py는 Day 4 composition root다. sandbox, PolicyEngine, ApprovalStore,
# JSONL TraceLogger가 설정된 Runtime을 이미 구성한다.
from Agent import DEFAULT_RUNTIME as DAY4_RUNTIME
from Agent import TOOLS, to_observation
import security.provenance as DEFAULT_PROVENANCE

load_dotenv()

api_key = os.environ.get("OPENAI_API_KEY")
if not api_key:
    raise RuntimeError("OPENAI_API_KEY is required to run the agent loop")

client = OpenAI(api_key=api_key)
MODEL = os.getenv("MODEL", "gpt-5.5")

# 신뢰된 승인 제어와 다음 도구 호출을 연결하는 데모 전용 연결부다.
# 운영에서는 서버 측 session/database에 있어야 하며 LLM prompt나 브라우저가
# 제어하는 hidden field에 두면 안 된다.
_APPROVED_APPROVAL_IDS: dict[str, str] = {}

def normalize_terminal_text(
    text: str,
) -> str:
    # WSL의 surrogateescape 입력을 정상 UTF-8 텍스트로 복구한다
    try:
        return (
            text.encode(
                "utf-8",
                "surrogateescape"
            ).decode("utf-8")
        )

    except UnicodeError:
        # 정말 잘못된 문자는 보이는 escape 문자열로 남긴다.
        return (
            text.encode(
                "utf-8",
                "backslashreplace"
            ).decode("utf-8")
        )
    

class AgentEventLogger:
    """Day 4 Runtime과 같은 JSONL trace에 LLM-loop 이벤트를 기록한다.

    Runtime 소유 이벤트(tool_intent, policy_decision, runtime_result)는 계속
    Runtime이 기록한다. 이 adapter는 호환되지 않는 v0.2.2 TraceLogger API를
    되살리지 않고 Agent/LLM 측 이벤트만 기록한다.
    """

    def __init__(self, *, run_id: str) -> None:
        self.run_id = run_id
        self.step = 0

    def next_step(self) -> None:
        self.step += 1

    def log(self, event: str, payload: dict[str, Any] | None = None, **fields: Any) -> None:

        record = {"agent_step": self.step, **(payload or {}), **fields}

        call_id = record.pop("call_id", None) # 모든 agnet event 가 id 를 갖고 있지는 얺기 때문에 기본값 None 제공.

        if call_id is None and isinstance(record.get("data"), dict):

            call_id = record["data"].get("call_id")

        DAY4_RUNTIME.trace.emit(
            event,
            self.run_id,
            call_id=call_id,
            **record,
        )


def approve_pending_request(
    approval_id: str,
    *,
    authenticated_approver: str,
    actor: str,
) -> dict[str, Any]:
    """*신뢰된* control plane을 통해 pending record를 승인한다.

    실제 서비스에서는 authentication layer가 ``authenticated_approver``를
    제공한다. 아래 CLI의 ``demo-admin``은 로컬 실험 전용이다. 승인은 도구를
    실행하지 않으며, 일치하는 미래 ToolIntent 하나만 Runtime 실행 후보로 만든다.
    """
    state = DAY4_RUNTIME.approvals.approve(
        approval_id,
        approver=authenticated_approver,
    )
    DAY4_RUNTIME.trace.emit(
        "approval_state_changed",
        f"approval_{uuid.uuid4().hex}",
        actor=authenticated_approver,
        approval=state.status.value,
        approval_id=state.approval_id,
        reason="approved_by_authenticated_control_plane",
    )
    if state.status.value == "approved":
        _APPROVED_APPROVAL_IDS[actor] = approval_id
    return {
        "approval_id": state.approval_id,
        "status": state.status.value,
        "approver": state.approver,
        "expires_at": state.expires_at,
    }

def run_agent( user_input: str, *,
    actor: str = "user-001",
    initial_provenance: DEFAULT_PROVENANCE.Provenance | None = None, ) -> str:
    """Day 4 보안 경계를 통과해 여러 단계의 agent task 하나를 실행한다.

    ``current_provenance``는 직접 사용자 요청으로 시작한다. read_file이 성공한
    뒤 다음 도구 제안은 보수적으로 그 파일 내용에서 유래했다고 취급한다. 이는
    완전한 인과 provenance 시스템이 아니라 Day 4 실험 규칙이다.
    """

    user_input = normalize_terminal_text(user_input)


    if initial_provenance is None:

        # 이번 LLM 응답이 생성될 때 적용되는 provenance
        current_provenance = DEFAULT_PROVENANCE.direct_user_provenance(
            "interactive-user"
        )

    else:
        current_provenance = initial_provenance

    run_id = f"run_{uuid.uuid4().hex}"
    print(f"[RUN ID] {run_id}")
    
    logger = AgentEventLogger(run_id=run_id)

    logger.log("run_start", {"actor": actor, "user_input": user_input})

    # 이 위치에는 어떤 Python 객체가 들어와도 된다고 표시하는 타입
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

        # 다음 turn을 위해 모델의 function-call 객체를 보존한다.
        input_items += response.output
        tool_called = False

        # 모델은 아직 이번 turn의 파일 observation을 받지 못했으므로, 같은
        # 모델 응답에서 나온 이후 호출을 taint하지 않는다. 전이는 다음 Responses
        # API turn에만 적용한다.

        # 이번 처리가 끝난 뒤, 다음 LLM 응답에 적용할 provenance.
        # 다음 turn의 기본 provenance는 일단 현재와 같다
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

        #=====================================================================
            # v0.3에서 유일한 도구 실행 진입점이다.
            runtime_result = DAY4_RUNTIME.execute_tool(
                tool_name=tool_name,
                arguments=arguments,
                call_id=item.call_id,
                run_id=run_id,
                actor=actor,
                provenance=intent_provenance,
                approval_id=_APPROVED_APPROVAL_IDS.get(actor),
                agent_step=logger.step,
            ).to_dict()

            # ``consumed``는 동일한 재시도라도 이 일회용 grant가 다른 작업을
            # 더 이상 승인할 수 없다는 뜻이다.
            if runtime_result["meta"].get("approval") == "consumed":
                _APPROVED_APPROVAL_IDS.pop(actor, None)

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

            #========================provenance 미리 설정
            # Provenance 전이: 다음 제안 작업은 이 파일 내용의 영향을 받았을 수
            # 있으므로 직접 사용자 trust를 잃는다.
            # 만약 현재 동작이 read_file 이고 정상적으로 수행됐다면 
            if tool_name == "read_file" and runtime_result["ok"]:
                next_provenance = DEFAULT_PROVENANCE.repository_provenance(
                    arguments["path"],
                    parent_event_id=item.call_id,
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


if __name__ == "__main__":
    while True:
        user_input = input("\nUSER > ")
        if user_input.lower() in {"exit", "quit"}:
            break
        if user_input.startswith("/approve "):
            
            approval_id = user_input.removeprefix("/approve ").strip()
            print(
                approve_pending_request(
                    approval_id,
                    authenticated_approver="demo-admin",
                    actor="user-001",
                )
            )
            continue
        run_agent(user_input)
