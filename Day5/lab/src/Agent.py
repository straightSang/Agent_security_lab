"""기존 mini agent와 호환되는 Day 4 진입점.

이 모듈의 공개 helper는 ``validate_tool_call()``, ``execute_tool()``,
``make_runtime_result()``, ``to_observation()``라는 v0.2.2 형태를 유지한다.
다만 실제 enforcement는 ``runtime.Runtime``에 위임하므로 LLM의 도구 제안은
그 자체로 실행 권한이 되지 않는다.
"""

from __future__ import annotations

import os
import uuid
from pathlib import Path
from typing import Any, Mapping

from runtime import (
    ARGUMENT_SPEC,
    PATH_TOOLS,
    Runtime,
    make_runtime_result,
    safe_resolve as _safe_resolve,
    to_observation,
    validate_arguments,
    validate_tool_call as _validate_tool_call,
)
from security.authorization import AuthorizationEngine
from security.approval import ApprovalStore
from security.policy import PolicyEngine
from security.provenance import direct_user_provenance
from trace_logger import TraceLogger

SOURCE_DIR = Path(__file__).resolve().parent
SANDBOX_ROOT = (SOURCE_DIR / "sandbox").resolve()
TRACE_PATH = SOURCE_DIR / "traces" / "trace_A.jsonl"

# OpenAI Responses API 호환 함수 도구 목록이다. 이것은 보안 통제가 아니며,
# strict=True여도 Runtime validation은 반드시 수행한다.
TOOLS: list[dict[str, Any]] = [
    {
        "type": "function", "name": "calculator", "strict": True,
        "description": "Perform a basic arithmetic calculation.",
        "parameters": {"type": "object", "properties": {"expression": {"type": "string"}}, "required": ["expression"], "additionalProperties": False},
    },
    {
        "type": "function", "name": "read_file", "strict": True,
        "description": "Read a UTF-8 text file at a relative sandbox path.",
        "parameters": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"], "additionalProperties": False},
    },
    {
        "type": "function", "name": "get_time", "strict": True,
        "description": "Get the local system time.",
        "parameters": {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
    },
    {
        "type": "function", "name": "write_file", "strict": True,
        "description": "Write a UTF-8 file at a relative sandbox path.",
        "parameters": {"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}}, "required": ["path", "content"], "additionalProperties": False},
    },
    {
        "type": "function", "name": "list_files", "strict": True,
        "description": "List a sandbox directory at a relative path.",
        "parameters": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"], "additionalProperties": False},
    },
    {
        "type": "function", "name": "run_command", "strict": True,
        "description": "Run a restricted logical command: pwd, ls [path], or cat <file>.",
        "parameters": {"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"], "additionalProperties": False},
    },
]


def build_runtime(*, trace_path: Path = TRACE_PATH) -> Runtime:
    """API key 없이 기본 로컬 testbed Runtime을 구성한다."""
    return Runtime(
        sandbox_root=SANDBOX_ROOT,
        policy=PolicyEngine(),
        approvals=ApprovalStore(),
        trace_logger=TraceLogger(trace_path),
        authorizer=AuthorizationEngine(),
    )


DEFAULT_RUNTIME = build_runtime()


def safe_resolve(user_path: str) -> Path:
    """이 Agent의 sandbox에 결속된 v0.2.2 호환 경로 resolver."""
    return _safe_resolve(user_path, SANDBOX_ROOT)


def validate_tool_call(tool_name: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
    """이 Agent의 sandbox에 결속된 v0.2.2 호환 validation wrapper."""
    return _validate_tool_call(tool_name, arguments, SANDBOX_ROOT)


def execute_tool(
    tool_name: str,
    arguments: Mapping[str, Any],
    call_id: str | None = None,
    *,
    run_id: str | None = None,
    actor: str = "local-user",
    provenance=None,
    approval_id: str | None = None,
    agent_step: int | None = None,
    runtime: Runtime | None = None,
) -> dict[str, Any]:
    """모든 Day 3/4 통제를 거쳐 제안을 실행한다.

    이전의 세 위치 인자는 계속 허용한다. 새 호출자는 provenance와 승인된
    approval ID를 제공할 수 있으나, 둘 다 LLM 문자열에서 추론하지 않는다.
    """
    active_runtime = runtime or DEFAULT_RUNTIME
    return active_runtime.execute_tool(
        tool_name=tool_name,
        arguments=dict(arguments),
        call_id=call_id or f"call_{uuid.uuid4().hex}",
        run_id=run_id or f"run_{uuid.uuid4().hex}",
        actor=actor,
        provenance=provenance or direct_user_provenance(),
        approval_id=approval_id,
        agent_step=agent_step,
    ).to_dict()


def observation_for_tool_output(runtime_result: Mapping[str, Any]) -> dict[str, Any]:
    """기존 Observation Adapter의 의미를 분명히 한 별칭."""
    return to_observation(runtime_result)


def run_responses_agent(user_input: str) -> str:
    """선택적으로 사용하는 최소 Responses API loop.

    테스트와 보안 실험은 OpenAI SDK를 import하거나 ``OPENAI_API_KEY``를 읽지
    않고 로컬에서 실행할 수 있도록 의도적으로 opt-in으로 만들었다.
    """
    try:
        from openai import OpenAI
    except ImportError as exc:  # pragma: no cover - environment dependent
    
        raise RuntimeError("Install requirements.txt to use the API loop") from exc

    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is required for the API loop")
    client = OpenAI(api_key=api_key)
    response = client.responses.create(model=os.getenv("MODEL", "gpt-5.5"), input=user_input, tools=TOOLS)
    # 운영 loop는 function call을 반복 처리해야 한다. 이 구현을 작게 유지하여
    # execute_tool을 우회하지 않게 했고, 호출자는 모든 요청을 이 경계로 보내야 한다.
    return response.output_text
