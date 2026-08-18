"""Day 4-compatible entry point for the original mini agent.

The public helpers in this module deliberately preserve the v0.2.2 shape:
``validate_tool_call()``, ``execute_tool()``, ``make_runtime_result()`` and
``to_observation()``.  The implementation now delegates enforcement to
``runtime.Runtime`` so an LLM tool proposal is never itself an execution grant.
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
from security.approval import ApprovalStore
from security.policy import PolicyEngine
from security.provenance import direct_user_provenance
from trace_logger import TraceLogger

SOURCE_DIR = Path(__file__).resolve().parent
SANDBOX_ROOT = (SOURCE_DIR / "sandbox").resolve()
TRACE_PATH = SOURCE_DIR / "traces" / "trace.jsonl"

# Kept as an OpenAI Responses API compatible function-tool list.  It is not a
# security control; runtime validation remains mandatory even with strict=True.
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
    """Build the default local testbed runtime without requiring an API key."""
    return Runtime(
        sandbox_root=SANDBOX_ROOT,
        policy=PolicyEngine(),
        approvals=ApprovalStore(),
        trace_logger=TraceLogger(trace_path),
    )


DEFAULT_RUNTIME = build_runtime()


def safe_resolve(user_path: str) -> Path:
    """v0.2.2-compatible sandbox resolver bound to this agent's sandbox."""
    return _safe_resolve(user_path, SANDBOX_ROOT)


def validate_tool_call(tool_name: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
    """v0.2.2-compatible validation wrapper bound to this agent's sandbox."""
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
    """Execute a proposal through all Day 3/4 controls.

    The old three positional arguments are still accepted.  New callers can
    supply provenance and an approved approval id; neither is inferred from an
    LLM string.
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
    """Explicitly named alias for the original Observation Adapter."""
    return to_observation(runtime_result)


def run_responses_agent(user_input: str) -> str:
    """Optional minimal Responses API loop.

    This is intentionally opt-in: tests and security experiments run locally
    without importing the OpenAI SDK or reading ``OPENAI_API_KEY``.
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
    # A production loop should iterate function calls. Keeping this small avoids
    # accidentally bypassing execute_tool; callers must feed every call through it.
    return response.output_text
