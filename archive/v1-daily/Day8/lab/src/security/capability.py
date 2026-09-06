"""정규화된 도구 제안을 실행에 필요한 최소 capability로 매핑한다."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from .types import Capability


TOOL_CAPABILITY_MAP = {
    "calculator": (Capability.CALCULATOR_EXECUTE, "calculate", None),
    "get_time": (Capability.CLOCK_READ, "read", "system:clock"),
}

PATH_TOOL_CAPABILITY_MAP = {
    "read_file": (Capability.FILESYSTEM_READ, "read"),
    "write_file": (Capability.FILESYSTEM_WRITE, "write"),
    "list_files": (Capability.FILESYSTEM_LIST, "list"),
}

COMMAND_CAPABILITY_MAP = {
    "pwd": Capability.COMMAND_READ,
    "ls": Capability.COMMAND_READ,
    "cat": Capability.COMMAND_READ,
}


def _relative_resource(path: Path | None, sandbox_root: Path) -> str | None:
    if path is None:
        return None
    return path.relative_to(sandbox_root).as_posix() or "."


def describe_intent(tool_name: str, arguments: Mapping[str, Any], validation: Mapping[str, Any], sandbox_root: Path) -> tuple[Capability, str, str | None]:
    path = validation.get("resolved_path")
    resource = _relative_resource(path, sandbox_root)
    if tool_name in TOOL_CAPABILITY_MAP:
        return TOOL_CAPABILITY_MAP[tool_name]
    if tool_name in PATH_TOOL_CAPABILITY_MAP:
        capability, action = PATH_TOOL_CAPABILITY_MAP[tool_name]
        return capability, action, resource
    if tool_name == "run_command":
        command = validation.get("command_base", "unknown")
        return COMMAND_CAPABILITY_MAP.get(command, Capability.UNKNOWN), command, resource
    return Capability.UNKNOWN, "unknown", None


def capability_mapping_snapshot() -> dict[str, object]:
    """실험 전후 비교용 선언형 capability mapping을 반환한다."""
    return {
        "tools": {
            name: {
                "capability": capability.value,
                "action": action,
                "resource": resource,
            }
            for name, (capability, action, resource) in TOOL_CAPABILITY_MAP.items()
        },
        "path_tools": {
            name: {"capability": capability.value, "action": action}
            for name, (capability, action) in PATH_TOOL_CAPABILITY_MAP.items()
        },
        "commands": {
            name: capability.value
            for name, capability in COMMAND_CAPABILITY_MAP.items()
        },
    }
