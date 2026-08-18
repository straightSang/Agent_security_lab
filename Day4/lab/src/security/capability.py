"""Map normalized tool proposals to the least capability needed to perform them."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from .types import Capability


def _relative_resource(path: Path | None, sandbox_root: Path) -> str | None:
    if path is None:
        return None
    return path.relative_to(sandbox_root).as_posix() or "."


def describe_intent(tool_name: str, arguments: Mapping[str, Any], validation: Mapping[str, Any], sandbox_root: Path) -> tuple[Capability, str, str | None]:
    path = validation.get("resolved_path")
    resource = _relative_resource(path, sandbox_root)
    mapping = {
        "calculator": (Capability.CALCULATOR_EXECUTE, "calculate", None),
        "get_time": (Capability.CLOCK_READ, "read", "system:clock"),
        "read_file": (Capability.FILESYSTEM_READ, "read", resource),
        "write_file": (Capability.FILESYSTEM_WRITE, "write", resource),
        "list_files": (Capability.FILESYSTEM_LIST, "list", resource),
    }
    if tool_name in mapping:
        return mapping[tool_name]
    if tool_name == "run_command":
        command = validation.get("command_base", "unknown")
        return (Capability.COMMAND_READ if command in {"pwd", "ls", "cat"} else Capability.UNKNOWN, command, resource)
    return Capability.UNKNOWN, "unknown", None
