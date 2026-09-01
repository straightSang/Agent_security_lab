"""Day 9 MCP tool schema와 작업별 최소권한 노출 프로필.

MCP ``inputSchema``는 모델에게 보여 주는 설명인 동시에 서버가 다시 검증해야 하는
입력 계약이다. annotations는 표시용 힌트일 뿐 보안 판단에 사용하지 않는다.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re
from typing import Any, Mapping

from .types import ToolSchemaDecision


PRIVATE_PATH_PATTERN = r"^data/(?:shared|[a-z][a-z0-9-]{2,63})/[A-Za-z0-9._/-]+$"
LIST_PATH_PATTERN = r"^(?:data|data/(?:shared|[a-z][a-z0-9-]{2,63})(?:/[A-Za-z0-9._/-]+)?)$"


MCP_TOOL_CATALOG: dict[str, dict[str, Any]] = {
    "calculator": {
        "name": "calculator",
        "description": "기본 산술식만 계산한다.",
        "inputSchema": {
            "type": "object",
            "properties": {"expression": {"type": "string", "maxLength": 500}},
            "required": ["expression"],
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
        "_meta": {"lab/capability": "calculator.execute"},
    },
    "get_time": {
        "name": "get_time",
        "description": "현재 UTC 시각을 읽는다.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": [],
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": False,
            "openWorldHint": False,
        },
        "_meta": {"lab/capability": "clock.read"},
    },
    "read_file": {
        "name": "read_file",
        "description": "sandbox의 data 소유자/shared 경로에서 UTF-8 파일 하나를 읽는다.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "pattern": PRIVATE_PATH_PATTERN,
                    "maxLength": 240,
                }
            },
            "required": ["path"],
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
        "_meta": {"lab/capability": "filesystem.read"},
    },
    "list_files": {
        "name": "list_files",
        "description": "sandbox의 data 경로 하나를 나열한다.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "pattern": LIST_PATH_PATTERN,
                    "maxLength": 240,
                }
            },
            "required": ["path"],
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
        "_meta": {"lab/capability": "filesystem.list"},
    },
    "write_file": {
        "name": "write_file",
        "description": "승인 가능한 sandbox data 경로에 제한된 UTF-8 내용을 쓴다.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "pattern": PRIVATE_PATH_PATTERN,
                    "maxLength": 240,
                },
                "content": {"type": "string", "maxLength": 4096},
            },
            "required": ["path", "content"],
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": False,
            "openWorldHint": False,
        },
        "_meta": {"lab/capability": "filesystem.write"},
    },
    # 이전 run_command 흐름을 재현할 때만 명시적으로 선택한다. 기본/읽기 전용
    # 프로필에는 노출하지 않는다.
    "run_command": {
        "name": "run_command",
        "description": "이전 버전 호환용 제한 명령. Day 9 기본 프로필에는 노출하지 않는다.",
        "inputSchema": {
            "type": "object",
            "properties": {"command": {"type": "string", "maxLength": 240}},
            "required": ["command"],
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": False,
            "openWorldHint": False,
        },
        "_meta": {"lab/capability": "command.read"},
    },
}


@dataclass(frozen=True)
class ToolProfile:
    name: str
    exposed_tools: tuple[str, ...]


READ_ONLY_PROFILE = ToolProfile(
    "read_only",
    ("calculator", "get_time", "read_file", "list_files"),
)
WRITE_ENABLED_PROFILE = ToolProfile(
    "write_enabled",
    (*READ_ONLY_PROFILE.exposed_tools, "write_file"),
)
LEGACY_COMPAT_PROFILE = ToolProfile(
    "legacy_compat",
    (*WRITE_ENABLED_PROFILE.exposed_tools, "run_command"),
)

PROFILES = {
    profile.name: profile
    for profile in (READ_ONLY_PROFILE, WRITE_ENABLED_PROFILE, LEGACY_COMPAT_PROFILE)
}


def get_tool_profile(name: str) -> ToolProfile:
    try:
        return PROFILES[name]
    except KeyError as exc:
        raise ValueError(f"unknown MCP tool profile: {name}") from exc


def _schema_digest(profile: ToolProfile) -> str:
    material = {
        name: MCP_TOOL_CATALOG[name]
        for name in profile.exposed_tools
    }
    encoded = json.dumps(
        material, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return f"sha256:{sha256(encoded).hexdigest()}"


def profile_snapshot(profile: ToolProfile) -> dict[str, Any]:
    return {
        "profile": profile.name,
        "exposed_tools": list(profile.exposed_tools),
        "schema_digest": _schema_digest(profile),
        "declared_capabilities": {
            name: MCP_TOOL_CATALOG[name]["_meta"]["lab/capability"]
            for name in profile.exposed_tools
        },
    }


def tools_for_mcp(profile: ToolProfile) -> list[dict[str, Any]]:
    """MCP server의 ``tools/list``에 해당하는 정의를 반환한다."""
    return [dict(MCP_TOOL_CATALOG[name]) for name in profile.exposed_tools]


def tools_for_openai(profile: ToolProfile) -> list[dict[str, Any]]:
    """동일한 MCP 계약을 기존 Responses API 함수 도구 형식으로 변환한다."""
    return [
        {
            "type": "function",
            "name": tool["name"],
            "strict": True,
            "description": tool["description"],
            "parameters": tool["inputSchema"],
        }
        for tool in tools_for_mcp(profile)
    ]


def validate_tool_schema(
    profile: ToolProfile,
    tool_name: str,
    arguments: Mapping[str, Any],
) -> ToolSchemaDecision:
    """노출 여부와 작은 JSON Schema 부분집합을 Runtime에서 다시 검사한다."""
    digest = _schema_digest(profile)
    if tool_name not in profile.exposed_tools:
        return ToolSchemaDecision(
            False, "TOOL_NOT_EXPOSED_IN_PROFILE", profile.name,
            tool_name, None, digest,
        )
    if not isinstance(arguments, Mapping):
        return ToolSchemaDecision(
            False, "MCP_ARGUMENTS_MUST_BE_OBJECT", profile.name,
            tool_name, None, digest,
        )

    definition = MCP_TOOL_CATALOG[tool_name]
    schema = definition["inputSchema"]
    properties = schema["properties"]
    required = set(schema.get("required", ()))
    keys = set(arguments)
    capability = definition["_meta"]["lab/capability"]

    if missing := required - keys:
        return ToolSchemaDecision(
            False, "MCP_REQUIRED_ARGUMENT_MISSING", profile.name,
            tool_name, capability, digest,
        )
    if schema.get("additionalProperties") is False and (keys - set(properties)):
        return ToolSchemaDecision(
            False, "MCP_ADDITIONAL_ARGUMENT_DENIED", profile.name,
            tool_name, capability, digest,
        )

    for name, value in arguments.items():
        property_schema = properties[name]
        expected = property_schema.get("type")
        if expected == "string" and not isinstance(value, str):
            return ToolSchemaDecision(
                False, "MCP_ARGUMENT_TYPE_MISMATCH", profile.name,
                tool_name, capability, digest,
            )
        if isinstance(value, str):
            if len(value) > int(property_schema.get("maxLength", len(value))):
                return ToolSchemaDecision(
                    False, "MCP_ARGUMENT_TOO_LONG", profile.name,
                    tool_name, capability, digest,
                )
            if pattern := property_schema.get("pattern"):
                normalized = value.replace("\\", "/")
                if normalized.startswith("/") or ".." in normalized.split("/"):
                    return ToolSchemaDecision(
                        False, "MCP_PATH_OUTSIDE_PROFILE_SCOPE", profile.name,
                        tool_name, capability, digest,
                    )
                if re.fullmatch(pattern, normalized) is None:
                    return ToolSchemaDecision(
                        False, "MCP_ARGUMENT_PATTERN_MISMATCH", profile.name,
                        tool_name, capability, digest,
                    )

    return ToolSchemaDecision(
        True, "MCP_TOOL_SCHEMA_ALLOWED", profile.name,
        tool_name, capability, digest,
    )
