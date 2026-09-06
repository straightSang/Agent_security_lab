# 모듈이름: security.tool_schema
# 역할: Schema gate, MCP 도구 카탈로그, 작업별 노출 프로필, 서버 측 inputSchema 재검사
# 호출 주체: runtime.Runtime.execute_tool()의 0단계, agent(도구 목록 생성)
#
# 기능 설명:
#     MCP inputSchema는 모델에게 보여 주는 설명인 동시에 서버가 다시 검증해야
#     하는 입력 계약이다. 모델에게 보여 줬다는 사실이 검증을 대신하지 않는다.
#
#     [세 개의 프로필]
#
#         read_only      calculator, get_time, read_file, list_files
#         write_enabled  read_only + write_file
#         legacy_compat  write_enabled + run_command (회귀 재현 전용)
#
#     기본값은 read_only다. 쓰기가 필요한 실험만 명시적으로 넓힌다.
#
#     readOnlyHint, destructiveHint 등은 UI 표시용 힌트다. 보안 판단에 쓰면
#     모델이나 서버 제공자가 자기 도구를 '안전하다'고 선언하는 것만으로 검사를
#     통과하게 된다.

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from hashlib import sha256
from typing import Any

from .types import ToolSchemaDecision

# [A-01] Day 9까지는 이 정규식이 '어느 범위까지 허용되는가'까지 결정했다. 그 결과
# ``permission.POLICY``의 allowed_scopes 여러 개가 어떤 호출로도 도달하지 못했다.
# 이제 schema 단계는 '구조적으로 안전한 상대 경로인가'만 판정하고, 실제 범위
# 판정은 단일 기준인 ``permission.POLICY``가 담당한다. traversal·절대 경로 차단은
# ``validate_tool_schema()``가 패턴 검사보다 먼저 수행하므로 여기서 다루지 않는다.
SAFE_RELATIVE_PATH_PATTERN = r"^[A-Za-z0-9._][A-Za-z0-9._/-]*$"

# 이전 이름을 참조하던 코드·문서와의 호환을 위해 별칭을 남긴다.
PRIVATE_PATH_PATTERN = SAFE_RELATIVE_PATH_PATTERN
LIST_PATH_PATTERN = SAFE_RELATIVE_PATH_PATTERN


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


# 클래스이름: ToolProfile
# 필드:
#     name (str): 프로필 이름 (read_only / write_enabled / legacy_compat)
#     exposed_tools (tuple[str, ...]): 이 프로필이 노출하는 도구 이름들
# 기능 설명:
#     작업별로 어떤 도구를 보여 줄지 정하는 신뢰된 설정이다.
#
#     운영 환경에서는 OAuth token scope가 프로필을 정해야 한다. 랩에서는 test
#     harness가 정한다. 어느 쪽이든 모델이나 관측값이 정하지 않는다.
#
#     쓰기 도구를 아예 보여 주지 않으면 모델이 쓰기를 제안할 수 없다. 뒤에서
#     막는 것보다 앞에서 안 보여 주는 쪽이 공격 표면을 줄인다.
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


# 함수이름: get_tool_profile
# 인자:
#     name (str): 프로필 이름
# 반환값:
#     ToolProfile: 해당 프로필
#     ValueError: 등록되지 않은 이름일 때 발생
# 기능 설명:
#     이름으로 프로필을 찾는다. 없는 이름은 기본값으로 넘어가지 않고 즉시
#     실패한다. 오타가 조용히 넓은 프로필로 이어지면 안 되기 때문이다.
def get_tool_profile(name: str) -> ToolProfile:
    try:
        return PROFILES[name]
    except KeyError as exc:
        raise ValueError(f"unknown MCP tool profile: {name}") from exc


# 함수이름: _schema_digest
# 인자:
#     profile (ToolProfile): 대상 프로필
# 반환값:
#     str: 'sha256:...' 형태의 해시
# 기능 설명:
#     이 프로필이 노출하는 도구 정의 전체의 해시를 만든다.
#
#     "판정에 사용한 도구 정의가 이것이었다"를 기록으로 남긴다. catalog가
#     나중에 바뀌면 digest가 달라지므로, 과거 실험 결과를 다른 정의로 만든
#     결과와 혼동하지 않게 된다.
def _schema_digest(profile: ToolProfile) -> str:
    material = {
        name: MCP_TOOL_CATALOG[name]
        for name in profile.exposed_tools
    }
    encoded = json.dumps(
        material, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return f"sha256:{sha256(encoded).hexdigest()}"


# 함수이름: profile_snapshot
# 인자:
#     profile (ToolProfile): 대상 프로필
# 반환값:
#     dict: profile · exposed_tools · schema_digest · declared_capabilities
# 기능 설명:
#     control plane 스냅샷에 들어갈 프로필 사본을 만든다. 공격 전후로 비교해
#     도구 노출 범위가 변조되지 않았음을 확인한다.
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


# 함수이름: tools_for_mcp
# 인자:
#     profile (ToolProfile): 대상 프로필
# 반환값:
#     list[dict]: MCP tools/list에 해당하는 독립된 도구 정의들
# 기능 설명:
#     모델에게 광고할 도구 목록을 만든다.
#
#     호출자가 반환된 description, inputSchema, annotations를 바꾸더라도 Runtime이
#     신뢰하는 원본 catalog는 변하지 않아야 한다. 얕은 복사면 중첩된 dict를 통해
#     원본이 오염된다. 광고본이 원본을 바꿀 수 있으면 '서버가 다시 검사한다'는
#     전제가 무너진다. D9의 격리 검사가 이 성질을 회귀로 확인한다.
def tools_for_mcp(profile: ToolProfile) -> list[dict[str, Any]]:
    return [deepcopy(MCP_TOOL_CATALOG[name]) for name in profile.exposed_tools]


# 함수이름: tools_for_openai
# 인자:
#     profile (ToolProfile): 대상 프로필
# 반환값:
#     list[dict]: Responses API 함수 도구 형식의 정의들
# 기능 설명:
#     같은 MCP 계약을 OpenAI 함수 도구 형식으로 변환한다.
#
#     도구 정의의 단일 기준은 MCP catalog 하나다. API 형식마다 정의를 따로
#     관리하면 두 정의가 어긋나고, 모델이 본 것과 서버가 검사하는 것이 달라진다.
def tools_for_openai(profile: ToolProfile) -> list[dict[str, Any]]:
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


# 함수이름: validate_tool_schema
# 인자:
#     profile (ToolProfile): 이 호출에 적용할 노출 프로필
#     tool_name (str): 제안된 도구 이름
#     arguments (Mapping): 제안된 인자
# 반환값:
#     ToolSchemaDecision: 통과 여부와 안정적인 reason
# 기능 설명:
#     노출 여부와 인자 계약을 서버에서 다시 검사한다. Runtime의 첫 관문이다.
#
#         1. 이 프로필에 노출된 도구인가   -> TOOL_NOT_EXPOSED_IN_PROFILE
#         2. 인자가 객체인가               -> MCP_ARGUMENTS_MUST_BE_OBJECT
#         3. 필수 인자가 있는가            -> MCP_REQUIRED_ARGUMENT_MISSING
#         4. 선언되지 않은 인자가 없는가   -> MCP_ADDITIONAL_ARGUMENT_DENIED
#         5. 타입·길이·경로 형식          -> MCP_ARGUMENT_* / MCP_PATH_*
#
#     [A-01] 경로 검사는 '구조적으로 안전한 상대 경로인가'까지만 본다. 어느
#     범위까지 허용되는지는 security.permission의 POLICY가 정한다. 이전에는 이
#     정규식이 범위까지 결정해 POLICY의 여러 분기가 도달 불가 상태였다.
#
#     절대 경로와 '..'는 정규식 통과 여부와 무관하게 먼저 막는다. 패턴이 넓어져도
#     이 방어는 유지된다.
#
#     readOnlyHint 같은 값은 표시용 힌트일 뿐 권한이 아니다. 서버가 신뢰하는 것은
#     _meta의 capability와 자체 catalog뿐이다.
def validate_tool_schema(
    profile: ToolProfile,
    tool_name: str,
    arguments: Mapping[str, Any],
) -> ToolSchemaDecision:
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
        # [A-06] 어떤 인자가 빠졌는지 계산해 놓고 버리지 않는다. reason은 안정적인
        # 규칙 식별자로 유지하고, 사람이 읽는 세부는 detail에 담는다.
        return ToolSchemaDecision(
            False, "MCP_REQUIRED_ARGUMENT_MISSING", profile.name,
            tool_name, capability, digest,
            detail="missing=" + ",".join(sorted(missing)),
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
