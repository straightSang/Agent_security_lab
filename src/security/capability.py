# 모듈이름: security.capability
# 역할: 정규화된 도구 제안을 실행에 필요한 최소 capability로 매핑한다
# 호출 주체: runtime.Runtime.execute_tool()의 2단계, experiment_support(스냅샷용)
#
# 기능 설명:
#     "무엇을 하려 하는가"를 (capability, action, resource) 세 값으로 바꾼다.
#     이 세 값이 이후 Policy·Authorization·Approval의 공통 입력이 된다.
#
#     도구는 늘어나지만 권한 종류는 그보다 적다. 'cat'과 'read_file'은 이름이
#     다르지만 같은 능력이다. 능력 단위로 묶어야 규칙을 두 벌 유지하지 않게 되고,
#     새 도구가 추가돼도 정책이 그대로 적용된다.

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

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


# 함수이름: _relative_resource
# 인자:
#     path (Path | None): 정규화된 절대 경로. 경로가 없는 도구는 None
#     sandbox_root (Path): 상대화 기준
# 반환값:
#     str | None: sandbox 기준 상대 경로. sandbox 루트 자체면 '.'
# 기능 설명:
#     절대 경로를 정책이 다루는 상대 경로 표기로 바꾼다.
#
#     이 값은 정책 판정의 입력이자 trace에 기록되는 값이다. 절대 경로를 그대로
#     쓰면 실행 환경마다 달라져 재현 digest가 흔들리고, 호스트의 디렉터리 구조가
#     로그에 남는다.
def _relative_resource(path: Path | None, sandbox_root: Path) -> str | None:
    if path is None:
        return None
    return path.relative_to(sandbox_root).as_posix() or "."


# 함수이름: describe_intent
# 인자:
#     tool_name (str): 도구 이름
#     arguments (Mapping): 도구 인자
#     validation (Mapping): validate_tool_call()의 결과. 정규화된 경로를 담는다
#     sandbox_root (Path): 상대화 기준
# 반환값:
#     tuple[Capability, str, str | None]: (필요한 최소 권한, 동작 이름, 대상 리소스)
# 기능 설명:
#     "이 호출이 실제로 필요로 하는 권한이 무엇인가"를 **서버가** 계산한다.
#
#     capability는 모델이 선언하는 것이 아니라 서버가 도구 이름과 검증된 인자
#     로부터 유도한다. 모델이 "나는 읽기 권한만 필요하다"고 주장해도 그 주장은
#     입력에 포함되지 않는다. 자기 권한을 스스로 선언할 수 있으면 권한 모델이
#     성립하지 않는다.
#
#     Capability.UNKNOWN을 돌려준다. PolicyEngine이 이를
#     CAPABILITY_NOT_ALLOWLISTED로 거부한다. 기본값이 거부다.
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


# 함수이름: capability_mapping_snapshot
# 인자: 없음
# 반환값:
#     dict: tools · path_tools · commands 세 묶음의 선언형 매핑 사본
# 기능 설명:
#     control plane 스냅샷에 들어갈 capability 매핑 사본을 만든다.
#
#     "도구 -> 권한" 매핑이 실험 도중에 바뀌면 그 뒤의 모든 판정이 다른 규칙
#     위에서 일어난 것이 된다. 공격 전후로 이 사본을 해시해 비교하면 매핑이
#     변조되지 않았음을 증명할 수 있다.
def capability_mapping_snapshot() -> dict[str, object]:
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
