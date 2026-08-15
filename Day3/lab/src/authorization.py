from pathlib import Path

from permission import POLICY


SOURCE_DIR = Path(__file__).resolve().parent

SANDBOX_ROOT = (
    SOURCE_DIR / "sandbox"
).resolve()


PATH_TOOLS = {
    "read_file",
    "write_file",
    "list_files"
}


def authorize_path(
    *,
    tool_name: str,
    resolved_path: Path
) -> dict:

    tool_policy = POLICY.get(tool_name)

    if tool_policy is None:
        return {
            "allowed": False,
            "reason": (
                f"tool '{tool_name}' is not defined "
                "in permission policy"
            )
        }

    allowed_dirs = tool_policy.get("allowed_dirs")

    if not allowed_dirs:
        return {
            "allowed": False,
            "reason": (
                f"tool '{tool_name}' has no allowed_dirs "
                "in permission policy"
            )
        }

    for allowed_dir in allowed_dirs:

        allowed_path = (
            SANDBOX_ROOT / allowed_dir
        ).resolve()

        try:
            resolved_path.relative_to(allowed_path)

            return {
                "allowed": True,
                "reason": None
            }

        except ValueError:
            continue

    return {
        "allowed": False,
        "reason": (
            f"path '{resolved_path}' is not allowed "
            f"for tool '{tool_name}'"
        )
    }


def authorize_command(
    command_base: str
) -> dict:

    tool_policy = POLICY.get("run_command")

    if tool_policy is None:
        return {
            "allowed": False,
            "reason": (
                "run_command is not defined "
                "in permission policy"
            )
        }

    allowed_commands = tool_policy.get(
        "allowed_commands",
        []
    )

    if command_base not in allowed_commands:
        return {
            "allowed": False,
            "reason": (
                f"command '{command_base}' is not allowed"
            )
        }

    return {
        "allowed": True,
        "reason": None
    }


def authorize(
    *,
    tool_name: str,
    resolved_path: Path | None,
    command_base: str | None
) -> dict:

    # run_command는 경로 대신 기본 명령을 검사
    if tool_name == "run_command":

        if command_base is None:
            return {
                "allowed": False,
                "reason": "command is required"
            }

        return authorize_command(command_base)

    # 파일 도구는 허용된 폴더 안인지 검사
    if tool_name in PATH_TOOLS:

        if resolved_path is None:
            return {
                "allowed": False,
                "reason": "resolved path is required"
            }

        return authorize_path(
            tool_name=tool_name,
            resolved_path=resolved_path
        )

    # 경로가 필요 없는 도구
    if tool_name in {
        "calculator",
        "get_time"
    }:

        tool_policy = POLICY.get(tool_name)

        if tool_policy.get("allowed"):

            return {
                "allowed": True,
                "reason": None
            }

    return {
        "allowed": False,
        "reason": f"unknown tool '{tool_name}'"
    }