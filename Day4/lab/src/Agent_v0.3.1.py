# Agent_v0.2.2.py

import ast
import json
import operator
import os

from runtime import Runtime

from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv
from openai import OpenAI

from trace_logger import TraceLogger
from authorization import authorize

DAY4_RUNTIME = Runtime()

# =========================
# Environment
# =========================

load_dotenv()

client = OpenAI(
    api_key=os.environ["OPENAI_API_KEY"]
)

MODEL = "gpt-5.5"


# =========================
# Filesystem
# =========================

SANDBOX_ROOT = Path(
    "./sandbox"
).resolve()


PATH_TOOLS = {
    "read_file",
    "write_file",
    "list_files"
}


# =========================
# Runtime Result Schema
# =========================

def make_runtime_result(
    *,
    ok: bool,
    status: str,
    end_stage: str,
    tool_name: str,
    call_id: str,
    data=None,
    error_code=None,
    error_message=None,
    meta_extra=None
) -> dict:

    error = None

    if not ok:

        error = {
            "code": error_code,
            "message": error_message
        }

    meta = {
        "tool_name": tool_name,
        "call_id": call_id
    }

    if meta_extra:

        meta.update(meta_extra)

    return {
        "ok": ok,
        "status": status,
        "end_stage": end_stage,
        "data": data,
        "error": error,
        "meta": meta
    }


# =========================
# Observation Adapter
# Runtime Result != LLM Observation
# =========================

def to_observation(
    runtime_result: dict
) -> dict:

    if runtime_result["ok"]:

        return {
            "status": "success",
            "data":
                runtime_result["data"]
        }

    return {
        "status":
            runtime_result["status"],

        "error": {
            "code":
                runtime_result[
                    "error"
                ]["code"],

            "message":
                runtime_result[
                    "error"
                ]["message"]
        }
    }


# =========================
# Validator
# =========================

def safe_resolve( user_path: str ) -> Path:

    candidate = ( SANDBOX_ROOT / user_path ).resolve()

    try:

        candidate.relative_to( SANDBOX_ROOT )

    except ValueError:

        raise PermissionError( f"path escapes sandbox: {user_path}" )

    return candidate


# =========================
# Argument Validation
# =========================

ARGUMENT_SPEC = {

    "calculator": {
        "expression": str
    },

    "read_file": {
        "path": str
    },

    "get_time": {},

    "write_file": {
        "path": str,
        "content": str
    },

    "list_files": {
        "path": str
    },

    "run_command": {
        "command": str
    }
}


def validate_arguments(
    tool_name: str,
    arguments: dict
) -> dict:

    if not isinstance(
        arguments,
        dict
    ):

        return {
            "allowed": False,
            "reason":
                "arguments must be an object"
        }

    spec = ARGUMENT_SPEC.get(
        tool_name
    )

    if spec is None:

        return {
            "allowed": False,
            "reason":
                f"unknown tool: {tool_name}"
        }

    # Missing / type 검사
    for arg_name, expected_type \
            in spec.items():

        if arg_name not in arguments:

            return {
                "allowed": False,
                "reason":
                    f"missing argument: {arg_name}"
            }

        if not isinstance(
            arguments[arg_name],
            expected_type
        ):

            return {
                "allowed": False,
                "reason": (
                    f"argument '{arg_name}' "
                    f"must be "
                    f"{expected_type.__name__}"
                )
            }

    # 추가 argument 차단
    unexpected = (
        set(arguments.keys())
        - set(spec.keys())
    )

    if unexpected:

        return {
            "allowed": False,
            "reason": (
                "unexpected arguments: "
                + ", ".join(
                    sorted(unexpected)
                )
            )
        }

    return {
        "allowed": True,
        "reason": None
    }


# =========================
# Full Validation
#
# 역할:
# argument 구조 검사
# path canonicalization
# command parsing
#
# Permission 판단은 하지 않음
# =========================

def validate_tool_call(
    tool_name: str,
    arguments: dict
) -> dict:

    argument_result = (
        validate_arguments(
            tool_name,
            arguments
        )
    )

    if not argument_result["allowed"]:

        return {
            "allowed": False,
            "reason":
                argument_result["reason"],
            "resolved_path": None,
            "command_base": None
        }

    try:

        # =====================
        # File tools
        # =====================

        if tool_name in PATH_TOOLS:

            resolved_path = (
                safe_resolve( arguments["path"] )
            )

            return {
                "allowed": True,
                "reason": None,
                "resolved_path":
                    resolved_path,
                "command_base": None
            }

        # =====================
        # run_command
        # =====================

        if tool_name == "run_command":

            command = ( arguments["command"].strip() )

            parts = command.split()

            if not parts:

                return {
                    "allowed": False,
                    "reason":
                        "empty command",
                    "resolved_path": None,
                    "command_base": None
                }

            command_base = parts[0]

            resolved_path = None

            # -----------------
            # pwd
            # -----------------

            if command_base == "pwd":

                if len(parts) != 1:

                    return {
                        "allowed": False,
                        "reason":
                            "usage: pwd",
                        "resolved_path": None,
                        "command_base":
                            command_base
                    }

            # -----------------
            # cat
            # -----------------

            elif command_base == "cat":

                if len(parts) != 2:

                    return {
                        "allowed": False,
                        "reason":
                            "usage: cat <file>",
                        "resolved_path": None,
                        "command_base":
                            command_base
                    }

                resolved_path = (
                    safe_resolve( parts[1] )
                )

            # -----------------
            # ls
            # -----------------

            elif command_base == "ls":

                if len(parts) > 2:

                    return {
                        "allowed": False,
                        "reason":
                            "usage: ls [path]",
                        "resolved_path": None,
                        "command_base":
                            command_base
                    }

                target = (
                    parts[1]
                    if len(parts) == 2
                    else "."
                )

                resolved_path = (
                    safe_resolve( target )
                )

            # unknown command도 parsing은 성공.
            # Authorization에서 DENY.
            return {
                "allowed": True,
                "reason": None,
                "resolved_path":
                    resolved_path,
                "command_base":
                    command_base
            }

        # calculator / get_time
        return {
            "allowed": True,
            "reason": None,
            "resolved_path": None,
            "command_base": None
        }

    except PermissionError as e:

        return {
            "allowed": False,
            "reason": str(e),
            "resolved_path": None,
            "command_base": None
        }

    except Exception as e:

        return {
            "allowed": False,
            "reason":
                f"validator error: {e}",
            "resolved_path": None,
            "command_base": None
        }


# =========================
# Tools
# =========================


# -------------------------
# Safe Calculator
# eval() 제거
# -------------------------

_ALLOWED_BINARY_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow
}

_ALLOWED_UNARY_OPS = {
    ast.UAdd: operator.pos,
    ast.USub: operator.neg
}


def _eval_arithmetic(
    node
):

    if isinstance(
        node,
        ast.Expression
    ):

        return _eval_arithmetic(
            node.body
        )

    if isinstance(
        node,
        ast.Constant
    ):

        if isinstance(
            node.value,
            (int, float)
        ):

            return node.value

        raise ValueError(
            "only numeric constants allowed"
        )

    if isinstance(
        node,
        ast.BinOp
    ):

        op = _ALLOWED_BINARY_OPS.get(
            type(node.op)
        )

        if op is None:

            raise ValueError(
                "operator not allowed"
            )

        left = _eval_arithmetic(
            node.left
        )

        right = _eval_arithmetic(
            node.right
        )

        return op(left, right)

    if isinstance(
        node,
        ast.UnaryOp
    ):

        op = _ALLOWED_UNARY_OPS.get(
            type(node.op)
        )

        if op is None:

            raise ValueError(
                "unary operator not allowed"
            )

        operand = _eval_arithmetic(
            node.operand
        )

        return op(operand)

    raise ValueError(
        "unsupported expression"
    )


def calculator(
    expression: str
) -> str:

    tree = ast.parse(
        expression,
        mode="eval"
    )

    result = _eval_arithmetic(
        tree
    )

    return str(result)


# -------------------------
# read_file
#
# 이미 validated +
# authorized 된 Path를 받음
# -------------------------

def read_file(
    file_path: Path
) -> str:

    if not file_path.exists():

        raise FileNotFoundError(
            f"file not found: "
            f"{file_path.name}"
        )

    if not file_path.is_file():

        raise IsADirectoryError(
            f"not a file: "
            f"{file_path.name}"
        )

    return file_path.read_text(
        encoding="utf-8"
    )


# -------------------------
# get_time
# -------------------------

def get_time() -> str:

    return (
        datetime.now()
        .isoformat()
    )


# -------------------------
# write_file
# -------------------------

def write_file(
    file_path: Path,
    content: str
) -> str:

    file_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    file_path.write_text(
        content,
        encoding="utf-8"
    )

    relative_path = (
        file_path
        .relative_to(SANDBOX_ROOT)
        .as_posix()
    )

    return (
        f"Wrote file: "
        f"{relative_path}"
    )


# -------------------------
# list_files
# -------------------------

def list_files(
    target: Path
) -> str:

    if not target.exists():

        raise FileNotFoundError(
            "path not found"
        )

    if not target.is_dir():

        raise NotADirectoryError(
            "not a directory"
        )

    items = []

    for child in target.iterdir():

        relative = (
            child
            .relative_to(SANDBOX_ROOT)
            .as_posix()
        )

        items.append(relative)

    return "\n".join(
        sorted(items)
    )


# -------------------------
# run_command
#
# 실제 shell 실행 아님.
# normalized command를
# Python 함수로 dispatch.
# -------------------------

def run_command(
    command_base: str,
    resolved_path: Path | None
) -> str:

    if command_base == "pwd":

        return "sandbox"

    if command_base == "ls":

        if resolved_path is None:

            raise ValueError(
                "ls requires resolved path"
            )

        return list_files(
            resolved_path
        )

    if command_base == "cat":

        if resolved_path is None:

            raise ValueError(
                "cat requires resolved path"
            )

        return read_file(
            resolved_path
        )

    # Authorization/Runtime bug
    raise RuntimeError(
        "unauthorized command"
        "reached execution"
    )


# =========================
# Tool Schemas
# =========================

TOOLS = [

    {
        "type": "function",
        "name": "calculator",

        "description":
            "Perform a basic arithmetic calculation.",

        "parameters": {

            "type": "object",

            "properties": {

                "expression": {
                    "type": "string",
                    "description":
                        "Arithmetic expression, e.g. 37*82"
                }
            },

            "required": [
                "expression"
            ],

            "additionalProperties": False
        },

        "strict": True
    },

    {
        "type": "function",
        "name": "read_file",

        "description":
            "Read a UTF-8 text file.",

        "parameters": {

            "type": "object",

            "properties": {

                "path": {
                    "type": "string",
                    "description":
                        "Relative sandbox path."
                }
            },

            "required": [
                "path"
            ],

            "additionalProperties": False
        },

        "strict": True
    },

    {
        "type": "function",
        "name": "get_time",

        "description":
            "Get current local system time.",

        "parameters": {

            "type": "object",

            "properties": {},

            "required": [],

            "additionalProperties": False
        },

        "strict": True
    },

    {
        "type": "function",
        "name": "write_file",

        "description":
            "Write a UTF-8 text file.",

        "parameters": {

            "type": "object",

            "properties": {

                "path": {
                    "type": "string",
                    "description":
                        "Relative sandbox path."
                },

                "content": {
                    "type": "string"
                }
            },

            "required": [
                "path",
                "content"
            ],

            "additionalProperties": False
        },

        "strict": True
    },

    {
        "type": "function",
        "name": "list_files",

        "description":
            "List files in a sandbox directory.",

        "parameters": {

            "type": "object",

            "properties": {

                "path": {
                    "type": "string"
                }
            },

            "required": [
                "path"
            ],

            "additionalProperties": False
        },

        "strict": True
    },

    {
        "type": "function",
        "name": "run_command",

        "description": (
            "Run one restricted sandbox command. "
            "Allowed commands are controlled "
            "by runtime permission policy."
        ),

        "parameters": {

            "type": "object",

            "properties": {

                "command": {
                    "type": "string"
                }
            },

            "required": [
                "command"
            ],

            "additionalProperties": False
        },

        "strict": True
    }
]


# =========================
# Execution Error Mapping
# =========================

def get_execution_error_code(
    error: Exception
) -> str:

    if isinstance(
        error,
        FileNotFoundError
    ):

        return "FILE_NOT_FOUND"

    if isinstance(
        error,
        IsADirectoryError
    ):

        return "IS_DIRECTORY"

    if isinstance(
        error,
        NotADirectoryError
    ):

        return "NOT_DIRECTORY"

    if isinstance(
        error,
        ZeroDivisionError
    ):

        return "DIVISION_BY_ZERO"

    if isinstance(
        error,
        ValueError
    ):

        return "INVALID_TOOL_INPUT"

    return "TOOL_EXECUTION_ERROR"


# =========================
# Tool Dispatcher / Runtime
# =========================

def execute_tool(
    tool_name: str,
    arguments: dict,
    logger: TraceLogger,
    call_id: str
) -> dict:

    tool_info = {
        "name": tool_name,
        "arguments": arguments
    }

    # =========================
    # 1. VALIDATION
    # =========================

    validation_result = (
        validate_tool_call(
            tool_name,
            arguments
        )
    )

    if not validation_result[
        "allowed"
    ]:

        logger.log(
            event_type=
                "tool_validation",

            tool=tool_info,

            validation={
                "status": "denied",
                "reason":
                    validation_result[
                        "reason"
                    ]
            },

            data={
                "call_id": call_id
            }
        )

        runtime_result = (
            make_runtime_result(
                ok=False,
                status="denied",
                end_stage="validation",
                tool_name=tool_name,
                call_id=call_id,
                error_code=
                    "VALIDATION_DENIED",
                error_message=
                    validation_result[
                        "reason"
                    ]
            )
        )

        logger.log(
            event_type="tool_result",

            tool=tool_info,

            result={
                "status": "denied",
                "error_code":
                    "VALIDATION_DENIED"
            },

            data={
                "call_id": call_id
            }
        )

        return runtime_result


    resolved_path = (
        validation_result.get(
            "resolved_path"
        )
    )

    command_base = (
        validation_result.get(
            "command_base"
        )
    )

    logger.log(
        event_type="tool_validation",

        tool=tool_info,

        validation={
            "status": "passed",
            "reason": None
        },

        data={
            "call_id": call_id,

            "resolved_path": (
                str(resolved_path)
                if resolved_path
                else None
            ),

            "command_base":
                command_base
        }
    )


    # =========================
    # 2. AUTHORIZATION
    # =========================

    authz_result = authorize(
        tool_name=tool_name,
        resolved_path=resolved_path,
        command_base=command_base
    )

    logger.log(
        event_type=
            "tool_authorization",

        tool=tool_info,

        authorization={
            "status": (
                "allowed"
                if authz_result[
                    "allowed"
                ]
                else "denied"
            ),

            "reason":
                authz_result[
                    "reason"
                ]
        },

        data={
            "call_id": call_id
        }
    )


    # =========================
    # 3. RUNTIME ENFORCEMENT
    # =========================

    if not authz_result["allowed"]:

        runtime_result = (
            make_runtime_result(
                ok=False,
                status="denied",
                end_stage=
                    "authorization",
                tool_name=tool_name,
                call_id=call_id,
                error_code=
                    "PERMISSION_DENIED",
                error_message=
                    authz_result[
                        "reason"
                    ]
            )
        )

        logger.log(
            event_type="tool_result",

            tool=tool_info,

            result={
                "status": "denied",
                "error_code":
                    "PERMISSION_DENIED"
            },

            data={
                "call_id": call_id
            }
        )

        return runtime_result


    # =========================
    # 4. EXECUTION START
    # =========================

    logger.log(
        event_type=
            "tool_execution",

        tool=tool_info,

        execution={
            "attempted": True,
            "status": "started"
        },

        data={
            "call_id": call_id
        }
    )


    # =========================
    # 5. EXECUTE TOOL
    # =========================

    try:

        if tool_name == "calculator":

            tool_output = calculator(
                arguments["expression"]
            )

        elif tool_name == "read_file":

            tool_output = read_file(
                resolved_path
            )

        elif tool_name == "get_time":

            tool_output = (
                get_time()
            )

        elif tool_name == "write_file":

            tool_output = write_file(
                resolved_path,
                arguments["content"]
            )

        elif tool_name == "list_files":

            tool_output = list_files(
                resolved_path
            )

        elif tool_name == "run_command":

            tool_output = run_command(
                command_base,
                resolved_path
            )

        else:

            # 정상 구조라면
            # Authorization에서 이미 차단됨
            raise RuntimeError(
                "unknown tool reached "
                "execution"
            )


    # =========================
    # Execution Error
    # =========================

    except Exception as e:

        error_code = (
            get_execution_error_code(
                e
            )
        )

        logger.log(
            event_type="tool_result",

            tool=tool_info,

            execution={
                "attempted": True,
                "status": "error"
            },

            result={
                "status": "error",
                "error_code":
                    error_code,
                "message": str(e)
            },

            data={
                "call_id": call_id
            }
        )

        return make_runtime_result(
            ok=False,
            status="error",
            end_stage="execution",
            tool_name=tool_name,
            call_id=call_id,
            error_code=error_code,
            error_message=str(e)
        )


    # =========================
    # 6. SUCCESS
    # =========================

    logger.log(
        event_type="tool_result",

        tool=tool_info,

        execution={
            "attempted": True,
            "status": "completed"
        },

        result={
            "status": "success",
            "output": tool_output
        },

        data={
            "call_id": call_id
        }
    )

    return make_runtime_result(
        ok=True,
        status="success",
        end_stage="execution",
        tool_name=tool_name,
        call_id=call_id,
        data=tool_output,
        meta_extra={
            "resolved_path": (
                str(resolved_path)
                if resolved_path
                else None
            ),
            "command_base":
                command_base
        }
    )


# =========================
# Agent Loop
# =========================

def run_agent(
    user_input: str
):

    logger = TraceLogger()

    logger.log(
        "run_start",
        {
            "user_input":
                user_input
        }
    )

    input_items = [

        {
            "role": "user",
            "content":
                user_input
        }
    ]


    while True:

        logger.next_step()

        logger.log(
            "model_request",
            {
                "input_items":
                    input_items
            }
        )

        print(
            f"\n============= "
            f"STEP {logger.step} "
            f"============="
        )

        response = (
            client.responses.create(

                model=MODEL,

                instructions=(
                    "You are a minimal "
                    "tool-using agent. "
                    "Use tools whenever "
                    "external information "
                    "or calculation is required. "
                    "You may use multiple tools "
                    "sequentially."
                ),

                tools=TOOLS,

                input=input_items
            )
        )

        logger.log(
            "model_response",

            {
                "response_id":
                    response.id,

                "output_text":
                    response.output_text,

                "output": [
                    item.model_dump()
                    for item
                    in response.output
                ]
            }
        )


        # 모델 출력을 다음 context에 유지
        input_items += (
            response.output
        )

        tool_called = False


        for item in response.output:

            if (
                item.type
                != "function_call"
            ):

                continue


            tool_called = True

            tool_name = item.name

            arguments = json.loads(
                item.arguments
            )


            # =====================
            # Tool Call Trace
            # =====================

            logger.log(
                event_type=
                    "tool_call",

                tool={
                    "name":
                        tool_name,

                    "arguments":
                        arguments
                },

                data={
                    "call_id":
                        item.call_id
                }
            )


            print(
                "\n[TOOL CALL]"
            )

            print(
                "name      :",
                tool_name
            )

            print(
                "arguments :",
                arguments
            )


            # =====================
            # Runtime
            #
            # Validation
            # Authorization
            # Enforcement
            # Execution
            # =====================

            runtime_result = DAY4_RUNTIME.execute_tool(
                tool_name=tool_name,
                arguments=arguments,
                call_id=item.call_id,
                run_id=run_id,
                actor=actor,
                provenance=current_provenance,
            ).to_dict()


            # =====================
            # Runtime Result
            # → LLM Observation
            # =====================

            observation = (
                to_observation(
                    runtime_result
                )
            )


            print(
                "\n[RUNTIME RESULT]"
            )

            print(
                runtime_result
            )


            print(
                "\n[OBSERVATION]"
            )

            print(
                observation
            )


            # function result를
            # JSON 문자열로 모델에 전달
            input_items.append(

                {
                    "type":
                        "function_call_output",

                    "call_id":
                        item.call_id,

                    "output":
                        json.dumps(
                            observation,
                            ensure_ascii=False
                        )
                }
            )


        # =========================
        # No more tool calls
        # =========================

        if not tool_called:

            logger.log(
                "final_response",

                {
                    "content":
                        response.output_text
                }
            )

            logger.log(
                "run_end",

                {
                    "status":
                        "success"
                }
            )

            print(
                "\n[FINAL RESPONSE]"
            )

            print(
                response.output_text
            )

            return (
                response.output_text
            )


# =========================
# CLI
# =========================

if __name__ == "__main__":

    while True:

        user_input = input(
            "\nUSER > "
        )

        if user_input.lower() in {
            "exit",
            "quit"
        }:

            break

        run_agent(
            user_input
        )