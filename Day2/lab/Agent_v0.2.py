# 구조 : loop + tools(함수) + tool schema + tool dispatcher(selector) + logger함수
from trace_logger import TraceLogger

import os 
import json

from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv # API key 등 로드 
from openai import OpenAI # OPENAI 모델과 통신하기 위함 

# import subprocess

# run_command 명령어 인자 제한
# 현재의 run_command()는 allowlist만 쓴다
ALLOWED_COMMANDS = {
    "pwd",
    "ls",
    "cat"
}

load_dotenv() #.env 파일의 환경변수를 os.environ에 로드

client = OpenAI(
    api_key=os.environ["OPENAI_API_KEY"]
)


MODEL = "gpt-5.5"

#===================
# Validator
# 기능 : 사용자/LLM이 준 경로를 실제 절대경로로 변환, sandbox 안에 있는지 확인, 밖이면 차단
#===================

# 1. Path 특화 검증
SANDBOX_ROOT = Path("./sandbox").resolve() # 상대 경로 객체 생성 후 절대 경로로 만듦

def safe_resolve(user_path: str) -> Path:
    candidate = (SANDBOX_ROOT / user_path).resolve()

    try:
        candidate.relative_to(SANDBOX_ROOT)
    except ValueError: # ValueError가 났다는 의미 = 샌드박스 탈출이므로 raise 키워드를 통해 보안 권한 에러인 PermissionError -> 함수실행 중단 후 예외를 호출자에게 전달.
        raise PermissionError(f"path escapes sandbox: {user_path}")

    return candidate

def validate_tool_call(name: str, arguments: dict) -> dict:
    try:
        if name in {"read_file", "write_file", "list_files"}:
            path = arguments["path"]

            resolved = safe_resolve(path)

            return {"allowed": True, "reason": None, "resolved_path": resolved}

        if name == "run_command":

            command = arguments["command"]
            parts = command.strip().split()

            if not parts:
                return {
                    "allowed": False,
                    "reason": "empty command"
                }
            base = parts[0]

            if base not in ALLOWED_COMMANDS:
                return {
                    "allowed": False,
                    "reason": f"command not allowed: {base}"
                }

            if base == "cat":

                if len(parts) != 2:

                    return {
                        "allowed": False,
                        "reason":
                            "usage: cat <sandbox-file>"
                    }

                resolved = safe_resolve(
                    parts[1]
                )

                return {
                    "allowed": True,
                    "reason": None,
                    "resolved_path": resolved
                }


            if base == "ls":

                target = (
                    parts[1]
                    if len(parts) > 1
                    else "."
                )

                resolved = safe_resolve(target)

                return {
                    "allowed": True,
                    "reason": None,
                    "resolved_path": resolved
                }


            return {
                "allowed": True,
                "reason": None
            }
        
        # calculator/get_time 등
        return {
            "allowed": True,
            "reason": None
        } 

    except PermissionError as e:
        return {
            "allowed": False,
            "reason": str(e)
        }

    except Exception as e:
        return {
            "allowed": False,
            "reason": f"validator error: {e}"
        }

# 2. 전체 대상

#===================
# Tools
#===================

# 1. calculator
def calculator(expression: str) -> str:

    result = eval(expression, {"__builtins__": {}}, {})

    return str(result)



# 2. read_file
def read_file(path: str) -> str:
    # 파일 경로를 클래스 객체로 변환.
    # file_path = Path(path)
    file_path = safe_resolve(path)

    if not file_path.exists():
        raise FileNotFoundError(
            f"file not found: {path}"
        )

    if not file_path.is_file():
        raise IsADirectoryError(
            f"not a file: {path}"
        )

    return file_path.read_text(
        encoding="utf-8"
    )

# 3. time
def get_time() -> str:
    return datetime.now().isoformat()

# 4. write_file
def write_file(path: str, content: str) -> str:

    file_path = safe_resolve(path) # validator

    file_path.parent.mkdir(parents=True, exist_ok=True)

    file_path.write_text(content, encoding="utf-8")

    return f"Wrote file: {path}"



# 5. list_files
def list_files(path: str=".") -> str:

    target = safe_resolve(path) # validator

    if not target.exists():
        raise FileNotFoundError( f"path not found: {path}" )

    if not target.is_dir():
        raise NotADirectoryError( f"not a directory: {path}" )

    items = []

    for child in target.iterdir():
        items.append( child.relative_to(SANDBOX_ROOT).as_posix() ) 

    return "\n".join(items)
    


# 6. run_command
def run_command(command: str) -> str:

    parts = command.strip().split()

    base = parts[0]

    if base == "pwd":
        return str(SANDBOX_ROOT)
    
    if base == "ls":
        target = (
            parts[1]
            if len(parts) > 1
            else "." )
        return list_files( target )


    if base == "cat":
        return read_file( parts[1] )

    raise ValueError( f"unsupported command reached execution: {base}" )


#===================
# Tool schemas
# 각 도구들을 호출할 때의 형식 지정 
#===================

TOOLS = [
    # 1. calculator 

    {
        "type": "function", # 도구 종류
        "name":"calculator", # 도구 이름
        "description": "Perform a basic arithmetic calculation.", # 도구 설명. LLM이 도구를 선택할 때 설명을 읽고 결정한다. 도구설명으로 자동으로 생성하는 함수도 있다. 
        "parameters": {
            "type":"object", # 객체(디셔너리) 타입만 인자로 받는다
            "properties":{ # 인자에 대한 설명
                "expression" : { # 인자(변수이름): expression
                    "type": "string", # 그 값과 설명
                    "description": "Arithmetic expression, e.g. '37*82'"
                }
            },
            "required": ["expression"],
            "additionalProperties": False # 지정된 인자외의 다른 인자를 받지 않겠다. 
        },
        "strict" : True # 구조화된 출력 엄격하게 유지
    },

    # 2. read_file
    {
        "type": "function",
        "name" : "read_file",
        "description": "Read a UTF-8 text file.",
        "parameters": {

            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Relative path to the file."
                }
            },
            "required": ["path"],
            "additionalProperties": False
        },
        "strict": True
    },

    {

        "type": "function",
        "name": "get_time",
        "description": "Get current local system time.",
        "parameters":{

            "type": "object",
            "properties":{},
            "required": [],
            "additionalProperties": False
        },
        "strict": True
    },

    {

        "type": "function",
        "name" : "write_file",
        "description":  "Write a text file inside the sandbox.",
        "parameters" : {
            "type": "object",
            "properties":{
                "path": {
                    "type": "string",
                },
                "content": {
                    "type": "string"
                }
            },
            "required": ["path", "content"],
            "additionalProperties": False
        },
        "strict": True
    },
    {

        "type": "function",
        "name": "list_files",
        "description": "List files inside the sandbox.",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string"
                }
            },
            "required": ["path"],
            "additionalProperties": False
        },
        "strict": True
    },
    {
        "type": "function",
        "name": "run_command",
        "description": ( 
            "Run one restricted sandbox command. "
            "Allowed commands: pwd, ls, cat." 
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string"
                }
            },
            "required": ["command"],
            "additionalProperties": False
        },
        "strict": True
    }
]


#===================
# Tool dispatcher
# LLM이 함수(도구)호출하면 해당 함수를 호출함. 
#===================

def execute_tool(name: str, arguments: dict, logger: TraceLogger, call_id: str) -> str:

    tool_info = {
        "name": name,
        "arguments": arguments
    }

    #==============
    # 1. validation
    #==============
    decision = validate_tool_call( name, arguments )

    if decision["allowed"]:
        logger.log(
            event_type="tool_validation",

            tool=tool_info,

            validation={
                "result": "allowed",
                "reason": None
            },

            data={
                "call_id": call_id,
                "resolved_path":
                str(decision.get("resolved_path"))
                if decision.get("resolved_path")
                else None
            }
        )


    else:
        logger.log(
            event_type="tool_validation",
            tool=tool_info,
            validation={
                "result": "denied",
                "reason": decision["reason"]
            },
            execution={
                "attempted": False,
                "status": "blocked"
            },
            data={
                "call_id": call_id
            }
        )

        logger.log(
            event_type="tool_result",
            tool=tool_info,

            execution={
                "attempted": False,
                "status": "blocked"
            },

            result={
                "status": "denied",
                "output": decision["reason"]
            },

            data={
                "call_id": call_id
            }        
        )

        return f"DENIED: {decision['reason']}"

    #==============
    # 2. Execution
    #==============

    logger.log(
        event_type="tool_execution",
        tool=tool_info,
        execution={
            "attempted": True,
            "status": "started"
        },
        data={
            "call_id": call_id
        }
    )

    try:
        if name == "calculator":
            result = calculator(arguments["expression"])

        elif name == "read_file":
            result = read_file(arguments["path"])

        elif name == "get_time":
            result = get_time()

        elif name == "write_file":
            result = write_file(arguments["path"], arguments["content"])

        elif name == "list_files":
            result = list_files(arguments["path"])

        elif name == "run_command":
            result = run_command( arguments["command"] )

        else:
            raise ValueError(
                f"unknown tool: {name}"
            )

    # =========================
    # 3. Result
    # ========================='

        logger.log(
            event_type="tool_result",
            tool=tool_info,
            execution={
                "attempted": True,
                "status": "executed"
            },

            result={
                "status": "success",
                "output": result
            },
            data={
                "call_id": call_id
            }          
        )

        return result

    except Exception as e:
        logger.log(
            event_type="tool_result",
            tool=tool_info,
            execution={
                "attempted": True,
                "status": "error"
            },

            result={
                "status": "error",
                "output": str(e)
            },
            data={
                "call_id": call_id
            }
        )

        return f"ERROR: {e}"

#===================
# Agent Loop
#===================

def run_agent(user_input: str):

    # trace logger 시작점
    logger = TraceLogger()
    logger.log( "run_start", {"user_input": user_input} )

    input_items = [
        {
            "role": "user",
            "content": user_input
        }
    ]


    # 에이전트 루프
    while True:
        
        # 모델 입력 직전 로그
        #step += 1
        logger.next_step()

        logger.log( "model_request", {"input_items": input_items})

        print(f"\n============= STEP {logger.step} =============")

        # response: 한번의 추론 결과(출력). 여러 함수를 병렬 호출할 수도 있다.(ex) 서울과 부산 날씨 알려줘)
        response = client.responses.create(
            model = MODEL, # LLM 모델 지정
            instructions=(  # instructions
                "You are a minimal tool-using agent. "
                "Use tools whenever external information "
                "or calculation is required. "
                "You may use multiple tools sequentially."
            ),
            tools=TOOLS, # instructions
            input=input_items  # data
        )

        # 모델 출력 직후 로그 
        logger.log(
            "model_response", 
            {
                "response_id": response.id, 
                "output_text": response.output_text,
                "output": [
                    item.model_dump()
                    for item in response.output
                ]
            }
        )

        # 모델 출력 보존 -> 다음 루프 입력에 더해서 사용
        input_items += response.output
        tool_called = False

        # LLM이 출력한 결과(json) 확인 후 함수 or 도구 실행
        for item in response.output:

            # LLM이 추론결과로 도구를 호출하지 않았다면
            if item.type != "function_call":
                continue


            # LLM이 추론결과로 도구를 호출했다면 

            # 도구 호출
            tool_called = True # continue 가 아니라는 건 tool_called 됐다는 것
            tool_name = item.name
            arguments = json.loads(item.arguments) # JSON 형태의 인자 문자열'을 Python 딕셔너리로 역직렬화


            logger.log(
                event_type="tool_call",
                tool={
                    "name": tool_name,
                    "arguments": arguments
                },

                data={
                    "call_id": item.call_id,
                }    
            )
                
            # =========================
            # Validation + Execution
            # =========================

            print("\n[TOOL CALL]")
            print("name     :", tool_name)
            print("arguments    :", arguments)

            # 도구 호출을 위한 tool dispatcher 실행 
            # LLM 이 호출한 함수 -> 인자 역직렬화 ->  Tool dispatcher 호출 -> 도구 호출
            result = execute_tool(
                tool_name,
                arguments,
                logger,
                item.call_id
            )

            print("\n[OBSERVATION]")
            print(result)

            # LLM API는 정해진 규격을 지켜야 한다. 이대로 context window에 반영된다.
            input_items.append(
                {
                    "type": "function_call_output",
                    "call_id": item.call_id,
                    "output": result
                }
            )
        
        # 이번 추론에서 도구를 호출하지 않았다 == 도구 사용을 마치고 최종답변 작성까지 완료했다. 
        # Agent loop 종료
        if not tool_called:

            logger.log(
                "final_response",
                {
                    "content": response.output_text
                }
            )

            logger.log(
                "run_end",
                {
                    "status": "success"
                }
            )

            print("\n[FINAL RESPONSE]")
            print(response.output_text)

            return response.output_text


#===================
# CLI
#===================
if __name__ == "__main__":


    while True:

        user_input = input(
            "\nUSER > "
        )

        if user_input.lower() in { "exit", "quit" }:
            break
        
        run_agent(user_input)
    
    """

    logger = TraceLogger()

    tests = [
    "./notes.txt",
    "./data/test.txt",
    "../test.txt",
    "../../something" ]

    for p in tests:

        logger.next_step()

        logger.log( "Validator test", {"input_items": p})


        try:
            resolved = safe_resolve(p) # validator 작동 실험
            print( p, "-> ALLOW ->", resolved )

            logger.log(
                event_type="validator_result",

                tool={
                    "name": "safe_resolve",
                    "arguments": {
                        "path": p
                    }
                },

                validation={
                    "result": "allowed",
                    "reason": None
                }
            )

        except Exception as e:
            print( p, "-> DENY ->", e )

            logger.log(
                event_type="validator_result",

                tool={
                    "name": "safe_resolve",
                    "arguments": {
                        "path": p
                    }
                },

                validation={
                    "result": "denied",
                    "reason": str(e)
                }
            )

    """