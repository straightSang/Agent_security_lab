# 구조 : loop + tools(함수) + tool schema + tool dispatcher(selector) + logger함수
from trace_logger import TraceLogger

import os 
import json

from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv # API key 등 로드 
from openai import OpenAI # OPENAI 모델과 통신하기 위함 

load_dotenv() #.env 파일의 환경변수를 os.environ에 로드

client = OpenAI(
    api_key=os.environ["OPENAI_API_KEY"]
)


MODEL = "gpt-5.5"


#===================
# Tools
#===================

# 1. calculator
def calculator(expression: str) -> str:

    try:
        result = eval(expression, {"__builtins__": {}}, {})

        return str(result)

    except Exception as e:
        return f"ERROR: {e}"


# 2. read_file
def read_file(path: str) -> str:
    # 파일 경로를 클래스 객체로 변환.
    file_path = Path(path)

    if not file_path.exists():
        return f"ERROR: file not foound: {path}"

    if not file_path.is_file():
        return  f"ERROR: not a file: {path}"

    try:
        return file_path.read_text( encoding = "utf-8" )
    except Exception as e:
        return f"ERROR: {e}"


# 3. time
def get_time() -> str:
    return datetime.now().isoformat()


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
    }
]


#===================
# Tool dispatcher
# LLM이 함수(도구)호출하면 해당 함수를 호출함. 
#===================

def execute_tool(name: str, arguments: dict) -> str:

    if name == "calculator":
        return calculator(arguments["expression"])

    if name == "read_file":
        return read_file(arguments["path"])

    if name == "get_time":
        return get_time()

    return f"ERROR: unknown tool: {name}"


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
                "tool_call",
                {
                    "call_id": item.call_id, # run_id: 도구 호출마다 변하는 값
                    "tool_name": tool_name,
                    "arguments": arguments
                }
            )


            print("\n[TOOL CALL]")
            print("name     :", tool_name)
            print("arguments    :", arguments)

            # 도구 호출을 위한 tool dispatcher 실행 
            # LLM 이 호출한 함수 -> 인자 역직렬화 ->  Tool dispatcher 호출 -> 도구 호출
            result = execute_tool(
                tool_name,
                arguments
            )
            
            logger.log(
                "tool_result",
                {
                    "call_id": item.call_id,
                    "tool_name": tool_name,
                    "result": result
                }
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