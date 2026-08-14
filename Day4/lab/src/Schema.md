- result, log() 스키마 작성:: 일관된 의미로 사용하는 것이 중요하다.
    - 
        result={
            "status": "success",
            "output": result -> 거부: 이유, 성공: 
        },


## 1. execute_tool return (Runtime 내부)스키마
return
{
    "ok": True | False,
    "end_stage": "validation" | "authorization" | "execution",
    "status": "success" | "denied" | "error",
    "data": None | object,
    "error": None | {
        "code": None | DENIED | ERROR
        "message": None | ["reason"] | str(e)
    },
    "meta": {
        "tool_name": 
        "call_id": 
    }
}

#### 성공
{
    "ok": True,
    "status": "success",
    "stage": "execution",
    "data": output,
    "error": None
}
#### 정책 차단
{
    "ok": False,
    "status": "denied",
    "stage": "authorization",
    "data": None,
    "error": {
        "code": "PERMISSION_DENIED",
        "message": decision["reason"]
    }
}
#### 실행 오류
{
    "ok": False,
    "status": "error",
    "stage": "execution",
    "data": None,
    "error": {
        "code": "TOOL_EXECUTION_ERROR",
        "message": str(e)
    }
}


## 2. LLM Obsevation context 스키마

if result["ok"]:
    return {
        "status": "success",
        "content": result["data"]
    }

return {
    "status": result["status"],
    "error": {
        "code": result["error"]["code"],
        "message": result["error"]["message"]
    }
}

## 3. logger 스키마


## 4. Tools 스키마
모든 도구들은 result를 반환할 때 dict에 result["reason"] 을 포함하고 있어야 한다. 