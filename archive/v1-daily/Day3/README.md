## Day3. -> Runtime Security · Permission Boundary · Tool Enforcement

#### 목표 : 
1. 보안 정책(Security Policy)을 설계
2. Runtime이 그 정책을 강제하도록 만든다 

#### Day2와의 차이점:
- Day2 는 Sandbox 안이면 항상 허용함 -> File system validation Only 구조
- 파일 내용을 검증하지 않고 Observation -> LLM 으로 넘김
- 파이프라인 추가
    - Day2: Validation -> Execution : 사용자 입력에 대한 검사
    - Day3: Validation -> "Authorization" -> "Runtime_Enforcement" -> Execution : Agent의 행동 허용 여부에 대한 별도의 보안 검사
        -> Validation: PASS, Permission: DENIED 가능.

#### 주목할 부분:
- Validation != Permission 
- ex) 파일이 Sandbox 안인가? != Agent가 test.txt를 읽어도 되는가?

#### 전체 실행 흐름:
execute_tool()
↓
tool_call
"LLM이 뭘 요청했나?"
↓
Validation
safe_resolve()
↓
PASS?
 ├→ NO → BLOCK
 │
 └→ YES
↓
Authorization
authorize()
↓
ALLOW?
 ├→ NO → BLOCK
 │
 └→ YES
↓
Runtime Enforcement
↓
Tool Execution
↓
tool_result

#### 전체 실행 구조:
LLM Tool Proposal
↓
Runtime
↓
Validation
↓
Authorization
↓
Execution
↓
Internal Tool Result
↓
Trace Logger
↓
Observation Adapter
↓
LLM Observation

#### 추가되는 파일 및 함수:
- 파일
    - permission.py
    - runtimeenforcement.py
- 함수
    - Agent_v0.3.py: "authorize()"
    - trace_logger.py: tool_validation -> "tool_authorization" -> tool_execution 
    - Threat Model v0.2.md: "7. Mitigation" 

- 예시
```python
resolved = safe_resolve(path)

# 추가된 Policy Engine
decision = policy.allow(

    tool="write_file",

    path=resolved

)

if not decision:

    deny()

execute()
```


#### Mitigation 이란: 위험/위협 완화 방안
1. 
- Threat: Path Traversal
- Mitigation: safe_resolve() + Sandbox Root Check

2. 
- Threat: Unauthorized Write
- Mitigation: Permission Policy

3. 
- Threat: Arbitrary Command
- Mitigation: Allowlist

4. 
- Threat: Tool Abuse
- Mitigation: Permission Policy


src 수정 사항
- 중복 검사 제거
- 인자 검사 추가
- result, log() 스키마 작성
- tools 에러 상황에서의 반환값


#### 흐름도
LLM
→ Tool Request
→ Validator
→ Permission Policy
→ Runtime Enforcement
→ Tool
→ Filesystem


https://code.claude.com/docs/en/agent-sdk/permissions
Day 4. Threat: prompt injection 추가 
파일 시스템에 대한 권한 인증, 파일 읽기 부분 취약점 공격 