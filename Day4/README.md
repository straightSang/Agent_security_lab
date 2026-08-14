## Day3. -> Runtime Security · Permission Boundary · Tool Enforcement

#### 목표 : 
1. 

#### Day3와의 차이점:
- 
#### 주목할 부분:
- 

#### 전체 실행 흐름:


#### 전체 실행 구조:
LLM Tool Proposal


#### 추가되는 파일 및 함수:
- 파일
    - 
- 함수
    -
    

- 예시
```python

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
- 


#### 흐름도
LLM
→ Tool Request
→ Validator
→ Permission Policy
→ Runtime Enforcement

→ Tool
→ Filesystem
