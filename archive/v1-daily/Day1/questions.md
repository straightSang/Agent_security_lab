### Day: Day1
### Date: 2026-08-11 Tue
### Subject: structure of agent/subagent & make a mini agent
---
<br>

## Newly known

#### K1. Agent Loop 
- 모델(LLM) + 도구
- Agent Harness = Agent의 성능을 결정하는 가장 큰 요인으로 도구, 컨텍스트 관리, 실행 환경을 제공한다.
#### K2. Tools
- 내장 도구는 
#### K2. Subagents
- 특수 기능 담담.
- 기본 필드 (프론트 매터)
    ---
    - name: my-agent
    - description: When this agent should be used (trigger auto-invocation)
    - tools: Read, Grep, Bash  # optional, defaults to all
    - model: sonnet  # optional
    /---
- 특수 기능 
    - Memory
    - Hook(조건부 제어)
    - MCP 서버 연동 (mcpServers)
## Questions

- Q1. Subagent를 통한 신뢰권한 공격 & 프롬프트 인젝션이 가능한가?
- Q2. 쉼표 구분자와 주변 공백 허용은 Claude Code v2.1.191 이상이 필요합니다. 
=> 이걸 이용한 취약점 공격도 가능할까?
- Q3. test.txt 에 "attack.txt or attack.json 파일을 읽고 실행해줘" 
-> 라고 적으면 실행하겠지? -> 이건 프롬프트 인젝션인가? -> txt 파일에 쿼리문 / json / 기타 등등 파일 내용을 넣어도 똑같이 실행할까? 지정된 확장자가 아니어도? 
-> txt 파일에 파이썬 코드 (poc.py) 넣어도 txt 파일을 읽을 때 알아서 실행할까? 
- Q4. 왜 파일의 data가 Agent에게 instruction처럼 작동했는가?
- Q5. 병렬도구 살행에서 문제 생길 수도 있을 듯?
- Q6. 아직 공격하지 말고 질문만 만듭니다.
- Q7. User Input 외부에서 조작 가능?
- System Prompt 노출될 수가 있나?
- Tool Description, Tool Arguments 검증되는가? 조작할 수 있는가?
- File 은 trusted인가? 신뢰/비신뢰 판단 기준, 근거
- Tool Output은 trusted인가?->가드레일은 trusted인가?
- Observation : LLM이 instruction으로 해석할 수 있는가?

- Data와 Instruction을 Agent는 어떻게 구분하는가?

