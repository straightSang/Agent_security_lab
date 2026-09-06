### 1. Risk Scope
- Risk scope
    - 에이전트의 보안 위험도는 다음 세 요소의 곱으로 정의된다.
    - Risk Scope = Agent capability x Agent Resources x Autonomy 
- Blast Radius
    - 보안 사고가 발생했을 때 영향이 미치는 시스템 자원의 범위를 뜻하며, 가드레일의 핵심 목표는 이 피해반경을 최소한으로 격리하는 것이다. 
    - Blast Radius Scope = C x R x A 
#### 요소 
- Agent capability (에이전트의 능력)
    - 에이전트가 사용할 수 있는 도구의 종류와 기능. 
    - 코드 실행, 파일 삭제 권한이 주어지면 인젝션 공격 시 시스템 파일이 삭제될 수 있다.
- Agent Resources (접근 가능한 자원)
    - 에이전트가 권한을 가진 데이터나 시스템 영역 (ex. public data와 .env 파일).
    - 에이전트가 로컬 파일 시스템 전체나 DB에 제한 없이 접근할 수 있다면 민감 정보 유출 위험이 커진다.
- Autonomy (자율성)
    - 에이전트가 사람의 승인 없이 스스로 판단하여 연쇄적으로 동작할 수 있는 범위 (ex. Human-in-the-loop와 무승인 에이전트 루프).
    - 에이전트가 스스로 판단하여 인간의 승인/제한 없이 연쇄 도구 호출을 수행한다면 의도치 않은 자동화 사고나 공격 피드백 루프가 발생한다. 
- 이 셋 중 하나만 커져도 위험 수준이 급상승하므로 세 요소를 조절하여 전체 위험을 제어해야 한다. 



### 2. Guardrails
에이전트의 보안 위험도를 결정하는 세 요소를 통제하기 위해 가드레일이 존재한다. 각 요소를 조절하는 방식은 다음과 같다
- Agent capability 
    - 도구 호출 전  Pre-Execution Guardrail 을 통해서 인자값을 검증 및 정제한다.
    - 위험한 인자가 발견되면 실행을 차단하여 도구가 가진 실제 파괴력의 작동 범위를 최소화한다. 
- Agent Resources 
    - Path Traversal 방지 필터나 접근제어 목록(ACL)을 적용한다.
    - read_file 호출 시 허용된 디렉토리 바깥에 대한 접근 시돌르 무조건 차단함으로써 접근 가능한 자원 영역을 샌드박싱한다. 
- Autonomy 
    - Human-in-the-loop 도입 및 최대 루프 횟수 제한. 
    - 파일 삭제, 외부 전송, 권한 변경 등 위험도가 높은 액션을 취하기 직전에 정지하고 사람의 수동 승인을 요구함으로써 자율성에 한계를 둔다.

- 일반 input/output guardrail과 tool guardrail의 적용 위치가 다르다
- LLM → Tool Request → Validation
    → Permission → Execution → Output Validation → LLM


### 3. Guardrails 적용 단계
----
0. [LLM] 
  │
  ▼
1. Tool Request  ──► LLM이 도구 사용 요청 (JSON 전달)
  │
  ▼
2. Validation    ──► [Guardrail] 인자값 규격 및 안전성 검증
  │
  ▼
3. Permission    ──► [Guardrail] 인가 여부 및 승인(Human-in-the-loop) 확인
  │
  ▼
4. Execution     ──► [Sandbox] 격리된 환경에서 도구 실제 실행
  │
  ▼
5. Output Val.   ──► [Guardrail] 실행 결과 데이터 필터링/인젝션 감지
  │
  ▼
[LLM]            ──► 정제된 Observation을 받아 다음 추론 진행
----
0. LLM 추론
- 사용자 요청과 대화 이력을 바탕으로 작업에 필요한 도구 결정.
1. Tool Request
- LLM이 사용하고자 하는 도구 이름, 인자를 정해진 JSON schema 형태로 생성.
2. Validation [Guardrail] (입력값/인자 검증)
- LLM이 생성한 인자값이 안전한지 검증.
    - 스키마 타입 일치 여부, Path Traversal 기호(../) 포함 여부, 악의적 명령어 주입(eval(), system()) 포함 여부 등 검증.  
3. Permission [Guardrail] (권한 제어)
- 해당 인자값과 도구를 실행할 권한이 시스템 또는 사용자에게 있는지 확인한다. 
    - RBAC/ABA(역할 기반 접근 제어/속성 기반 접근 제어)C: 해당 파일 경로에 대한 읽기 권한이 허용되어 있는지 체크한다.
    - Human-in-the-loop: 민감한 작업(파일 삭제, DB 수정 등)의 경우 사람(사용자)에게 승인 알림을 보내 수동 승인을 거치도록 한다.
4. Execution (격리된 실행)
- 검증과 승인을 통과한 도구를 실제 시스템에서 실행한다.
    - 시스템 전체에 영향을 주지 않도록 제한된 권한의 샌드박스 내부에서 실행한다. 
5. Output Validation [Guardrail] (출력값 검증)
- 도구 실행 결과를 다시 LLM에 전달하기 전에 정제함.
    - 실행 결과 파일 or 웹페이지에 숨겨진 Indirect Prompt Injection 텍스트를 필터링하거나 민감데이터가 LLM 컨텍스트로 들어가는 것을 마스킹한다.  
6. LLM 재추론
- 정제된 Observation 결과를 Context에 포함시켜 다음작업을 수행한다. 


### 4. Guardrails 적용 방법