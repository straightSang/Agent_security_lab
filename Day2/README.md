# Day2. Tool 추가 & Guardrail 적용 & Path validation
샌드박스 안에서 write_file(), list_files() 툴을 추가한다.

각 파이프라인 단계들에 가드레일을 순차적으로 전달한다. 

Agent v0.2를 “권한 경계 실험용 harness”로 바꾼다.
LLM의 의사결정
→ Validator의 검증
→ OS/Filesystem의 실제 권한

Agent의 판단을 신뢰하지 않고 Tool Runtime의 권한통제를 신뢰한다.
LLM도 정책, 상황, 위험을 이해, 판단, 설명할 수 있으나 보안 경계가 되어서는 안 된다. 

위험성을 모델의 판단에 맡기지 않아야 하며, 각 상황과 문맥에 관계없이 적용되는 정책이 필요하다. 

로그를 볼 때 "어디에서 차단됐는가를 보는는 것이 중요하다" = 신뢰 경계

신뢰 경계의 위치: LLM의 Tool Request가 실제 Execution Engine으로 넘어가기 직전의 Validation / Pre-Guardrail 레이어

신뢰 경계를 거쳐 trusted zone에 들어가야만 도구 호출 등이 실행될 수 있다. 
Trust Boundary (신뢰 경계):
데이터의 신뢰 수준이 변하는 경계선으로, 이 경계를 넘어가는 모든 데이터(Data Flow)는 반드시 입력값 검증(Validation) 및 정제(Sanitization)를 거쳐야 한다.

Agent 가 접근할 수 있는 파일은 모두 sandbox 안에 있다. 그 밖의 경로의 접근은 허용되지 않는다.

calculator = intentionally simple demo tool
=> 나중에 AST 기반 arithmetic parser로 교체