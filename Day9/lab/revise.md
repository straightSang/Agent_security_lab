# Day 9 변경 기록

## 전체 동작 과정과 함수 호출

| 순서 | 파일명/함수명 | 입력 | 출력 | 변경 여부 | 존재 이유 |
|---:|---|---|---|---|---|
| 1 | `Agent_v0.5.py/get_tool_profile()` | trusted 환경 설정 | ToolProfile | 추가 | 작업별 최소권한 선택 |
| 2 | `security/tool_schema.py/tools_for_openai()` | ToolProfile | Responses tool 목록 | 추가 | 기존 Agent loop와 MCP catalog 연결 |
| 3 | `Agent.py/execute_tool()` | proposal·actor·provenance | RuntimeResult dict | 유지 | 외부 단일 진입점 |
| 4 | `runtime.py/Runtime.execute_tool()` | 구조화 proposal | 단계별 결과 | schema gate 추가 | 순서 강제 |
| 5 | `security/tool_schema.py/validate_tool_schema()` | profile·tool·arguments | ToolSchemaDecision | 추가 | 미노출/과도한 입력 조기 차단 |
| 6 | `runtime.py/validate_tool_call()` | schema 통과 호출 | canonical validation | 유지 | 실제 sandbox 경계 재검사 |
| 7 | `security/capability.py/describe_intent()` | 검증 호출 | capability/action/resource | 유지 | 서버 측 권한 계산 |
| 8 | `security/policy.py/PolicyEngine.evaluate()` | ToolIntent | PolicyDecision | 유지 | trust/resource 일반 규칙 |
| 9 | `security/authorization.py/AuthorizationEngine.authorize()` | ToolIntent | AuthZ decision | 유지 | actor 자격 검사 |
| 10 | `security/approval.py/ApprovalStore` | write intent | approval state | 유지 | 명시적 승인·일회성 소비 |
| 11 | `runtime.py/Runtime._dispatch()` | 모든 gate 통과 intent | tool result | 유지 | 유일 실행 지점 |
| 12 | `trace_logger.py/record_*()` | 단계 결과 | JSONL 사건 | schema 사건 추가 | 감사 증거 |
| 13 | `security/evaluator.py/evaluate_run()` | 동일 run trace | metrics | schema 지표 추가 | 조기 종료·우회 평가 |
| 14 | `experiment_support.py/record_run_evidence()` | trace | stable digest | schema 판단 포함 | replay 비교 |

## 수정·추가 파일과 이유

| 파일 | 변경 내용 | 수정 이유 |
|---|---|---|
| `src/security/tool_schema.py` | MCP catalog, 3개 profile, schema validator | 도구 정의·노출·검증의 단일 기준 필요 |
| `src/security/types.py` | `ToolSchemaDecision` | schema 단계의 명시적 계약 필요 |
| `src/Agent.py` | hard-coded TOOLS 제거, catalog adapter 사용 | MCP/OpenAI 정의 중복 방지 |
| `src/Agent_v0.5.py` | `MCP_TOOL_PROFILE`, 기본 read_only | 기존 run_agent 흐름을 유지하며 최소권한 적용 |
| `src/runtime.py` | 기존 Validation 앞 schema gate | 미노출 권한을 Policy 이전에 차단 |
| `src/trace_logger.py` | schema decision/early result 사건 | ToolIntent 전 종료도 추적 |
| `src/trace_reader.py` | schema 사건 한글 요약 | 사람이 trace를 읽기 쉽게 함 |
| `src/security/evaluator.py` | schema bypass/false block | 새 gate의 효과·오탐 평가 |
| `src/experiment_support.py` | profile 주입, snapshot/digest 포함 | fixture별 동일 환경 replay |
| `src/fixtures/mcp_least_privilege.json` | D9-E01~E06 | 입력과 expected 고정 |
| `src/schemas/mcp-tool-profile.schema.json` | fixture 계약 | 잘못된 실험 데이터 구별 |
| `src/test_mcp_tool_schema.py` | 본 실험 | 정상 utility·공격 표면 감소 검증 |
| 기존 indirect fixture 3개 | write path를 actor data 경로로 수정 | Day9 path schema 통과 뒤 기존 Policy 방어를 계속 회귀하기 위해 |

## 기존 실행 흐름에서 유지한 부분

- Agent의 Responses API 반복 loop와 observation 전달
- `Agent.py/execute_tool()` 단일 진입점
- Runtime Validation과 canonical sandbox path
- ToolIntent 생성 방식
- Policy → Authorization → Approval 순서
- approval fingerprint·TTL·consume·replay 차단
- `_dispatch()` 유일 실행 경계
- run별 seed/trace/evaluator/evidence 구조

## 의도적으로 바꾼 부분

- 모든 작업에 같은 6개 도구를 노출하던 구조를 profile별 4/5/6개로 분리했다.
- `run_command`는 삭제하지 않고 legacy profile로 격리했다.
- Agent interactive 기본 profile을 read_only로 바꿨다.
- schema DENY는 Validation/ToolIntent/Policy 전에 종료한다.
- evaluator가 마지막 Policy가 아니라 마지막 RuntimeResult의 call_id를 기준으로 사건을
  연결하도록 수정했다. schema 조기 종료에는 Policy 사건이 없기 때문이다.

## 효율과 복잡성 판단

새 파일 하나와 decision type 하나가 늘어났지만 다음 중복을 줄였다.

- Agent의 hard-coded tool schema와 MCP schema를 별도로 관리하지 않는다.
- profile이 도구 목록을 재사용하므로 read/write Agent별 catalog 복사가 없다.
- Runtime schema validator 하나가 모델·fixture·API proposal을 동일하게 검사한다.
- 조기 차단으로 불필요한 path resolution, Policy, AuthZ, Approval 호출을 피한다.

반대로 JSON Schema 전체 엔진을 직접 구현하지 않았다. 현재 실험에 필요한 작은
부분집합만 사용해 복잡도를 제한했다. 운영 MCP server에서는 검증된 JSON Schema
validator와 SDK로 교체해야 한다.

## 문서 구조 변경

README와 EXP_README는 다음을 각각 별도 장으로 설명한다.

1. 실제 실험 수행
2. 기록 수행
3. 평가 수행
4. 파일·함수 역할과 존재 이유

Threat Model은 schema와 authorization을 같은 것으로 쓰지 않고 신뢰 경계를 분리한다.
`permission_policy.md`는 profile 노출 규칙과 기존 Policy/AuthZ/Approval 규칙을 함께
정리한다. `schema.md`는 실제 Python 자료형·trace 계약과 일치시킨다.
