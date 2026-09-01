# Day 9 데이터 계약 — MCP tool schema·Runtime

## 제1장 — 실제 실행 자료형

### ToolProfile

```python
ToolProfile(
    name="read_only",
    exposed_tools=("calculator", "get_time", "read_file", "list_files"),
)
```

profile은 trusted config다. ToolIntent나 LLM output의 필드가 아니다.

### MCP tool definition

```text
name
description
inputSchema
annotations
_meta.lab/capability
```

`inputSchema`는 JSON Schema이고, `annotations`는 보안 권한이 아닌 힌트다.
`_meta.lab/capability`도 catalog 감사 정보이며 최종 capability는
`describe_intent()`가 다시 계산한다.

### ToolSchemaDecision

```python
ToolSchemaDecision(
    allowed=False,
    reason="TOOL_NOT_EXPOSED_IN_PROFILE",
    profile="read_only",
    tool_name="write_file",
    declared_capability=None,
    schema_digest="sha256:...",
)
```

| 필드 | 역할 |
|---|---|
| allowed | schema gate 통과 여부 |
| reason | 안정적인 판정 코드 |
| profile | 실제 적용 profile |
| tool_name | 요청 tool |
| declared_capability | trusted catalog의 설명 값 |
| schema_digest | profile/tool schema 버전 비교 |

### ToolIntent

schema와 Runtime Validation을 모두 통과한 뒤에만 생성한다.

```text
run_id, call_id, actor, tool_name, arguments,
provenance, capability, action, resource,
agent_step, fixture_id
```

ToolIntent는 실행 요청이며 permission이 아니다.

### 기존 결정 계약

| 자료형 | 생성 주체 | 역할 |
|---|---|---|
| PolicyDecision | PolicyEngine | trust/capability/resource 일반 결론 |
| AuthorizationDecision | AuthorizationEngine | actor-resource-action 결론 |
| ApprovalState | ApprovalStore | pending/approved/consumed 상태 |
| RuntimeResult | Runtime | 최종 성공·거부·오류 |

## 제2장 — 기록 계약

### tool_schema_decision 사건

```json
{
  "event": "tool_schema_decision",
  "run_id": "run-...",
  "call_id": "call-...",
  "actor": "user-001",
  "tool_name": "write_file",
  "tool_schema_decision": "deny",
  "tool_schema_reason": "TOOL_NOT_EXPOSED_IN_PROFILE",
  "tool_profile": "read_only",
  "tool_schema_digest": "sha256:..."
}
```

필수 필드:

```text
call_id, tool_schema_decision, tool_schema_reason,
tool_profile, tool_schema_digest
```

`declared_capability`은 미노출 도구에서는 없을 수 있다.

### schema 조기 종료

```text
tool_schema_decision(deny)
-> runtime_result(
     ok=false,
     runtime_status=schema_denied,
     end_stage=tool_schema,
     error_code=MCP_TOOL_SCHEMA_DENIED
   )
```

이 경우 ToolIntent·Policy·AuthZ·Approval 사건이 없어야 한다.

### schema 통과

```text
tool_schema_decision(allow)
-> validation
-> tool_intent
-> policy_decision
-> authorization_decision
-> approval, if needed
-> runtime_result
```

JSONL은 사건별로 의미 있는 필드만 저장하며 빈 공통 `null` 필드를 반복하지 않는다.

## 제3장 — 평가 계약

EvaluationResult Day 9 필드:

| 필드 | 의미 |
|---|---|
| actual_schema_decision | 최종 RuntimeResult call의 schema 결론 |
| schema_bypass | schema DENY call이 성공했는가 |
| schema_false_block | 허용 기대 schema가 DENY됐는가 |
| trace_completeness | 조기 종료/기존 흐름에 필요한 사건이 모두 있는가 |

기존 safety/utility/AuthZ/Approval/provenance 지표는 유지한다.

## fixture 계약

`mcp_least_privilege.json`:

```text
suite_id
cases[]
  fixture_id
  category
  profile
  tool_name
  arguments
  seed_files
  expected
```

fixture의 profile과 expected는 test harness가 실험을 구성하고 검사하는 값이다.
Runtime이 fixture 파일을 읽어 permission을 만들지는 않는다.

## MCP/OpenAI adapter

권위 있는 catalog는 MCP 형식의 `inputSchema`를 사용한다.

```text
tools_for_mcp(profile)
  -> name/description/inputSchema/annotations/_meta

tools_for_openai(profile)
  -> type=function/name/description/parameters/strict
```

두 adapter는 같은 catalog를 사용하므로 schema를 두 군데 수정하는 오류를 줄인다.

## schema digest와 evidence digest

- schema digest: profile에 노출된 tool definition 집합의 안정적 hash
- seed digest: fixture 시작 파일 상태
- decision digest: schema/Policy/AuthZ/Approval 판단 집합
- result digest: Runtime 결과 집합

임의 run/call/approval ID와 timestamp는 재현성 digest 입력에서 제외하지만 원본
trace에는 보존한다.
