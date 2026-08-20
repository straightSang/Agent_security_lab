# Day 5 v0.4 변경 기록

## 1. 전체 동작 과정 · 함수 호출표

| 순서 | 호출 (`파일명/함수명`) | 입력 → 출력 | 보안 의미 |
|---:|---|---|---|
| 1 | `Agent_v0.4.py/execute_proposal` | 인증된 actor + LLM Tool Proposal → Runtime 호출 | LLM은 proposal만 만들며 actor를 정하지 못함 |
| 2 | `runtime.py/Runtime.execute_tool` | proposal → validation | 유일한 실행 입구 |
| 3 | `runtime.py/validate_tool_call` | tool/args → canonical path 또는 거부 | schema·sandbox 탈출 차단 |
| 4 | `security/capability.py/describe_intent` | 검증 결과 → ToolIntent 재료 | capability/action/resource 도출 |
| 5 | `security/types.py/ToolIntent.fingerprint` | 실행 의미 → SHA-256 digest | 승인 대상 intent를 고정 |
| 6 | `security/policy.py/PolicyEngine.evaluate` | intent → PolicyDecision | trust/capability/scope 일반 규칙 |
| 7 | `authorization.py/AuthorizationEngine.authorize` | intent → AuthorizationDecision | actor-owner/member 관계 검사 |
| 8 | `security/approval.py/ApprovalStore.request` | approval-required intent → pending ID | AuthZ 통과 뒤에만 record 생성 |
| 9 | `approval.py/approve_pending_request` | authenticated approver + ID → approved/pending | 상태만 변경, dispatch 없음 |
| 10 | `security/approval.py/ApprovalStore.consume` | approved ID + same fingerprint → consumed_now | 한 번만 dispatch admission |
| 11 | `runtime.py/Runtime._dispatch` | 허용된 intent → local tool result | 허용 목록 내부 함수만 실행 |
| 12 | `trace_logger.py/TraceLogger.record_*` | 각 결론 → JSONL | policy/authz/approval/result 감사 |
| 13 | `security/evaluator.py/evaluate_run` | trace → metrics | false allow/block, approval bypass 확인 |

## 2. 추가·수정된 파일

| 파일 | 변경 |
|---|---|
| `src/authorization.py` | 새 Day 5 AuthorizationEngine, path registry, owner/shared membership 규칙 구현 |
| `src/approval.py` | 새 control-plane facade; required approver만 pending record를 승인 가능 |
| `src/security/types.py` | AuthorizationOutcome/AuthorizationDecision 계약, ApprovalState의 actor·approver·resource·action 필드 추가 |
| `src/security/__init__.py` | 새 authorization types export |
| `src/security/approval.py` | required approver binding, record metadata, single-process consume lock 및 `consumed_now` 반환 추가 |
| `src/security/permission.py` | `data/**` write를 Policy상 approval-required로 허용; 실제 소유권은 AuthZ가 좁힘 |
| `src/runtime.py` | Policy 뒤 AuthZ 호출, authz deny trace/result, required approver로 approval request, consume 성공자만 dispatch |
| `src/trace_logger.py` | authorization decision/reason/required approver 공통 trace 필드 및 event 추가 |
| `src/security/evaluator.py` | authorization false allow/block 및 approval bypass 지표 추가 |
| `src/Agent.py` | Runtime composition root에서 AuthorizationEngine을 명시적으로 주입 |
| `src/Agent_v0.4.py` | 새 승인 UX Agent. `Agent_v0.3.2.py`는 변경하지 않음 |
| `src/test_runtime.py` | Day 5 owner, cross-user, wrong approver, consumed replay, shared reviewer fixture 및 dispatcher mock 검증 추가 |
| `README.md` | 실제 Day 5 actor/shared 규칙과 호출 순서 반영 |
| `src/policy.md` | Day 5 정책, 인가, Resource DB 확장 기준 문서화 |

## 3. 이전 버전과 달라진 보안 의미

- Day 4는 policy와 approval 중심이었다. v0.4는 `Policy=ALLOW`/`APPROVAL_REQUIRED`
  이후에도 actor-resource-action이 맞지 않으면 Runtime 전에 `FORBIDDEN`으로 끝난다.
- approval ID는 Agent ID/call ID가 아니라 한 Intent의 record ID다.
- 개인 경로는 `data/{ACTOR_NAME}/**`로 일반화했다. 해당 actor만 read/write할 수
  있고, 개인 write의 승인자는 actor 본인이다. shared write의 승인자는 Lab fixture
  role인 `reviewer-001`이다.
- `approved`는 실행 완료가 아니다. 같은 fingerprint의 재시도만 consume하며,
  consume에 성공한 한 호출만 dispatcher를 호출한다.
- fixture는 모델이 고르는 분류가 아니라 사람이 작성한 재현 가능한 입력·기대 결과다.
  이번 test는 dispatcher mock의 `call_count == 1`로 replay가 실행 함수에 닿지 않음을 검증한다.

## 4. 검증 결과

`src`에서 bundled Python으로 `test_runtime.py`를 실행했다.

- safe read: 성공
- untrusted write: Policy 차단
- own write: pending → own actor approval → consume 후 dispatcher 한 번
- cross-user read: Authorization 차단, approval ID 미발급
- wrong approver: pending 유지
- consumed approval replay: dispatcher call count 추가 없음
- shared write: user-003은 pending, `reviewer-001`이 required approver

테스트는 checked-in trace를 더럽히지 않도록 temporary trace path를 사용한다. 실제
파일 쓰기 대신 dispatcher mock을 사용한 곳은 **실제 filesystem 권한이 아니라 Runtime
admission 횟수**를 분리해 검증하기 위해서다.
