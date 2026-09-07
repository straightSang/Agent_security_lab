# CHANGELOG — 평가 보고서 반영 내역

기준 문서: `평가보고서_코드문서커리큘럼_20260903.docx` (RPT-2026-001)
대상: 기존 `AI_security_Lab/Day7~Day9` → 신규 `AI_Agent_Security_Lab_v2`

전체 32개 항목 중 **코드 12 · 문서 5 · 저장소 5 = 22개**를 이번에 처리했다.
나머지 10개는 PPT 커리큘럼 항목으로 `docs/CURRICULUM_12W.md`에 반영했다.

---

## Part A — 코드 (12/12 처리)

| ID | 심각도 | 처리 | 대상 파일 |
|---|---|---|---|
| A-01 | 높음 | schema 정규식을 구조 검사로 축소하고 범위 판정을 `POLICY`로 일원화. 도달 가능성 회귀 테스트 신설 | `security/tool_schema.py`, `security/permission.py`, `tests/test_policy_reachability.py` |
| A-02 | 높음 | `run_agent_loop()` 신설 — 모델의 tool call을 `execute_tool()`로 되돌리는 반복 루프. `propose=` 주입으로 모델 없이도 결정론적 재현 가능 | `src/agent.py` |
| A-03 | 높음 | 전역 `DEFAULT_RUNTIME` 제거 → `get_default_runtime()` 지연 생성. import 부작용 해소 | `src/agent.py` |
| A-04 | 중간 | 연속 중복 `if decision.outcome is APPROVAL_REQUIRED` 두 블록을 하나로 병합, 내부 3단계 주석 | `src/runtime.py` |
| A-05 | 중간 | 삼중따옴표 주석 3곳을 `#`으로 변환, 문자열 안의 죽은 함수 정의 삭제 | `src/runtime.py`, `src/agent.py` |
| A-06 | 중간 | 미사용 walrus 대입을 `detail` 필드로 활용. 누락 인자 목록을 거부 사유에 담음 | `security/tool_schema.py`, `security/types.py` |
| A-07 | 중간 | `authorization.py`의 절대 import를 상대 import로 통일 | `security/authorization.py` |
| A-08 | 중간 | 빈 canary 파일에 고유 마커 주입 + evaluator에 `canary_leak` 지표 추가 | `sandbox/secret/dome.env`, `security/evaluator.py` |
| A-09 | 중간 | `mkdir(parents=True)` 제거. 부모 디렉터리가 선언되어 있을 때만 쓰기 허용 | `src/runtime.py`, `src/experiment_support.py` |
| A-10 | 낮음 | fail-closed 경로의 `raise RuntimeError`를 trace를 남기는 거부 결과로 변경 | `src/runtime.py` |
| A-11 | 낮음 | 민감 리소스 판정에 확장자·부분 문자열 규칙 추가 | `security/policy.py` |
| A-12 | 낮음 | 하드코딩 모델 기본값 제거. `model` 인자 또는 `LAB_MODEL` 필수 | `src/agent.py` |

### A-01의 구체적 증거

수정 전, 아래 세 경로는 모두 schema 단계에서 거부되어 `POLICY`의 해당 분기에 도달하지 못했다.

```text
write_file path='notes.txt'     → MCP_ARGUMENT_PATTERN_MISMATCH   (POLICY: root_file 허용)
list_files path='.'             → MCP_ARGUMENT_PATTERN_MISMATCH   (POLICY: sandbox_root 허용)
read_file  path='data/test.txt' → MCP_ARGUMENT_PATTERN_MISMATCH   (POLICY: data 허용)
```

수정 후 `tests/test_policy_reachability.py`가 (도구, scope) 조합 5개 전부에 대해
schema gate를 통과해 PolicyEngine까지 도달함을 확인한다. traversal·절대 경로는 여전히
schema 단계에서 차단된다(별도 테스트 3건).

### 추가 개정 — A-13 계층 역할 분리

평가 이후 후속 논의에서 나온 항목이다. 원 보고서의 D-05(커리큘럼 중복이 이중
검증기를 유발함)가 지목한 코드 결함을 실제로 제거했다.

| 항목 | 내용 |
|---|---|
| 문제 | `runtime.ARGUMENT_SPEC`과 `tool_schema.inputSchema`가 인자의 이름·타입·필수·초과를 **중복 검사**했다. 같은 질문에 두 곳이 답하면 둘이 어긋나는 순간 도달 불가 분기가 생긴다 |
| 근거 | 5개 케이스를 두 계층에 동시 투입한 결과, 초과 인자와 타입 오류는 양쪽이 동일하게 거부했다. 반면 미노출 도구·길이 초과는 schema gate만, 심볼릭 링크 탈출은 validation만 잡았다 |
| 조치 | `ARGUMENT_SPEC`과 `validate_arguments()` 삭제. 인자 인터페이스 검사는 schema gate 단독. `validate_tool_call()`은 문자열→실체 변환(경로 정규화·셸 분해)만 수행 |
| 부수 개선 | 도구 목록의 단일 기준을 MCP catalog로 통일(`KNOWN_TOOLS = frozenset(MCP_TOOL_CATALOG)`). 두 번째 도구 목록이 사라졌다 |
| 사유 코드 | validation의 거부 사유를 안정적 코드로 정리: `PATH_ARGUMENT_UNUSABLE`, `COMMAND_ARGUMENT_UNUSABLE`, `EMPTY_COMMAND`, `COMMAND_USAGE:*`, `UNKNOWN_TOOL:*`, `PATH_ESCAPES_SANDBOX:*`. **'인터페이스 위반'과 '이 단계가 쓸 수 없는 값'이 trace에서 구별된다** |
| 회귀 | `tests/test_layer_separation.py` 신설 (검사 5종) |

핵심은 세 번째 검사다. `test_validation_does_not_check_interface()`는 validation이
초과 인자를 **통과시키는지**를 확인한다. validation이 다시 인터페이스를 검사하기
시작하면 이 테스트가 먼저 깨진다.

### 추가 개정 — RFC-001 공개 인터페이스 정리 (승인 후 실행)

`make_runtime_result`이 필요한지 묻는 질문에서 시작해, `agent.py`의 공개 표면
전체를 `ast`로 감사한 결과다. 설계도(`docs/RFC-001_public_api.html`)를 먼저
제시하고 선택지 B 승인을 받은 뒤 실행했다.

| 항목 | 내용 |
|---|---|
| 문제 | `agent.__all__`에 14개가 올라가 있는데 그중 12개를 어떤 파일도 import하지 않았다. 실제 인터페이스는 2개인데 감사 비용은 14개어치였다 |
| 근본 원인 | 12개에 "Day 1~8 호환용"이라는 주석이 붙어 있었으나, **Day 1~8 코드는 이 저장소에 없다.** 단일 트리로 옮기면서 `AI_security_Lab`에 남겨 뒀다. 어댑터가 가리키는 대상이 존재하지 않았다 |
| 왜 중요한가 | 이 저장소는 "실행 지점은 `_dispatch()` 하나뿐"이라고 주장한다. 그 주장을 검증하려는 사람은 공개 진입점을 전부 확인해야 한다 |

**변경 내역**

| # | 대상 | 조치 |
|---|---|---|
| C1 | `runtime.make_runtime_result` | 삭제 — 호출처 0. 정의–import–재수출 전 구간이 죽어 있었다 |
| C2 | `agent.safe_resolve` · `agent.validate_tool_call` | 삭제 — `runtime`의 원본을 `SANDBOX_ROOT`로 감싼 래퍼. 테스트는 이미 `runtime`에서 직접 가져가고 있었다 |
| C3 | `agent.TOOLS` · `READ_ONLY_TOOLS` · `WRITE_ENABLED_TOOLS` | 삭제 — 모델 광고용 `list[dict]`이며 검사에 쓰이는 `ToolProfile`과 다른 물건. `tools_for_openai(PROFILE)`로 필요할 때 생성 |
| C4 | `agent`의 `KNOWN_TOOLS` · `PATH_TOOLS` 재수출 | 제거 — 이름의 출처는 하나여야 한다 |
| C5 | `SANDBOX_ROOT` · `get_default_runtime` · `to_observation` | 내부로 — 이름은 유지하고 `__all__`에서만 제외 |
| C6 | `agent.__all__` | 14개 → **3개** (`execute_tool`, `build_runtime`, `run_agent_loop`) |
| C7 | `agent.py` 헤더 주석 | 재작성 — "Day 1~8 호환" 문구 삭제, 공개 인터페이스 3개와 그 근거 명시 |
| C8 | `tests/test_public_api_interface.py` | 신설 — 검사 4종 |

**C3의 부수 효과 — 이름 충돌 위험 제거**

`agent.READ_ONLY_TOOLS`와 `security.tool_schema.READ_ONLY_PROFILE`은 이름이
비슷해 혼동을 부르고 있었다. 실제로 "이거 MCP schema 검사에 쓰이는 것 아니냐"는
질문이 나왔고, 확인해 보니 전혀 다른 물건이었다.

```
security.tool_schema.READ_ONLY_PROFILE   ToolProfile   ← 검사에 쓰인다
agent.READ_ONLY_TOOLS                    list[dict]    ← 모델 광고용이었다
```

후자를 검사 함수에 넣으면 `AttributeError: 'list' object has no attribute
'exposed_tools'`가 난다. 삭제로 혼동 자체가 사라졌다.

**C8이 검사하는 것**

| 검사 | 내용 |
|---|---|
| `test_no_dead_public_names` | `__all__`의 모든 이름이 실제로 import되거나 `PLANNED`에 사유와 함께 등록되어 있는가 |
| `test_planned_entries_are_still_pending` | `PLANNED` 항목이 이미 쓰이고 있으면 목록에서 빼라고 알린다 |
| `test_public_surface_cannot_bypass_runtime` | `_dispatch` 등 실행 우회 경로가 공개되지 않았는가 |
| `test_entry_point_count_is_small` | 진입점 수가 상한(5) 이내인가 |

두 번째 검사가 핵심이다. "나중에 쓸 거라서 남겨 둔다"가 주석 속 구전이 아니라
**깨질 수 있는 선언**이 된다. 현재 `PLANNED`에는 `run_agent_loop` 하나가
"W1 D4 model-in-the-loop 기준선 측정에서 사용 예정"이라는 사유로 등록되어 있고,
W1 D4가 끝나면 자동으로 실패하면서 목록에서 빼라고 알려 준다.

**검증**

| 항목 | 결과 |
|---|---|
| 회귀 7스위트 | 전부 PASS (기존 6개 + 신규 1개) |
| `ruff check src tests` | All checks passed |
| ast import 재감사 | 미사용 공개 이름 0개 |
| 저장소 오염 | `.jsonl` 0개 |
| 코드 크기 | `agent.py` 381→352줄, `runtime.py` 662→633줄 |
| C8 유효성 | 일부러 죽은 이름을 넣어 테스트가 실패하는 것을 확인 후 원복 |

실행 경계(`runtime.Runtime`)와 보안 판정 코드(`security/`)는 **한 줄도 바꾸지
않았다.** 기존 6스위트가 그대로 통과한 것이 그 근거다.

---

## Part B — 문서 (5/5 처리)

| ID | 심각도 | 처리 |
|---|---|---|
| B-01 | 높음 | 같은 번호 다른 내용이던 `ThreatModel0.5.md` 문제를 `docs/THREAT_MODEL.md` v0.7 단일 문서로 해소. 버전 인터페이스와 변경 이력 표 명시 |
| B-02 | 높음 | Day9에서 사라졌던 Day8 `schema.md` 1~9절(Provenance·ObservationEnvelope·RuntimeResult·복수 observation·JSONL trace)을 `docs/DATA_INTERFACE.md`로 복원 통합 |
| B-03 | 중간 | 7개로 분기했던 `permission_policy.md`를 `docs/PERMISSION_POLICY.md` 하나로 통합 |
| B-04 | 중간 | 루트 `README.md` 신설 — 30초 요약, 재현 명령, Day1~9 커리큘럼 대응표, 현재 한계 |
| B-05 | 낮음 | 공백 포함 파일명 제거. 모든 문서를 `docs/` 아래 밑줄 표기로 통일 |

---

## Part C — 저장소·재현성 (5/5 처리)

| ID | 심각도 | 처리 |
|---|---|---|
| C-01 | 높음 | `requirements.txt`(정확한 `==` 버전), `.python-version`, `pyproject.toml` 추가 |
| C-02 | 높음 | Day별 전체 복사 구조를 단일 `src/` 트리로 통합. Day 경계는 fixture ID와 문서로만 표현 |
| C-03 | 중간 | trace 기본 출력을 저장소 밖 임시 디렉터리로 이동(`lab_paths.trace_root()`). 보고서 인용 run만 `LAB_TRACE_ROOT`로 `evidence/`에 승격 |
| C-04 | 중간 | `conftest.py` + pytest 설정으로 루트에서 일괄 실행. ruff 설정 추가 후 61건 검출·전부 수정 |
| C-05 | 낮음 | 가상환경을 저장소에서 제외. `requirements.txt`로 재생성 |

---

## 검증

수정 후 전체 회귀 스위트 재실행 결과.

| 테스트 | 대상 | 결과 |
|---|---|---|
| `test_policy_reachability.py` | A-01 회귀 (신규) | PASS |
| `test_mcp_tool_schema.py` | D9-E01~E06 + 격리 검사 | PASS |
| `test_indirect_injection.py` | D7-E01~E02 | PASS |
| `test_policy_boundary.py` | D8-E01~E06 | PASS |
| `test_security_invariants.py` | D9-E07~E09 | PASS |
| `test_layer_separation.py` | A-13 회귀 | PASS |
| `test_public_api_interface.py` | RFC-001 회귀 (신규) | PASS |

추가 확인.

- `ruff check src tests` → 0 errors (수정 전 61건)
- 테스트 5종 실행 후 저장소 내 `.jsonl` 파일 0개 (C-03 확인)
- 저장소에 실제 자격 증명·토큰 없음. `sandbox/secret/dome.env`는 합성 canary

---

## 이번에 처리하지 않은 것

| 항목 | 이유 |
|---|---|
| model-in-the-loop ASR 실측 | 루프는 구현했으나 측정은 실험 단계다. 12주 계획 W1 D4에 배치 |
| 관측 계층(trace 무결성) 공격 시나리오 | 새 위협 클래스 설계가 필요하다. 12주 계획 W2 D5에 배치 |
| Day1~Day6 코드 | 이번 요청 범위는 D7~D9. Day1~6은 기존 저장소에 그대로 보존 |
