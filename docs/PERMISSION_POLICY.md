# PERMISSION POLICY — 단일 기준

| 필드 | 값 |
|---|---|
| 버전 | v2.0 |
| 대체 대상 | Day3·4·5·6·7·8·9의 `permission_policy.md` 7개 사본 |
| 구현 | `src/security/permission.py` (`POLICY`), `src/security/policy.py` (`PolicyEngine`) |

> **왜 하나로 합쳤는가.** 이전 저장소에는 같은 이름의 정책 문서가 7개 있었고 내용이 모두 달랐다
> (37줄부터 154줄까지). 정책 문서는 enforcement의 근거이므로 사본이 여러 개면 코드가 어느 문서를
> 구현한 것인지 대응할 수 없다. 이 문서가 유일한 기준이다.

---

## 계층별 역할 분리

세 계층이 각각 **다른 질문**에 답한다. 이전 버전에서는 세 계층이 같은 질문(경로 범위)에
답하면서 서로 어긋났고, 그 결과 아래 `POLICY` 규칙 여러 개가 어떤 호출로도 도달하지 못했다.

| 계층 | 파일 | 답하는 질문 |
|---|---|---|
| MCP schema gate | `security/tool_schema.py` | 도구를 노출했는가 · **인자 인터페이스를 지켰는가** · 경로가 구조적으로 안전한가 |
| Runtime validation | `runtime.py` | 이 문자열을 **정규화된 실체로 바꿀 수 있는가**(심볼릭 링크 추적, 셸 분해) |
| **Policy (이 문서)** | `security/permission.py` | **이 도구가 이 범위에 접근해도 되는가** |
| Authorization | `security/authorization.py` | 이 actor가 이 리소스의 소유자·멤버인가 |

인자 인터페이스 검사는 schema gate **한 곳에서만** 한다. 이전에는 `runtime.py`의
`ARGUMENT_SPEC`이 같은 검사를 중복으로 수행했고, 두 목록이 어긋나면 A-01과 같은
유형의 도달 불가 분기가 생겼다. `tests/test_layer_separation.py`가 재발을 막는다.

`tests/test_policy_reachability.py`가 "여기 선언된 모든 scope가 실제로 평가되는가"를 회귀로 검사한다.

---

## 범위(scope) 정의

모든 경로는 `SANDBOX_ROOT` 기준 상대 경로다. Runtime이 root를 붙이므로 도구 인자에
`sandbox/` 문자열을 넣지 않는다.

| scope | 의미 | 예시 |
|---|---|---|
| `sandbox_root` | sandbox 최상위 그 자체 | `.` |
| `root_file` | 최상위 직하위 파일 | `notes.txt` |
| `data` | `data` 디렉터리와 그 하위 전체 | `data/user-001/notes.txt` |
| `other_subdirectory` | 그 밖의 하위 디렉터리 | 현재 어떤 규칙도 허용하지 않음 |

## 도구별 규칙

| 도구 | capability | 허용 범위 | 승인 |
|---|---|---|---|
| `calculator` | `calculator.execute` | — | 불필요 |
| `get_time` | `clock.read` | `system:clock` | 불필요 |
| `read_file` | `filesystem.read` | `data` | 불필요 |
| `list_files` | `filesystem.list` | `sandbox_root`, `data` | 불필요 |
| `write_file` | `filesystem.write` | `root_file`, `data` | **필요** |
| `run_command` | `command.read` | `pwd`, `ls`, `cat`만 · 경로는 위임 도구의 범위를 따름 | 불필요 |

`write_file`의 `root_file`은 Policy 단계에서는 허용되지만 Authorization 단계에서
`RESOURCE_NOT_REGISTERED`로 거부된다. 이는 죽은 분기가 아니라 **의도된 계층 방어**다.
Policy는 "범위상 가능한가"에, Authorization은 "이 리소스에 주인이 있는가"에 답한다.

## 평가 순서

`PolicyEngine.evaluate()`는 아래 순서로 판정하며, 먼저 걸리는 규칙의 reason code를 반환한다.
순서 자체가 인터페이스다.

```text
1. provenance → trust label 계산
2. 민감 리소스 이름 검사        → SENSITIVE_RESOURCE_DENIED
3. capability allowlist 검사    → CAPABILITY_NOT_ALLOWLISTED
4. untrusted provenance 검사    → UNTRUSTED_PROVENANCE_CANNOT_AUTHORIZE_TOOL
5. 범위·명령 규칙 검사          → RESOURCE_OR_COMMAND_SCOPE_DENIED
6. 승인 필요 여부               → WRITE_REQUIRES_EXPLICIT_APPROVAL
7. 통과                         → BASELINE_CAPABILITY_ALLOWED
```

4번이 5번보다 **먼저** 오는 것이 핵심이다. 비신뢰 출처의 제안은 승인 단계에 도달하기 전에
항상 거부되므로, approval ID로 파일·웹·도구 출력에서 유래한 명령을 되살릴 수 없다.

## 민감 리소스 판정

이름 조각이 다음 중 하나에 해당하면 범위 검사 이전에 거부한다.

- 정확히 일치: `.env`, `credential(s)`, `secret(s)`, `id_rsa`, `token(s)`, `password(s)`
- 확장자: `.env`, `.pem`, `.key`, `.p12`, `.pfx`, `.keystore`
- 부분 문자열: `credential`, `secret`, `token`, `password`, `passwd`, `apikey`, `api_key`

확장자·부분 문자열 규칙은 이번 개정에서 추가했다. 이전 규칙은 조각이 정확히 일치하거나
특정 접두사로 시작할 때만 판정해 `api.env` 같은 이름을 놓쳤다.

## 인가(Authorization) 규칙

| 리소스 종류 | 판정 경로 | 읽기·목록 | 쓰기 |
|---|---|---|---|
| `public_read` | `.`, `data`, `sharedbook.txt` | 허용 | 거부 |
| `private` | `data/{actor-id}/**` | 소유자만 | 소유자만, **본인 승인 필요** |
| `shared` | `data/shared`, `data/shared/**` | 멤버만 | 멤버만, **reviewer 승인 필요** |
| `unregistered` | 그 밖 전부 | 거부 | 거부 |

- `actor`는 인증·session·test harness에서만 들어온다. **LLM 인자에서 오지 않는다.**
- `reviewer-001`은 승인자 전용 신원이며 도구 접근 권한이 없다.
- `data`와 `data/shared` 디렉터리 자체를 `public_read`/`shared`로 인정한 것은 이번 개정 사항이다.
  이전에는 하위 파일만 매칭되어 정상적인 목록 조회가 과차단(over-block)되었다.

## 승인(Approval) 규칙

- 승인은 특정 `ToolIntent` 지문(fingerprint)에 결속된다. 인자가 하나라도 다르면 무효다.
- 기본 TTL 10분. 만료 시 `EXPIRED`.
- dispatch 직전에 `consume()`으로 1회용 소비. 같은 ID 재제출은 `CONSUMED` 상태라 실행되지 않는다.
- 승인자는 `required_approver`와 정확히 일치해야 한다. 요청자와 승인자를 분리해 기록한다.

## 쓰기 시 디렉터리 정책

도구는 디렉터리를 만들지 않는다. 부모 디렉터리가 이미 존재할 때만 쓰기가 가능하며,
없으면 `NotADirectoryError`로 거부된다. 실험 환경이 제공하는 네임스페이스는
`experiment_support.DECLARED_SANDBOX_DIRECTORIES`에 선언한다.

이전에는 `mkdir(parents=True)`로 임의 깊이의 디렉터리를 만들 수 있었다. 인가 판정이
`data/{actor}/` 디렉터리 이름에 의존하므로, 이는 에이전트가 ownership 네임스페이스를
스스로 만들 수 있다는 뜻이었다.

## 변경 이력

| 버전 | 변경 |
|---|---|
| v1.x (Day 3~9) | 7개 사본으로 분기 |
| v2.1 | `ARGUMENT_SPEC` 제거로 인자 인터페이스 검사 단일화. schema gate / validation 역할 명시 |
| v2.0 | 단일 문서로 통합 · 계층 역할 분리 명시 · 민감 판정 확장 · `data`/`data/shared` 과차단 해소 · 디렉터리 자동 생성 금지 |
