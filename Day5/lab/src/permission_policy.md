# 권한 정책 v0.4 — Day 5

## 범위

모든 path 인자는 `SANDBOX_ROOT` 기준 상대 경로다. Runtime이 root를 자동으로 붙이므로 `notes.txt`, `data/example.txt`를 쓰며 `sandbox/notes.txt`는 쓰지 않는다.

Validation은 “형식이 맞고 sandbox 밖으로 탈출하지 않는가?”를 답한다. Policy는 “이 리소스 범위와 행동 유형이 원칙적으로 허용되는가?”를 답한다. Authorization은 “인증된 actor가 이 정확한 resource에 접근할 수 있는가?”를 답한다. Validation 통과는 permission을 의미하지 않는다.

## 리소스 정책

| 도구 | 허용 범위 | 승인 | 거부 예시 |
|---|---|---|---|
| `read_file` | root file 및 `data/...` | 불필요. 단, Authorization 통과 필요 | `private/a.txt` |
| `list_files` | sandbox root(`.`) 및 `data/...` | 불필요. 단, Authorization 통과 필요 | `private/` |
| `write_file` | root file 및 `data/...` | 직접 사용자 요청의 명시적 승인 + Authorization 통과 필요 | `private/out.txt` |
| `run_command` | `pwd`; 허용 list 범위의 `ls`; 허용 read 범위의 `cat` | 불필요 | `rm`, `curl`, `cat private/a.txt` |

## 접근 가능 리소스

Authorization은 Validation에서 canonical path로 바뀐 resource와 인증된 actor를 비교한다. actor 이름은 LLM tool argument가 아니라 session, IdP 또는 이 Lab의 test harness가 Runtime에 전달한다.

| resource | 접근 가능한 actor | read/list | write | 승인자 |
|---|---|---|---|---|
| `notes.txt`, `.` | 인증된 일반 actor | 가능 | 불가 | 없음 |
| `data/{ACTOR_NAME}/**` | path의 `{ACTOR_NAME}`과 같은 actor | 가능 | 가능 | 해당 actor 본인 |
| `data/shared/**` | `user-001`, `user-003` | 가능 | 가능 | `reviewer-001` |
| 다른 actor의 `data/{ACTOR_NAME}/**` | 해당 없음 | 불가 | 불가 | approval ID 발급 전 `FORBIDDEN` |
| 미등록 path | 해당 없음 | 불가 | 불가 | 없음 |

`reviewer-001`은 현재 Lab에서 공유 write 검토자 역할을 나타내는 fixture identity다. 실제 운영에서는 이 값을 팀 ACL, 데이터 소유자, change manager 같은 인증된 역할로 교체한다.

예시:

```text
read_file("notes.txt")                     -> 직접 사용자 provenance면 allow
read_file("data/user-001/a.txt")           -> actor=user-001이면 allow
read_file("data/user-002/a.txt")           -> actor=user-001이면 forbidden (cross-user)
write_file("data/user-001/out.txt")        -> actor=user-001이면 approval_required
write_file("data/shared/out.txt")          -> actor=user-003이면 reviewer-001 approval_required
write_file("data/user-001/out.txt")        -> repository provenance면 deny (untrusted)
```

## 결정 순서

1. Validation: 인자 형태와 sandbox 탈출을 검사하고 canonical path를 만든다.
2. Policy: 민감 리소스, capability allow-list, provenance trust, 이 문서의 리소스/명령 표 순서로 검사한다.
3. Authorization: actor와 canonical resource의 owner/member 관계 및 action을 검사한다. cross-user 접근은 여기서 `FORBIDDEN`이며 approval ID가 만들어지지 않는다.
4. Approval: Authorization을 통과한 직접 사용자 write만 이 단계에 도달한다. 개인 경로 write는 owner actor, shared write는 `reviewer-001`의 승인이 필요하다.
5. Runtime: validation·policy·authorization을 재검증하고, fingerprint가 일치하는 미만료·일회용 승인만 consume한 뒤 Dispatcher로 보낸다.

특히 untrusted provenance는 2단계에서 `deny`되므로 approval ID로 우회할 수 없다. Policy가 `ALLOW` 또는 `APPROVAL_REQUIRED`여도 Authorization이 `DENY`이면 실행되지 않는다.

실행 설정은 `security/permission.py`, Policy 해석은 `security/policy.py`, actor-resource-action 해석은 `authorization.py`에 있다. Agent 코드에 별도 permission 목록을 만들지 않는다.
