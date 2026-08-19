# 권한 정책 v0.2 — Day 4

## 범위

모든 path 인자는 `SANDBOX_ROOT` 기준 상대 경로다. Runtime이 root를 자동으로 붙이므로 `notes.txt`, `data/example.txt`를 쓰며 `sandbox/notes.txt`는 쓰지 않는다.

Validation은 “형식이 맞고 sandbox 밖으로 탈출하지 않는가?”를 답한다. Policy는 “이 리소스 범위가 허용되는가?”를 답한다. Validation 통과는 permission을 의미하지 않는다.

## 리소스 정책

| 도구 | 허용 범위 | 승인 | 거부 예시 |
|---|---|---|---|
| `read_file` | root file 및 `data/...` | 불필요 | `private/a.txt` |
| `list_files` | sandbox root(`.`) 및 `data/...` | 불필요 | `private/` |
| `write_file` | root file만 | 직접 사용자 요청의 명시적 승인 필요 | `data/out.txt`, `private/out.txt` |
| `run_command` | `pwd`; 허용 list 범위의 `ls`; 허용 read 범위의 `cat` | 불필요 | `rm`, `curl`, `cat private/a.txt` |

예시:

```text
read_file("notes.txt")       -> 직접 사용자 provenance면 allow
read_file("data/test.txt")   -> 직접 사용자 provenance면 allow
write_file("output.txt")     -> 직접 사용자 provenance면 approval_required
write_file("data/out.txt")   -> deny (리소스 범위)
write_file("output.txt")     -> repository provenance면 deny (untrusted)
```

## 결정 순서

1. Validation: 인자 형태와 sandbox 탈출을 검사한다.
2. Policy: 민감 리소스, capability allow-list, provenance trust, 이 문서의 리소스/명령 표 순서로 검사한다.
3. Approval: 허용된 직접 사용자 root-file 쓰기만 이 단계에 도달한다.
4. Runtime: `allow` 또는 일치·미만료·일회용 승인 요청만 Dispatcher로 보낸다.

특히 untrusted provenance는 2단계에서 `deny`되므로 approval ID로 우회할 수 없다.

실행 설정은 `security/permission.py`, 해석 코드는 `security/policy.py`에 있다. Agent 코드에 별도 permission 목록을 만들지 않는다.
