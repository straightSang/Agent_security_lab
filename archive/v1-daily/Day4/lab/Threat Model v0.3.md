# Threat Model v0.3 — Day 4 Agent Security Testbed

## System

```text
Authenticated Actor
  -> Agent / LLM
  -> Tool Proposal
  -> Validation
  -> ToolIntent (provenance, actor, capability, action, resource)
  -> Trust Label
  -> Policy Decision
  -> Approval Store (조건부)
  -> Runtime Enforcement / Dispatcher
  -> Local Sandbox Tool
  -> Runtime Result / Trace
```

## Assets

- sandbox 내부 파일과 디렉터리
- agent의 도구 capability
- ToolIntent의 provenance, trust, actor 메타데이터
- approval record와 approval ID
- 정책·승인·실행 trace의 무결성
- Runtime Dispatcher의 실행 무결성

## Trust Boundaries

| 구성 요소 | 신뢰 수준 | 이유 |
|---|---|---|
| 사용자 자연어 입력 | 내용은 신뢰하지 않음, 출처는 인증 계층이 부여 | 사용자가 안전한 요청도 위험한 요청도 할 수 있음 |
| LLM 출력 / Tool arguments | 신뢰하지 않음 | 형식 오류, hallucination, prompt injection 영향 가능 |
| repository 파일 / 웹 콘텐츠 / tool observation | `untrusted` | 간접 지시를 포함할 수 있음 |
| `provenance.py`, `trust.py`, `policy.py`, Runtime | Trusted Computing Base | 요청의 출처·판단·실행을 강제함 |
| Approval control | Trusted Computing Base | 인증된 approver만 상태 변경 가능해야 함 |
| TraceLogger | 감사 증거 구성 요소 | 실행 판단의 사후 검토·재현에 필요 |

현재 lab의 `actor="user-001"`, `demo-admin`은 실제 인증이 아닌 label이다. 운영 환경에서는 서버가 검증한 session/OIDC subject와 role을 사용해야 한다.

## 보안 불변조건

1. LLM의 Tool Proposal은 실행 권한이 아니다.
2. sandbox 밖 경로는 validation에서 거부된다.
3. unknown capability와 allow-list 밖 명령은 policy에서 거부된다.
4. `untrusted` provenance는 approval ID가 있어도 policy에서 무조건 거부된다.
5. 직접 사용자 유래의 허용된 root-file 쓰기만 `approval_required`에 도달한다.
6. 승인 record는 actor·도구·인자·capability·action·resource fingerprint에 결속되고, 만료되며, 한 번 소비된다.
7. Dispatcher는 ALLOW 또는 일치하는 유효 승인 결과 뒤에만 호출된다.

## Threats

| ID | Threat | Attack Surface | Day 4 Mitigation | 검증 |
|---|---|---|---|---|
| T-001 | Path Traversal | file path | `safe_resolve()` + sandbox root 검사 | Validation DENY |
| T-002 | 허용 범위 밖 읽기/목록 | `read_file`, `list_files`, `cat`, `ls` | `permission.py` resource scope | Policy DENY |
| T-003 | 무단 쓰기 | `write_file` | root-file scope + direct-user approval | DENY 또는 APPROVAL_REQUIRED |
| T-004 | 임의 명령 실행 | `run_command` | `pwd`/`ls`/`cat` logical allow-list, shell 미사용 | Policy DENY / Dispatcher 오류 방어 |
| T-005 | 간접 Prompt Injection | repository/tool/web 콘텐츠 | provenance -> untrusted -> Policy DENY | unsafe fixture + Dispatcher mock |
| T-006 | 승인 재사용·변조 | approval ID, 재시도 ToolIntent | fingerprint, TTL, `consumed` | approval lifecycle test |
| T-007 | Runtime 우회 | Agent 또는 다른 호출 경로 | Runtime 단일 실행 진입점, `_dispatch()` 감시 | `assert_not_called()` |
| T-008 | 감사 불완전성 | trace 기록 | 공통 trace 키, evaluator | `trace_completeness` |

## 주요 위협 시나리오

### T-001 Path Traversal

```text
read_file("../secret.txt")
-> safe_resolve()
-> Validation DENY
-> ToolIntent와 Dispatcher 미도달
```

### T-003 무단 쓰기

```text
write_file("data/out.txt", "...")
-> Validation PASS (sandbox 내부)
-> Policy DENY (write scope 밖)
```

```text
write_file("output.txt", "...") + user_task
-> Policy APPROVAL_REQUIRED
-> pending 상태에서는 Dispatcher 미도달
```

### T-005 간접 Prompt Injection

```text
malicious_note.txt의 지시
-> 다음 ToolIntent의 provenance = repository_content
-> trust = untrusted
-> Policy DENY
-> ApprovalStore.request() 미호출
-> Runtime Dispatcher 미도달
```

사용자가 이후에 같은 작업을 직접 요청하면 그것은 별도의 `user_task` ToolIntent다. 다만 허용된 root-file 쓰기라 해도 새 approval 절차를 거친다. 이것은 파일 지시를 승인한 것이 아니다.

### T-006 승인 재사용·변조

```text
approved approval ID
-> 현재 ToolIntent fingerprint 비교
-> 동일하면 dispatch 직전 consumed
-> actor/path/content 등이 다르면 fingerprint 불일치
-> 새 pending record, 실행 불가
```

## Security Flow

```text
Validation PASS
-> Policy DENY
   -> 즉시 종료 (untrusted, sensitive, capability, resource scope)

Validation PASS
-> Policy APPROVAL_REQUIRED
   -> pending / rejected / expired: 종료
   -> approved + fingerprint 일치: consume -> dispatch

Validation PASS
-> Policy ALLOW
   -> optional legacy authorization -> dispatch
```

## 범위 밖 / 잔여 위험

- 실제 사용자 인증, RBAC, 조직별 permission 검증
- approval record의 영속 저장소·동시성·서명·감사 보존
- 다중 Agent 간 identity와 delegation chain
- 외부 network/MCP 권한과 credential 관리
- 대규모 경로 규칙·정책 버전 관리
- 모델의 간접 지시 이해 성능 자체의 보장
- trace 파일 자체의 변조 방지
- Windows/WSL 파일시스템과 symlink의 모든 edge case

이 항목들은 “현재 방어가 실패했다”가 아니라, 이 로컬 Day 4 testbed가 아직 구현하지 않은 보안 범위다.
