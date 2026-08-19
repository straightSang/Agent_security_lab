아래는 강의·블로그·사내 교육 자료에 바로 쓸 수 있는 교육용 원고 초안입니다.  
참고로 MCP는 Anthropic이 시작한 공개 프로토콜이지만, 현재는 Linux Foundation 산하 Agentic AI Foundation에 기증되어 벤더 중립적으로 운영됩니다. [공식 발표](https://blog.modelcontextprotocol.io/posts/2025-12-09-mcp-joins-agentic-ai-foundation/)

# Chapter 2. MCP(Model Context Protocol)의 개념과 활용

## 2.1 MCP란 무엇인가

MCP(Model Context Protocol)는 LLM 애플리케이션이 외부 데이터와 도구에 일관된 방식으로 연결되도록 돕는 개방형 프로토콜이다. 기존에는 각 AI 애플리케이션과 각 서비스가 개별 연동 코드를 만들어야 했다. MCP는 이 연결 방식을 표준화해, 하나의 MCP 서버가 여러 호환 클라이언트와 연동될 수 있게 한다.

쉽게 말해 MCP는 “AI가 외부 세계와 대화하는 공통 인터페이스”다. 모델은 자연어로 판단하지만, 실제 데이터 조회나 시스템 작업은 MCP가 정의한 구조화된 요청을 통해 수행한다.

MCP 구조는 보통 다음 세 역할로 나뉜다.

| 구성 요소 | 역할 | 예시 |
|---|---|---|
| Host | 사용자와 AI 경험을 제공하는 애플리케이션 | 데스크톱 AI 앱, 사내 에이전트 |
| MCP Client | Host 내부에서 MCP 서버와 통신하는 구성 요소 | 도구 목록 조회, 호출 요청 전송 |
| MCP Server | 데이터·도구를 안전한 인터페이스로 제공 | 문서 검색, 주문 조회, 사내 API 호출 |

MCP 서버는 대표적으로 다음 기능을 제공한다.

- Tools: 실제 작업을 수행하는 함수. 예: `get_order`, `create_ticket`
- Resources: 모델이 읽을 수 있는 데이터나 문서
- Prompts: 재사용 가능한 프롬프트 템플릿

프로토콜 메시지는 JSON-RPC 기반이며, 현재 표준 전송 방식으로는 로컬 프로세스 연결에 적합한 `stdio`와 원격 서버 연결에 적합한 Streamable HTTP가 사용된다. [MCP 전송 규격](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2026-07-28/basic/transports/index.mdx)

## 2.2 왜 MCP를 사용하는가

MCP의 핵심 가치는 모델 교체와 도구 교체에 강한 구조를 만드는 데 있다. 에이전트 애플리케이션은 MCP Client를 통해 도구를 호출하고, 도구 구현은 MCP Server 뒤에 둔다. 따라서 모델 제공자나 UI가 바뀌어도 서버의 인터페이스를 유지할 수 있다.

그러나 MCP가 보안을 자동으로 해결하지는 않는다. MCP는 연결 규약이며, 실제 안전성은 다음 설계에 달려 있다.

1. 도구 입력을 스키마로 검증하는가  
2. 모델의 제안을 즉시 실행하지 않는가  
3. 도구별 권한과 승인 절차가 분리되어 있는가  
4. 외부 연동 전 로컬 환경에서 재현 가능한 테스트를 수행하는가  

## 2.3 안전한 MCP Testbed 구축

교육과 초기 개발에서는 실제 외부 API 대신 로컬 fixture를 사용하는 Testbed를 먼저 만든다. 이 환경의 목적은 “모델이 무엇을 제안했는가”와 “시스템이 무엇을 실행했는가”를 분리해 관찰하는 것이다.

권장 구조는 다음과 같다.

```text
mcp-testbed/
├─ server/
│  ├─ tools.py          # MCP 도구 정의
│  ├─ schemas.py        # Pydantic/JSON Schema
│  ├─ policy.py         # 권한 및 승인 규칙
│  └─ executor.py       # 허용된 작업만 실행
├─ fixtures/
│  ├─ orders.json       # 모의 주문 데이터
│  └─ users.json        # 모의 사용자 데이터
├─ traces/
│  └─ .gitkeep
├─ tests/
│  ├─ test_schema.py
│  ├─ test_policy.py
│  └─ test_e2e.py
└─ README.md
```

초기 Testbed에서는 다음 원칙을 지킨다.

- 실제 고객 정보, API 키, 운영 DB를 넣지 않는다.
- 외부 네트워크 호출을 기본적으로 차단한다.
- fixture는 Git에 함께 기록한다.
- 테스트는 항상 같은 입력에 같은 결과가 나오도록 만든다.
- 실행 로그에는 비밀번호·토큰·개인정보를 남기지 않는다.

# Chapter 3. 입력 및 도구 스키마 검증

## 3.1 모델 출력은 신뢰할 수 없는 입력이다

LLM이 생성한 도구 호출 인자는 문법적으로 그럴듯해도 잘못된 값일 수 있다. 예를 들어 주문 조회 도구에 문자열이 아닌 객체가 전달되거나, 존재하지 않는 상태값이 들어가거나, 삭제 범위를 과도하게 넓히는 인자가 전달될 수 있다.

따라서 모델 출력은 내부 시스템의 명령이 아니라 “검증이 필요한 외부 입력”으로 취급해야 한다.

도구 정의에는 최소한 다음을 명시한다.

- 필수 필드
- 데이터 타입
- 허용 값
- 길이·범위 제한
- 기본값
- 추가 필드 허용 여부
- 사용자·조직·리소스 범위

MCP는 프로토콜 차원에서 JSON Schema를 활용하며, 기본 스키마 방언으로 JSON Schema 2020-12를 지원한다. [MCP 스키마 규격](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/draft/basic/index.mdx)

## 3.2 Pydantic을 이용한 검증 예시

다음은 주문 조회 도구의 입력을 검증하는 예시다.

```python
from enum import Enum
from pydantic import BaseModel, ConfigDict, Field

class OrderStatus(str, Enum):
    PAID = "paid"
    SHIPPED = "shipped"
    CANCELLED = "cancelled"

class GetOrderInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    order_id: str = Field(
        min_length=8,
        max_length=32,
        pattern=r"^ORD-[A-Z0-9]+$"
    )
    include_customer_name: bool = False
    status: OrderStatus | None = None
```

`extra="forbid"`는 정의되지 않은 필드를 거부한다. 이것은 모델이 임의로 `delete_all=true` 같은 인자를 덧붙이더라도 서버가 받아들이지 않게 하는 방어선이다.

도구 호출부는 반드시 검증 단계를 통과한 객체만 받도록 구성한다.

```python
def get_order(raw_arguments: dict, actor: str):
    try:
        request = GetOrderInput.model_validate(raw_arguments)
    except Exception:
        return {
            "ok": False,
            "error": "INVALID_ARGUMENT",
            "message": "도구 입력 형식이 올바르지 않습니다."
        }

    return lookup_fixture_order(
        order_id=request.order_id,
        actor=actor,
        include_customer_name=request.include_customer_name
    )
```

중요한 점은 스키마 검증이 권한 검증을 대체하지 않는다는 것이다. `order_id`의 형식이 맞더라도, 요청자가 그 주문을 볼 권한이 있는지는 별도로 확인해야 한다.

## 3.3 방어적 에이전트 설계 원칙

잘못된 요청에 대한 응답은 내부 구현 세부 정보를 노출하지 않아야 한다. 사용자나 모델에는 간결한 오류 코드를 돌려주고, 상세 원인은 보안 처리된 Trace에 기록한다.

권장 오류 유형은 다음과 같다.

- `INVALID_ARGUMENT`: 타입·형식·범위 오류
- `UNKNOWN_TOOL`: 허용되지 않은 도구
- `FORBIDDEN`: 권한 부족
- `CONFIRMATION_REQUIRED`: 사람 승인 필요
- `POLICY_DENIED`: 정책상 금지된 작업
- `EXECUTION_FAILED`: 검증 이후 실행 과정의 실패

# Chapter 4. 모델 출력과 실행 권한의 디커플링

## 4.1 판단과 실행은 다르다

모델이 “환불을 처리해야 한다”고 판단하는 것과, 실제 결제 시스템에서 환불을 실행할 권한은 전혀 다른 문제다.

안전한 에이전트는 다음 흐름을 가져야 한다.

```text
모델의 제안
   ↓
스키마 검증
   ↓
정책·권한 검사
   ↓
위험도 판정
   ↓
사용자 또는 관리자 승인
   ↓
제한된 실행기(Executor)
   ↓
결과와 Trace 기록
```

이 구조에서 모델은 `ActionProposal`을 만들 수는 있어도 직접 시스템 명령을 실행할 수 없다. 실제 실행기는 승인된 액션만 받고, 액션별로 최소 권한을 가진 계정이나 토큰을 사용한다.

## 4.2 액션 등급 설계

교육용 Testbed에서는 도구를 세 등급으로 나누는 방식이 이해하기 쉽다.

| 등급 | 예시 | 처리 방식 |
|---|---|---|
| Read | 주문 상태 조회, FAQ 검색 | 자동 실행 가능 |
| Write-Low | 임시 메모 생성, 초안 생성 | 정책 검사 후 실행 |
| Write-High | 환불, 고객 정보 변경, 삭제 | 명시적 사용자 승인 필요 |

예를 들어 모델이 `refund_payment`를 호출하려 해도 다음 조건을 모두 충족해야 한다.

- 입력 스키마가 유효한가
- 사용자가 해당 주문에 접근할 수 있는가
- 환불 금액이 정책 한도 이내인가
- 동일 요청이 중복되지 않았는가
- 사용자가 최종 승인했는가
- 실행 서비스 계정에 필요한 최소 권한만 있는가

이러한 분리는 프롬프트 인젝션이나 모델의 오판이 바로 시스템 변경으로 이어지는 것을 막는다.

## 4.3 Guardrail의 역할

Guardrail은 모델을 “믿을 수 있게 만드는 장치”가 아니라, 모델을 완전히 신뢰하지 않아도 안전하게 운영하기 위한 시스템 경계다.

대표적인 Guardrail은 다음과 같다.

- 도구 allowlist: 등록된 도구만 호출 허용
- 입력 검증: JSON Schema 또는 Pydantic 검증
- 정책 엔진: 역할, 리소스 소유권, 금액 한도 확인
- 승인 UI: 고위험 작업의 최종 사용자 확인
- 속도 제한: 반복·대량 호출 방지
- 감사 로그: 요청자, 입력 요약, 정책 결정, 결과 기록
- 비밀정보 마스킹: Trace에서 토큰·개인정보 제거

원격 MCP 서버의 경우 OAuth 기반 권한 부여, 짧은 수명의 토큰, 최소 권한 scope, 토큰 검증이 중요하다. 특히 서버는 전달받은 토큰이 자기 서버용으로 발급된 것인지 검증해야 하며, 검증하지 않은 토큰을 하위 API에 그대로 넘기는 방식은 피해야 한다. [MCP 보안 모범 사례](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)

# Chapter 5. Fixture 기반의 로컬 샌드박스

## 5.1 Fixture가 필요한 이유

외부 API를 직접 호출하는 테스트는 느리고, 비용이 들며, 네트워크나 운영 데이터 상태에 따라 결과가 달라질 수 있다. 반면 fixture는 미리 준비한 고정 입력과 예상 결과를 사용한다.

예를 들어 `fixtures/orders.json`에 다음과 같은 테스트 주문을 둔다.

```json
[
  {
    "order_id": "ORD-A1B2C3D4",
    "owner_id": "user-001",
    "status": "paid",
    "amount": 15000
  }
]
```

테스트는 다음과 같은 질문에 답해야 한다.

- 올바른 주문 ID는 조회되는가?
- 잘못된 형식은 실행 전에 거부되는가?
- 다른 사용자의 주문은 조회되지 않는가?
- 모델이 승인 없이 환불을 시도하면 차단되는가?
- 차단된 이유가 Trace에 남는가?

## 5.2 결정론적 테스트 원칙

결정론적 테스트란 동일한 코드와 동일한 fixture라면 언제나 같은 결과가 나오는 테스트다. 이를 위해 다음 값을 고정한다.

- 현재 시간
- 난수 시드
- 테스트 사용자 ID와 역할
- fixture 데이터
- 네트워크 상태: 기본적으로 외부 호출 금지
- 모델 응답: 실제 모델 대신 저장된 응답 또는 모의 객체 사용

실제 LLM 호출 테스트는 유용하지만 매번 동일한 결과를 보장하기 어렵다. 따라서 핵심 보안 규칙은 모델 없이도 검증할 수 있는 단위 테스트로 만들고, LLM 연동 테스트는 별도 계층으로 둔다.

# Chapter 6. 에이전트 트레이싱과 버전 관리

## 6.1 무엇을 기록할 것인가

Trace는 단순한 대화 로그가 아니다. 에이전트가 어떤 근거로 어떤 도구를 선택했고, 정책 엔진이 왜 허용하거나 거부했는지를 재현할 수 있어야 한다.

권장 Trace 필드는 다음과 같다.

```json
{
  "trace_id": "tr_20260816_001",
  "timestamp": "2026-08-16T10:00:00+09:00",
  "actor_id": "user-001",
  "user_request": "내 주문 상태를 알려줘",
  "tool_name": "get_order",
  "arguments_redacted": {
    "order_id": "ORD-A1B2C3D4"
  },
  "schema_valid": true,
  "policy_decision": "allowed",
  "execution_result": "success",
  "fixture_version": "orders-v1"
}
```

원문 프롬프트와 도구 결과가 민감 정보를 포함할 가능성이 있다면, Git에 저장하기 전에 마스킹하거나 요약해야 한다. API 키, 액세스 토큰, 주민번호, 이메일 전체값, 원본 고객 데이터는 Trace와 커밋에서 제외한다.

## 6.2 Git에 남겨야 할 것과 남기면 안 되는 것

Git에는 다음을 기록한다.

- 도구 스키마
- 정책 규칙
- fixture
- 테스트 코드
- 마스킹된 Trace 샘플
- 실패 사례와 회귀 테스트
- 의존성 버전 및 실행 방법

Git에 기록하지 않는다.

- `.env` 파일
- API 키와 토큰
- 운영 DB 덤프
- 실제 고객 정보
- 복구 불가능한 민감 Trace

좋은 커밋은 “무엇이 바뀌었는가”뿐 아니라 “어떤 위험을 막기 위해 바꿨는가”를 설명한다. 예를 들어 `fix: reject unknown arguments in refund tool`처럼 남기면, 나중에 보안 정책의 변화를 추적하기 쉽다.

# MCP 자료를 검색하는 방법

검색은 “MCP”만 입력하기보다, 목적·기술·위험을 함께 넣는 편이 훨씬 좋습니다.

| 찾고 싶은 내용 | 권장 검색어 |
|---|---|
| MCP 기본 개념 | `Model Context Protocol official introduction` |
| 최신 명세 | `site:modelcontextprotocol.io specification MCP` |
| Python 서버 구현 | `site:modelcontextprotocol.io build MCP server Python` |
| 도구 스키마 | `MCP tools JSON Schema inputSchema` |
| 권한 부여 | `site:modelcontextprotocol.io MCP authorization OAuth security` |
| 프롬프트 인젝션 대응 | `MCP prompt injection tool security best practices` |
| Pydantic 검증 | `Pydantic v2 model_validate extra forbid API validation` |
| fixture 테스트 | `pytest fixture deterministic test mocking external API` |
| Trace 설계 | `agent tracing audit log tool call redaction` |
| 최신 변경 사항 | `site:blog.modelcontextprotocol.io specification release` |

검색 결과는 다음 순서로 검증합니다.

1. `modelcontextprotocol.io`와 공식 GitHub 조직의 문서를 먼저 본다.  
2. 글의 게시일과 명세 버전을 확인한다. MCP는 빠르게 변하므로 오래된 튜토리얼의 전송 방식이나 인증 설명이 현재 명세와 다를 수 있다.  
3. 블로그 글은 개념 이해에 사용하고, 구현 결정은 Specification과 SDK 문서로 재확인한다.  
4. 보안 관련 내용은 개인 블로그 하나에 의존하지 말고 공식 보안 가이드와 OAuth 표준을 함께 확인한다.  

시작점으로는 [MCP 공식 문서](https://modelcontextprotocol.io/), [공식 명세 저장소](https://github.com/modelcontextprotocol/modelcontextprotocol), [보안 모범 사례](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)가 가장 좋습니다.

----

## 추가 설명
여기서 말하는 **“MCP가 연결 방식을 표준화한다”**가 처음 보면 꽤 추상적입니다. 핵심은 **MCP가 생기기 전과 후를 비교**하면 쉽게 이해됩니다.

## 1. 먼저 MCP가 없다고 생각해보자

AI Agent가 외부 기능을 사용한다고 해봅시다.

예를 들어 Agent에게 이런 일을 시키고 싶습니다.

```text
"내 GitHub repository를 확인하고
관련 문서를 찾아서
이슈를 만들어줘."
```

LLM 자체는 기본적으로 이런 외부 시스템을 마음대로 사용할 수 없습니다.

```text
LLM
  X GitHub 접근
  X DB 접근
  X 로컬 파일 접근
  X 사내 API 접근
```

그래서 개발자가 연결 기능을 만들어야 합니다.

예를 들어:

```text
             ┌→ GitHub API용 코드
             │
AI Agent ────┼→ Google Drive용 코드
             │
             ├→ Database용 코드
             │
             └→ File System용 코드
```

문제는 **서비스마다 연결 방법이 다르다**는 겁니다.

GitHub는:

```text
Agent
→ GitHub API 형식으로 변환
→ HTTP Request
→ GitHub
```

DB는:

```text
Agent
→ SQL/DB Client 형식으로 변환
→ Database
```

Filesystem은:

```text
Agent
→ Python/OS 함수
→ Filesystem
```

즉 개발자가 각각의 연결 규칙을 만들어야 합니다.

---

# 2. MCP의 아이디어

MCP는 여기서 이렇게 생각합니다.

> 외부 기능을 AI에게 제공하는 **공통 규칙**을 만들면 어떨까?

그래서 구조를:

```text
                 MCP Server ─→ GitHub
                /
AI Application
                \
                 MCP Server ─→ Database
```

처럼 만듭니다.

AI 애플리케이션은 각 서비스의 세부 구현을 직접 이해하는 대신 **MCP라는 공통 프로토콜을 통해 기능을 발견하고 호출**합니다.

공식 MCP 명세도 MCP를 LLM 애플리케이션과 외부 context/tool을 연결하는 표준화된 방법으로 설명하고 있습니다. 통신의 기본 메시지 형식은 JSON-RPC 2.0입니다. 

비유하면 **USB와 비슷합니다.**

```text
MCP 이전

기기 A → 전용 연결 규격 A
기기 B → 전용 연결 규격 B
기기 C → 전용 연결 규격 C
```

USB가 있으면:

```text
기기 A ─┐
기기 B ─┼→ USB라는 공통 규격 → Computer
기기 C ─┘
```

MCP에서는:

```text
GitHub ────── MCP Server ─┐
Database ─── MCP Server ──┼→ MCP Client → AI Application
Filesystem ─ MCP Server ──┘
```

라고 생각하면 됩니다.

---

# 3. 그런데 중요한 게 하나 있다

MCP 자체가 GitHub나 DB인 것은 아닙니다.

그리고 MCP Server가 LLM인 것도 아닙니다.

각자의 역할이 다릅니다.

```text
LLM
│
│ "이 파일을 읽어야겠다"
▼
Host
│
▼
MCP Client
│
│ MCP 메시지
▼
MCP Server
│
│ 실제 기능 수행
▼
Filesystem / API / DB
```

공식 아키텍처에서도 **Host → Client → Server** 구조로 구분합니다. Host가 여러 MCP Client를 관리할 수 있고, 각각의 Client는 특정 Server와 세션을 맺습니다. 

예를 들어 Coding Agent를 아주 단순화하면:

```text
사용자
↓
"README.md 읽어줘"

LLM
↓
read_file이 필요하다고 판단

MCP Client
↓
MCP Server에 tool 호출 요청

Filesystem MCP Server
↓
read_file("README.md")

Filesystem
↓
README 내용 반환

MCP Server
↓
MCP Client
↓
LLM

"README의 내용은..."
```

이런 구조입니다.

---

# 4. 그러면 MCP Server가 실제로 제공하는 것은?

여기서 **Tools / Resources / Prompts**를 이해하면 MCP가 훨씬 선명해집니다.

공식 명세에서도 MCP Server의 핵심 primitive로 이 세 가지를 정의합니다. 

### Tools — “뭔가 해줘”

실행 가능한 기능입니다.

```text
read_file()
write_file()
search_database()
create_issue()
send_message()
```

예를 들어:

```text
Tool:
read_file

Input:
{
    "path": "README.md"
}
```

Tools는 외부 시스템에서 **행동하거나 정보를 조회하는 callable function**에 해당합니다. 

### Resources — “이 데이터를 읽어”

Context로 사용할 수 있는 데이터입니다.

```text
README.md
Database schema
Git history
Documentation
Configuration
```

예를 들어:

```text
resource://project/README.md
```

MCP 공식 문서도 Resources를 파일, DB schema 등 모델에게 context를 제공할 수 있는 데이터로 설명합니다. 

### Prompts — “이 작업은 이런 방식으로 해”

재사용 가능한 prompt template입니다.

예:

```text
/review-code

→

"다음 코드를 보안 관점에서 검토하고
취약점을 분류하십시오..."
```

Prompts는 서버가 Client에 제공할 수 있는 구조화된 재사용 템플릿입니다. 

따라서 아주 간단하게 외우면:

```text
Resources
= 읽을 것

Prompts
= 어떻게 할지 알려주는 템플릿

Tools
= 실제로 할 수 있는 것
```

---

# 5. 네 Mini Agent와 연결하면 더 쉽다

지금까지 만든 일반적인 Mini Agent 구조를 생각하면:

```text
LLM
↓
Tool Call
↓
Dispatcher
↓
Validation
↓
Authorization
↓
Runtime
↓
read_file()
write_file()
run_command()
```

여기서 `read_file`, `write_file` 등을 **MCP Server가 제공하는 Tool로 바꾸는 것**을 생각하면 됩니다.

```text
                 기존

LLM
↓
Tool Call
↓
내 Python Dispatcher
↓
read_file()
↓
Filesystem
```

MCP를 사용하면 개념적으로:

```text
                 MCP

LLM
↓
Host
↓
MCP Client
↓
MCP Protocol
↓
MCP Server
↓
read_file()
↓
Filesystem
```

즉
> **Tool을 Agent에 연결하는 인터페이스를 표준화하는 계층이 추가된다**

라고 이해하는 편이 좋습니다.

---

# 6. 왜 굳이 이렇게 복잡하게 만들까?

예를 들어 Agent A에 GitHub 기능을 붙였습니다.

MCP 없이 전용 구현이라면:

```text
Agent A
↓
내가 만든 GitHub 연결 코드
↓
GitHub
```

나중에 Agent B를 만들면 또 연결해야 할 수 있습니다.

```text
Agent B
↓
또 다른 integration
↓
GitHub
```

MCP 호환 구조라면 서버가 공통 인터페이스를 제공하기 때문에:

```text
Agent A ─┐
         │
Agent B ─┼→ MCP Server → GitHub
         │
Agent C ─┘
```

처럼 **클라이언트와 서버가 같은 프로토콜을 이해하도록 만들 수 있습니다.**

MCP 명세가 Language Server Protocol(LSP)을 비유로 드는 이유도 이것입니다. LSP가 여러 편집기와 언어 도구의 연결을 표준화한 것처럼 MCP는 AI 애플리케이션과 context/tools의 통합 방식을 표준화하려는 것입니다. 

---

# 7. 그런데 Agent Security에서는 여기부터가 중요하다

MCP를 단순히

```text
AI ↔ 외부 서비스 연결 기술
```

이라고만 배우면 부족합니다.

보안 연구자는 이렇게 봐야 합니다.

```text
Untrusted Input
↓
LLM
↓
Tool Selection
↓
MCP Client
↓
──────── Trust Boundary ────────
↓
MCP Server
↓
Tool
↓
Filesystem / Network / API / Credentials
```

왜냐하면 MCP Tool이 예를 들어:

```text
read_file
write_file
run_command
send_email
create_issue
query_database
```

를 제공한다면 LLM의 출력이 **실제 시스템 capability로 연결되는 통로**가 되기 때문입니다.

그래서 공격자가 LLM을 속여서:

```text
"README를 읽어"

→ 정상
```

대신

```text
"credential 파일을 읽어"

→ ?
```

를 유도했다고 생각해봅시다.

여기서 중요한 질문은:

```text
LLM이 read_file을 호출했는가?
```

에서 끝나지 않습니다.

진짜 보안 질문은:

```text
① 이 MCP Server는 어떤 Tool을 제공하는가?

② Tool은 어떤 arguments를 받는가?

③ arguments를 검증하는가?

④ 어떤 파일까지 읽을 권한이 있는가?

⑤ MCP Server 프로세스 자체의 OS 권한은?

⑥ LLM의 요청과 실제 실행 권한이 분리되어 있는가?

⑦ 사용자 승인이 필요한 작업은 무엇인가?

⑧ 결과가 다시 LLM Context에 들어갈 때 신뢰할 수 있는가?
```

입니다.

공식 MCP 아키텍처 역시 Host가 connection permission, security policy, user authorization 등을 관리하는 역할을 둡니다. 그리고 Tool 문서에서도 tool invocation을 거부할 수 있는 인간 통제의 중요성을 명시합니다. 

---

# 8. 그래서 지금 배우는 Validation / Authorization과 정확히 연결된다

예를 들어 MCP Server가 이런 요청을 받았다고 합시다.

```text
Tool
read_file

Arguments
{
    "path": "../../secret.txt"
}
```

MCP라고 해서 이 요청이 자동으로 안전해지는 게 아닙니다.

안전한 구조는 여전히:

```text
LLM
↓
Tool Proposal

read_file("../../secret.txt")

↓
MCP Client
↓
MCP Server
↓
Schema Validation
↓
Path Validation
↓
Authorization
↓
Runtime Enforcement
↓
Filesystem
```

이어야 합니다.

즉 네가 지금까지 공부한

```text
Validation
Authorization
Runtime Enforcement
Sandbox
Trace
```

는 MCP를 배우기 전에 했던 별개의 공부가 아니라, **MCP Tool을 안전하게 운영하는 데 그대로 적용되는 기반 개념**입니다.

MCP는 연결 방법을 표준화하지,

```text
MCP = Sandbox
MCP = Permission System
MCP = 자동으로 안전한 Tool
```

을 의미하지 않습니다.

초기 MCP 명세부터 프로토콜 자체가 모든 보안 원칙을 강제할 수 없으며 구현자가 consent, authorization, access control 등을 구축해야 한다고 명시해 왔습니다. 

---

## 한 문장으로 정리

지금 단계에서는 이렇게 기억하면 됩니다.

> **MCP는 LLM/Agent와 외부 데이터·도구를 연결하기 위한 “공통 통신 규칙”이고, MCP Server는 그 규칙을 따라 실제 Tool/Resource/Prompt를 제공하는 프로그램이다.**

그리고 보안 관점에서는:

```text
LLM의 판단
        ↓
    MCP Client
        ↓
   MCP Protocol
        ↓
 ┌───────────────┐
 │  MCP Server   │
 │               │
 │ Validation    │
 │ Authorization │
 │ Policy        │
 │ Runtime       │
 └───────┬───────┘
         ↓
Filesystem / API / DB / Network
```

이 그림을 머릿속에 잡는 게 가장 중요합니다.

[MCP 공식 Architecture 문서](https://modelcontextprotocol.io/specification/2025-06-18/architecture?utm_source=chatgpt.com)에서 다음으로 **Host / Client / Server가 실제 요청 하나를 어떻게 주고받는지**를 보면 이해가 가장 빨라집니다.


