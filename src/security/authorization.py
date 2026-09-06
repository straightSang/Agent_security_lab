# 모듈이름: security.authorization
# 역할: actor-resource-action 관계 판정. 소유권과 멤버십만 본다
# 호출 주체: runtime.Runtime.execute_tool()의 4단계
#
# 기능 설명:
#     Policy가 "규칙상 허용되는가"에 답한다면, 이 모듈은 "이 사람이 해도 되는가"
#     에 답한다. 두 질문을 섞으면 둘 다 약해진다.
#
#     Runtime이 넘겨준 검증·정규화된 ToolIntent만 받는다. LLM의 도구 인자에서
#     actor 신원을 읽지 않는다.
#
#     소유권을 경로 문자열에서 유도한다(data/{actor}/...). 실제 시스템에서는
#     리소스 DB에 소유권을 영구 저장해야 파일을 옮겨도 소유자가 유지된다.

from __future__ import annotations

import re
from dataclasses import dataclass

# [A-07] 패키지 내부는 상대 import로 통일한다. 절대 import는 src가 sys.path에
# 있을 때만 동작하므로 실행 위치에 따라 깨진다.
from .types import (
    AuthorizationDecision,
    AuthorizationOutcome,
    ToolIntent,
)

# 현재는 매 toolcall 마다 ResourceMetadata(owner="user-0") 생성
# 실제 시스템에서는 Resource DB에 ownership을 영구 저장한다. -> 파일의 폴더 변경마다 owner 가 변경될 위험X
SHARED_MEMBERS = frozenset({"user-001", "user-003"})
SHARED_APPROVER = "reviewer-001"
# actor는 LLM argument가 아니라 인증/session/test harness에서만 들어온다.
# Lab에서는 고정 목록 대신 유효한 actor ID 모양을 허용하여
# data/{ACTOR_NAME}/** 규칙을 일반화한다.
ACTOR_ID_PATTERN = re.compile(r"^[a-z][a-z0-9-]{2,63}$")


# 클래스이름: ResourceMetadata
# 필드:
#     kind (str): 'public_read' / 'private' / 'shared' / 'unregistered'
#     owner (str | None): private 리소스의 소유자 actor ID
#     members (frozenset[str]): shared 리소스에 접근 가능한 actor 집합
# 기능 설명:
#     경로 하나에 대한 소유권 정보다.
#
#     [주의]
#     이것은 실험용 fixture 레지스트리의 결과이지 운영 데이터베이스 모델이
#     아니다. 실제 시스템에서는 리소스 DB가 소유권을 영구 저장해야 한다.
#     지금은 매 호출마다 경로 문자열에서 유도하므로, 파일을 다른 폴더로 옮기면
#     소유자가 바뀐다는 한계가 있다.
@dataclass(frozen=True)
class ResourceMetadata:

    kind: str
    owner: str | None = None
    members: frozenset[str] = frozenset()


# 함수이름: resolve_resource
# 인자:
#     resource (str | None): sandbox 기준 상대 경로. 경로 없는 도구는 None
# 반환값:
#     ResourceMetadata: 해당 경로의 소유권 정보
# 기능 설명:
#     경로를 소유권 종류로 분류한다.
#
#         data/shared 및 그 하위     -> shared    (멤버만, 쓰기는 reviewer 승인)
#         data/{actor-id}/파일       -> private   (소유자만)
#         '', '.', 'data', 'sharedbook.txt' -> public_read (읽기·목록만)
#         그 외                      -> unregistered (전부 거부)
#
#     data/ 아래 두 번째 조각이 소유자 이름이 된다. 형식을 검사하지 않으면
#     'data/../x' 같은 값이 소유자 이름으로 들어올 수 있다. 경로 정규화는 이미
#     Runtime이 했지만, 소유권 판정도 자기 입력을 스스로 검사해야 한다.
#
#     주인이 확인되지 않은 리소스는 접근을 거부한다. fail-closed다.
def resolve_resource(resource: str | None) -> ResourceMetadata:
    normalized = (resource or "").replace("\\", "/").strip("/")

    # [OBR] ``data/shared`` 디렉터리 자체도 shared로 인정한다. 이전에는 하위 파일만
    # 매칭되어 공유 폴더 목록 조회가 RESOURCE_NOT_REGISTERED로 과차단되었다.
    if normalized == "data/shared" or normalized.startswith("data/shared/"):
        return ResourceMetadata("shared", members=SHARED_MEMBERS)

    # "data/" 아래의 항목들 나누기
    if normalized.startswith("data/"):
        parts = normalized.split("/")

        # 최소한 data / actor-name / file-name 이 구조가 있어야 private 파일로 분류된다.
        # actor-name(==parts[1]), 즉 이름의 형식이 ACTOR_ID_PATTERN 에 정의된 형식에서 벗어나면 안 된다(특수문자 등등)
        if len(parts) >= 3 and ACTOR_ID_PATTERN.fullmatch(parts[1]):
            # 조건을 통과하면 해당 폴더(소유자)이름을 ResourceMetadata의 owner 이름으로 저장한다.
            return ResourceMetadata("private", owner=parts[1])

    # [OBR] ``data`` 디렉터리 자체는 목록 조회 대상이므로 public_read로 둔다.
    # 쓰기는 아래 public_read 분기에서 여전히 거부된다.
    if normalized in {"", ".", "data", "sharedbook.txt"}:
        return ResourceMetadata("public_read")

    return ResourceMetadata("unregistered")


# 클래스이름: AuthorizationEngine
# 필드: 없음. 상태를 갖지 않는다
# 메서드:
#     authorize(): 유일한 공개 메서드
#     _allow() / _deny(): 결정 생성 헬퍼
# 기능 설명:
#     "이 actor가 이 리소스에 이 동작을 해도 되는가"에 답한다.
#     "규칙상 허용되는가"는 PolicyEngine의 몫이다.
#
#     Policy가 ALLOW를 줬어도 여기서 DENY가 날 수 있다. 예를 들어 data/ 아래
#     쓰기는 Policy상 APPROVAL_REQUIRED지만, 소유자가 아니면 여기서 FORBIDDEN
#     이다. 두 계층은 서로를 대체하지 않는다.
#
#     인증·session·test harness에서만 온다. LLM의 도구 인자에서 오지 않는다.
#     모델이 자기 신원을 주장할 수 있으면 소유권 검사가 무의미해진다.
class AuthorizationEngine:

    # 함수이름: AuthorizationEngine.authorize
    # 인자:
    #     intent (ToolIntent): Runtime이 검증·정규화한 요청
    # 반환값:
    #     AuthorizationDecision: outcome(ALLOW/DENY), reason, actor, action,
    #         resource, required_approver
    # 기능 설명:
    #     actor와 리소스의 관계를 판정한다.
    #
    #         1. actor ID 형식 검사        -> UNKNOWN_ACTOR
    #         2. 승인자 전용 신원 차단     -> REVIEWER_HAS_NO_TOOL_ACCESS
    #         3. 리소스 종류별 규칙 적용
    #
    #     reviewer-001은 승인만 하는 신원이다. 승인자가 도구도 쓸 수 있으면 스스로
    #     요청하고 스스로 승인하는 경로가 열린다. 직무 분리를 코드로 강제한다.
    #
    #     "요청할 자격은 있다"와 "바로 실행해도 된다"는 다르다. 쓰기는 자격이
    #     있어도 승인이 필요하므로, 여기서 ALLOW + required_approver를 주고 Policy가
    #     APPROVAL_REQUIRED로 이어받는다.
    def authorize(self, intent: ToolIntent) -> AuthorizationDecision:

        if not ACTOR_ID_PATTERN.fullmatch(intent.actor):
            return self._deny(intent, "UNKNOWN_ACTOR")

        if intent.actor == SHARED_APPROVER:
            return self._deny(intent, "REVIEWER_HAS_NO_TOOL_ACCESS")

        metadata = resolve_resource(intent.resource)

        if metadata.kind == "public_read":

            if intent.action in {"read", "list", "pwd", "calculate"}:

                return self._allow(intent, "PUBLIC_READ_RESOURCE")

            return self._deny(intent, "PUBLIC_RESOURCE_WRITE_NOT_AUTHORIZED")


        if metadata.kind == "private":

            if metadata.owner != intent.actor:

                return self._deny(intent, "ACTOR_NOT_RESOURCE_OWNER")


            if intent.action == "write":
                # Requirement 4: the resource owner must explicitly approve
                # their own write request before it can be dispatched.
                return self._allow(intent, "RESOURCE_OWNER_SELF_APPROVAL_REQUIRED", required_approver=intent.actor)

            return self._allow(intent, "RESOURCE_OWNER")


        if metadata.kind == "shared":

            if intent.actor not in metadata.members:
                return self._deny(intent, "ACTOR_NOT_SHARED_MEMBER")

            if intent.action == "write":
                # A shared folder has no single owner.  The Lab therefore uses
                # a designated reviewer; production would use a team ACL.
                return self._allow(intent, "SHARED_WRITE_REQUIRES_REVIEWER", required_approver=SHARED_APPROVER)

            return self._allow(intent, "SHARED_MEMBER")

        return self._deny(intent, "RESOURCE_NOT_REGISTERED")

    # 함수이름: AuthorizationEngine._allow
    # 인자:
    #     intent (ToolIntent): 판정 대상
    #     reason (str): 안정적인 규칙 식별자
    #     required_approver (str | None): 승인이 필요하면 그 승인자. 기본값 None
    # 반환값:
    #     AuthorizationDecision: ALLOW 결정
    # 기능 설명:
    #     허용 결정을 같은 모양으로 만드는 헬퍼다. required_approver가 있으면
    #     "자격은 있으나 승인이 필요하다"는 뜻이다.
    @staticmethod
    def _allow(intent: ToolIntent, reason: str, *, required_approver: str | None = None) -> AuthorizationDecision:
        return AuthorizationDecision(AuthorizationOutcome.ALLOW, reason, intent.actor, intent.action, intent.resource, required_approver)

    # 함수이름: AuthorizationEngine._deny
    # 인자:
    #     intent (ToolIntent): 판정 대상
    #     reason (str): 안정적인 규칙 식별자
    # 반환값:
    #     AuthorizationDecision: DENY 결정. required_approver는 항상 None
    # 기능 설명:
    #     거부 결정을 만든다. 거부에는 승인자를 붙이지 않는다. 승인으로 되살릴 수
    #     있으면 거부가 아니기 때문이다.
    @staticmethod
    def _deny(intent: ToolIntent, reason: str) -> AuthorizationDecision:
        return AuthorizationDecision(AuthorizationOutcome.DENY, reason, intent.actor, intent.action, intent.resource)
