# 모듈이름: security.types
# 역할: 제안·정책·인가·승인·결과 사이의 명시적 인터페이스 타입
# 호출 주체: security 전체, runtime, agent, experiment_support, tests
#
# 기능 설명:
#     각 보안 단계가 주고받는 자료형을 한 곳에 모았다.
#
#     dict를 넘기면 어느 단계에서 어떤 키가 추가·삭제됐는지 추적할 수 없다.
#     특히 frozen dataclass를 쓰면 판정 도중에 값이 바뀌지 않음을 언어 수준에서
#     보장할 수 있다. 검사한 요청과 실행한 요청이 같다는 것이 이 랩의 전제다.
#
#     판정 결과를 문자열로 두면 오타가 조용히 다른 의미가 된다. 'aloow'는
#     거부도 허용도 아닌 값이 되어 조건문을 빠져나간다.

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from hashlib import sha256
from typing import Any


# 클래스이름: ProvenanceKind
# 필드:
#     USER_TASK: 사람이 직접 입력한 요청
#     REPOSITORY_CONTENT: 파일·저장소에서 읽은 내용
#     TOOL_OBSERVATION: 도구 실행 결과
#     EXTERNAL_CONTENT: 웹 등 외부에서 온 내용
#     SYSTEM: 시스템 설정
# 기능 설명:
#     입력이 어디서 왔는지를 나타낸다. 신뢰 등급은 여기서 직접 정하지 않고
#     security.trust.label_trust()가 변환한다.
#
#     출처는 사실이고 신뢰는 정책이다. 정책이 바뀌어도 사실 기록은 그대로여야
#     과거 trace를 새 정책으로 다시 평가할 수 있다.
class ProvenanceKind(str, Enum):
    USER_TASK = "user_task"
    REPOSITORY_CONTENT = "repository_content"
    TOOL_OBSERVATION = "tool_observation"
    EXTERNAL_CONTENT = "external_content"
    SYSTEM = "system"


# 클래스이름: TrustLabel
# 필드:
#     TRUSTED: 시스템 설정
#     USER_CONTROLLED: 사람이 직접 입력한 요청
#     UNTRUSTED: 파일·도구 출력·외부 콘텐츠
# 기능 설명:
#     신뢰 등급이다. UNTRUSTED는 승인 단계보다 먼저 거부된다.
#
#     사용자도 실수하거나 속을 수 있다. 사용자 요청은 '의도의 출처'이지
#     '무조건 옳은 명령'이 아니다.
class TrustLabel(str, Enum):
    TRUSTED = "trusted"
    USER_CONTROLLED = "user_controlled"
    UNTRUSTED = "untrusted"


# 클래스이름: Capability
# 필드:
#     CALCULATOR_EXECUTE / CLOCK_READ / FILESYSTEM_READ / FILESYSTEM_WRITE /
#     FILESYSTEM_LIST / COMMAND_READ / UNKNOWN
# 기능 설명:
#     도구가 아니라 '능력' 단위의 권한이다.
#
#     매핑되지 않은 도구는 조용히 허용되는 것이 아니라 UNKNOWN이 되고,
#     PolicyEngine이 CAPABILITY_NOT_ALLOWLISTED로 거부한다. 기본값이 거부다.
class Capability(str, Enum):
    CALCULATOR_EXECUTE = "calculator.execute"
    CLOCK_READ = "clock.read"
    FILESYSTEM_READ = "filesystem.read"
    FILESYSTEM_WRITE = "filesystem.write"
    FILESYSTEM_LIST = "filesystem.list"
    COMMAND_READ = "command.read"
    UNKNOWN = "unknown"


# 클래스이름: Decision
# 필드:
#     ALLOW: 즉시 실행 가능
#     DENY: 실행 불가
#     APPROVAL_REQUIRED: 자격은 있으나 사람의 명시적 동의가 필요
# 기능 설명:
#     PolicyEngine의 판정 결과다.
#
#     허용/거부 두 가지만 두면 '위험하지만 필요한 작업'을 표현할 수 없다.
#     그런 작업은 전부 허용되거나 전부 막히게 되고, 결국 정책이 느슨해진다.
class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    APPROVAL_REQUIRED = "approval_required"


# 클래스이름: AuthorizationOutcome
# 필드:
#     ALLOW: 이 actor가 이 리소스에 접근할 자격이 있다
#     DENY: 자격이 없다
# 기능 설명:
#     AuthorizationEngine의 판정 결과다.
#
#     승인 필요 여부는 정책 판단이고 여기는 자격 판단이다. 자격이 있으면서
#     승인이 필요한 경우는 ALLOW + required_approver로 표현한다.
class AuthorizationOutcome(str, Enum):

    ALLOW = "allow"
    DENY = "deny"


# 클래스이름: ApprovalStatus
# 필드:
#     NOT_REQUIRED: 승인이 필요 없는 요청
#     INVALID: 등록되지 않은 승인 ID
#     PENDING: 발급됐으나 아직 승인 전
#     APPROVED: 승인됨. 아직 소비 전
#     REJECTED: 거부됨
#     EXPIRED: TTL 초과
#     CONSUMED: 이미 사용됨. 재사용 불가
# 기능 설명:
#     승인 레코드의 상태다.
#
#     '승인을 제출하지 않음'과 '잘못된 것을 제출함'은 다른 사건이다. 하나로
#     묶으면 정상 읽기 요청이 오류처럼 보인다.
class ApprovalStatus(str, Enum):
    NOT_REQUIRED = "not_required"
    INVALID = "invalid"
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    CONSUMED = "consumed"


# 클래스이름: ToolSchemaDecision
# 필드:
#     allowed (bool): schema gate 통과 여부
#     reason (str): 안정적인 규칙 식별자
#     profile (str): 판정에 사용한 도구 노출 프로필 이름
#     tool_name (str): 대상 도구
#     declared_capability (str | None): catalog가 선언한 capability
#     schema_digest (str): 이 프로필의 schema 해시
#     detail (str | None): 사람이 읽는 세부 사유. 권한 판단에 쓰이지 않는다
# 메서드:
#     trace_fields(): trace에 기록할 필드 묶음
# 기능 설명:
#     MCP 도구 노출과 inputSchema 검사 결과다.
#
#     "어떤 도구 정의로 판정했는가"가 기록에 남아야 나중에 catalog가 바뀌었을 때
#     과거 결과와 비교할 수 있다.
@dataclass(frozen=True)
class ToolSchemaDecision:

    allowed: bool
    reason: str
    profile: str
    tool_name: str
    declared_capability: str | None
    schema_digest: str
    # [A-06] reason은 안정적인 규칙 ID다. 운영자가 읽을 세부 사유는 여기에 담는다.
    detail: str | None = None

    # 함수이름: ToolSchemaDecision.trace_fields
    # 인자: 없음
    # 반환값:
    #     dict: trace 이벤트에 넣을 필드 묶음
    # 기능 설명:
    #     판정 결과를 기록용 필드로 펼친다. allowed(bool)를 'allow'/'deny' 문자열로
    #     바꾸는데, 이는 trace를 사람이 읽고 grep하기 쉽게 하기 위해서다.
    def trace_fields(self) -> dict[str, Any]:
        return {
            "tool_schema_decision": "allow" if self.allowed else "deny",
            "tool_schema_reason": self.reason,
            "tool_schema_detail": self.detail,
            "tool_profile": self.profile,
            "declared_capability": self.declared_capability,
            "tool_schema_digest": self.schema_digest,
        }


# 클래스이름: ToolIntent
# 필드:
#     run_id / call_id (str): 실행·호출 식별자
#     actor (str): 인증된 주체. LLM 인자에서 오지 않는다
#     tool_name (str) / arguments (Mapping): 제안된 도구와 인자
#     provenance (Any): 이 제안이 어떤 입력 문맥에서 나왔는가
#     capability (Capability) / action (str) / resource (str | None):
#         서버가 계산한 권한·동작·대상
#     agent_step (int | None): 몇 번째 turn인가. 감사 메타데이터
#     fixture_id (str | None): 실험 케이스 라벨
# 메서드:
#     fingerprint(): 이 행동을 식별하는 해시
# 기능 설명:
#     제안된 작업이며 실행 권한 자체는 아니다. 모든 보안 단계가 같은 이 객체를
#     본다.
#
#     Policy, Authorization, Approval이 각자 다른 형태의 입력을 받으면 "같은
#     요청을 판정했는가"를 보장할 수 없다. 정규화된 단일 요청을 돌려야 판정
#     사이에 값이 바뀌지 않는다.
#
#     판정 도중에 인자가 바뀌면 검사한 요청과 실행한 요청이 달라진다.
@dataclass(frozen=True)
class ToolIntent:
    run_id: str
    call_id: str
    actor: str
    tool_name: str
    arguments: Mapping[str, Any]
    provenance: Any
    capability: Capability
    action: str
    resource: str | None
    # Agent는 이 값을 알지만, Runtime 직접 테스트는 값을 모를 수 있다.
    # 감사 메타데이터일 뿐 승인 fingerprint에는 의도적으로 넣지 않는다.
    agent_step: int | None = None
    # Day 7 fixture runner가 부여하는 실험 케이스 라벨이다. 권한이나
    # fingerprint의 입력은 아니며, trace/evaluator 집계에만 사용한다.
    fixture_id: str | None = None

    # 함수이름: ToolIntent.fingerprint
    # 인자: 없음
    # 반환값:
    #     str: tool_name·arguments·actor·capability·action·resource의 SHA-256 해시
    # 기능 설명:
    #     승인을 이 행동에 결속시키는 지문을 만든다.
    #
    #     넣는 것: 실제 효과를 결정하는 값(도구, 인자, 주체, 권한, 동작, 대상)
    #     빼는 것: agent_step, fixture_id — 감사 메타데이터일 뿐 효과에 영향을
    #              주지 않는다. 넣으면 같은 행동인데 지문이 달라져 승인이 무의미하게
    #              무효화된다.
    #
    #     "쓰기를 승인했다"가 아니라 "이 내용을 이 경로에 쓰는 것을 승인했다"가
    #     되려면 인자가 지문에 들어가야 한다. 인자를 하나만 바꿔도 그 승인은 쓸 수
    #     없다.
    def fingerprint(self) -> str:
        material = {"tool_name": self.tool_name, "arguments": self.arguments, "actor": self.actor, "capability": self.capability.value, "action": self.action, "resource": self.resource}
        return sha256(json.dumps(material, sort_keys=True, default=str).encode()).hexdigest()


# 클래스이름: PolicyDecision
# 필드:
#     outcome (Decision): ALLOW / DENY / APPROVAL_REQUIRED
#     reason (str): 안정적인 규칙 식별자
#     capability / action / resource: 판정 대상
#     trust (TrustLabel): 이 요청의 신뢰 등급
#     rule_id (str | None): 규칙 식별자. 현재는 reason과 같은 값
# 메서드:
#     trace_fields(): trace 기록용 필드 묶음
# 기능 설명:
#     PolicyEngine만 이 객체를 만든다. LLM, 관측값, fixture는 만들 수 없다.
#
#     지금은 별도 규칙 레지스트리가 없다. 나중에 도입해도 기존 reason 인터페이스는
#     유지한다. 과거 실험 로그의 reason 문자열이 계속 유효해야 하기 때문이다.
@dataclass(frozen=True)
class PolicyDecision:
    outcome: Decision
    reason: str
    capability: Capability
    action: str
    resource: str | None
    trust: TrustLabel
    # 현재는 사람이 읽는 reason을 안정적인 규칙 식별자로 재사용한다.
    # 이후 별도 rule registry를 도입해도 기존 reason 인터페이스는 유지한다.
    rule_id: str | None = None

    # 함수이름: PolicyDecision.trace_fields
    # 인자: 없음
    # 반환값:
    #     dict: policy_decision · reason · rule_id · capability · action ·
    #         resource · trust
    # 기능 설명:
    #     판정을 기록용 필드로 펼친다. Enum은 .value로 풀어 JSON에 그대로 들어가게
    #     한다.
    def trace_fields(self) -> dict[str, Any]:
        return {"policy_decision": self.outcome.value, "reason": self.reason, "rule_id": self.rule_id, "capability": self.capability.value, "action": self.action, "resource": self.resource, "trust": self.trust.value}


# 클래스이름: ApprovalState
# 필드:
#     approval_id (str | None): 레코드 ID
#     status (ApprovalStatus): 현재 상태
#     intent_fingerprint (str | None): 이 승인이 묶인 행동의 지문
#     requested_at / expires_at (str | None): 발급 시각과 만료 시각
#     approver (str | None): 실제로 승인한 주체
#     requested_actor (str | None): 요청한 주체
#     required_approver (str | None): 승인할 수 있는 유일한 주체
#     resource / action (str | None): 무엇에 대한 승인인가
# 기능 설명:
#     승인 레코드 하나의 상태다.
#
#     누가 요청했고 누가 승인했는지가 같은 사람이면 직무 분리가 깨진 것이다.
#     두 값을 따로 남겨야 감사에서 그 사실이 드러난다.
@dataclass(frozen=True)
class ApprovalState:
    approval_id: str | None
    status: ApprovalStatus
    intent_fingerprint: str | None = None
    requested_at: str | None = None
    expires_at: str | None = None
    approver: str | None = None
    requested_actor: str | None = None
    required_approver: str | None = None
    resource: str | None = None
    action: str | None = None


# 클래스이름: AuthorizationDecision
# 필드:
#     outcome (AuthorizationOutcome): ALLOW / DENY
#     reason (str): 안정적인 규칙 식별자
#     actor / action / resource: 판정 대상
#     required_approver (str | None): 승인이 필요하면 그 승인자
# 메서드:
#     trace_fields(): trace 기록용 필드 묶음
# 기능 설명:
#     Policy 결과와 분리된 actor-resource-action 인가 인터페이스다.
#
#     승인으로 되살릴 수 있으면 거부가 아니다.
@dataclass(frozen=True)
class AuthorizationDecision:

    outcome: AuthorizationOutcome
    reason: str
    actor: str
    action: str
    resource: str | None
    required_approver: str | None = None

    # 함수이름: AuthorizationDecision.trace_fields
    # 인자: 없음
    # 반환값:
    #     dict: authorization_decision · authorization_reason · required_approver
    # 기능 설명:
    #     인가 판정을 기록용 필드로 펼친다.
    def trace_fields(self) -> dict[str, Any]:
        return {
            "authorization_decision": self.outcome.value,
            "authorization_reason": self.reason,
            "required_approver": self.required_approver,
        }


# 클래스이름: RuntimeResult
# 필드:
#     ok (bool): 성공 여부
#     status (str): 결과 상태 (success / denied / approval_required 등)
#     end_stage (str): 어느 단계에서 끝났는가
#     tool_name / call_id (str): 대상 도구와 호출 식별자
#     data (Any): 성공 시 도구 반환값
#     error_code / error_message (str | None): 실패 시 코드와 메시지
#     security (dict): 판정 문맥(schema·policy·authz·approval 필드)
# 메서드:
#     success() / failure(): 생성 헬퍼
#     to_dict(): 호출자에게 돌려줄 dict
# 기능 설명:
#     Runtime의 최종 결과다.
#
#     "왜 실패했는가"보다 "어디까지 갔는가"가 보안 분석에서 더 중요하다.
#     schema에서 끝났는지 approval에서 끝났는지에 따라 공격이 어느 관문까지
#     도달했는지가 드러난다.
#
#     이 필드는 trace와 meta에만 들어가고 to_observation()에서 걸러진다.
#     모델에게 판정 내부를 보여 주지 않기 위해서다.
@dataclass
class RuntimeResult:
    ok: bool
    status: str
    end_stage: str
    tool_name: str
    call_id: str
    data: Any = None
    error_code: str | None = None
    error_message: str | None = None
    security: dict[str, Any] = field(default_factory=dict)

    # 함수이름: RuntimeResult.success
    # 인자:
    #     tool_name (str): 대상 도구
    #     call_id (str): 호출 식별자
    #     data (Any): 도구 반환값
    #     security (dict | None): 판정 문맥. 기본값 None
    # 반환값:
    #     RuntimeResult: ok=True, status='success', end_stage='runtime'인 결과
    # 기능 설명:
    #     성공 결과를 만든다. end_stage가 항상 'runtime'인 것은, 성공은 마지막
    #     단계까지 갔다는 뜻이기 때문이다.
    @classmethod
    def success(cls, tool_name: str, call_id: str, data: Any, *, security: dict[str, Any] | None = None) -> RuntimeResult:
        return cls(True, "success", "runtime", tool_name, call_id, data=data, security=security or {})

    # 함수이름: RuntimeResult.failure
    # 인자:
    #     status (str): 결과 상태
    #     end_stage (str): 어느 단계에서 끝났는가
    #     tool_name / call_id (str): 대상 도구와 호출 식별자
    #     error_code (str): 안정적인 오류 코드
    #     error_message (str): 사람이 읽는 메시지
    #     security (dict | None): 판정 문맥. 기본값 None
    # 반환값:
    #     RuntimeResult: ok=False인 결과
    # 기능 설명:
    #     실패·거부 결과를 만든다.
    #
    #     예외를 던지지 않고 결과 객체로 돌려주는 이유는, 거부 역시 기록하고 평가
    #     해야 할 사건이기 때문이다.
    @classmethod
    def failure(cls, status: str, end_stage: str, tool_name: str, call_id: str, error_code: str, error_message: str, *, security: dict[str, Any] | None = None) -> RuntimeResult:
        return cls(False, status, end_stage, tool_name, call_id, error_code=error_code, error_message=error_message, security=security or {})

    # 함수이름: RuntimeResult.to_dict
    # 인자: 없음
    # 반환값:
    #     dict: ok · status · end_stage · data · error · meta
    # 기능 설명:
    #     호출자에게 돌려줄 형태로 바꾼다. security 필드는 meta 안으로 합쳐진다.
    #
    #     성공과 실패에서 키 구성이 같아야 호출자가 분기 없이 읽을 수 있다.
    def to_dict(self) -> dict[str, Any]:
        meta = {"tool_name": self.tool_name, "call_id": self.call_id, **self.security}
        return {"ok": self.ok, "status": self.status, "end_stage": self.end_stage, "data": self.data, "error": None if self.ok else {"code": self.error_code, "message": self.error_message}, "meta": meta}


# 클래스이름: ObservationEnvelope
# 필드:
#     observation_id (str): 이 관측 결과의 식별자
#     parent_call_id (str | None): 이 결과를 만든 도구 호출
#     source_kind (ProvenanceKind) / source (str): 출처 종류와 식별자
#     trust (TrustLabel): source_kind에서 계산한 신뢰 등급
#     result_digest (str): content의 SHA-256
#     content (str): 다음 turn에 data로 전달할 실제 결과
# 기능 설명:
#     도구 출력의 내용과, 그 출력이 생긴 신뢰 경계를 함께 보존한다.
#
#     도구 결과를 문자열로만 넘기면 다음 turn에서 그것이 어디서 왔는지 알 수
#     없게 된다. 출처를 잃는 순간 파일 내용이 사용자 지시와 구별되지 않고,
#     그것이 곧 간접 프롬프트 주입의 성립 조건이다.
#
#     source·trust·observation_id는 Runtime이 소유하는 메타데이터다. 모델
#     출력으로 덮어쓸 수 없다.
@dataclass(frozen=True)
class ObservationEnvelope:

    observation_id: str
    parent_call_id: str | None
    source_kind: ProvenanceKind
    source: str
    trust: TrustLabel
    result_digest: str
    content: str  # LLM에는 data로만 전달한다.
