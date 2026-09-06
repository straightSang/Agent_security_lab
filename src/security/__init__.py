# 모듈이름: security
# 역할: 보안 도메인 타입의 공개 표면
# 호출 주체: runtime, agent, experiment_support, tests
#
# 기능 설명:
#     자주 쓰는 계약 타입만 재수출한다. 판정 엔진(PolicyEngine,
#     AuthorizationEngine, ApprovalStore)은 일부러 넣지 않았다.
#
#     `from security import PolicyEngine` 처럼 짧게 쓸 수 있으면 어느 모듈이
#     어떤 판정기를 쓰는지가 import 목록에서 흐려진다. 판정기는 항상 원래
#     위치에서 가져오게 해서 의존 관계가 눈에 보이도록 한다.

from .types import (
    ApprovalState,
    AuthorizationDecision,
    AuthorizationOutcome,
    Decision,
    ObservationEnvelope,
    PolicyDecision,
    RuntimeResult,
    ToolIntent,
    ToolSchemaDecision,
)

__all__ = [
    "ApprovalState",
    "AuthorizationDecision",
    "AuthorizationOutcome",
    "Decision",
    "ObservationEnvelope",
    "PolicyDecision",
    "RuntimeResult",
    "ToolSchemaDecision",
    "ToolIntent",
]
