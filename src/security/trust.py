# 모듈이름: security.trust
# 역할: 출처(provenance) -> 신뢰 등급(trust label) 단일 대응표
# 호출 주체: security.policy, security.provenance, experiment_support
#
# 기능 설명:
#     "이 입력을 얼마나 믿을 것인가"를 한 곳에서 정한다. allow/deny 정책과
#     분리해 유지하는 이유는, 신뢰 등급은 사실 판단이고 허용 여부는 정책 판단
#     이기 때문이다. 둘을 섞으면 정책을 바꿀 때 신뢰 모델까지 흔들린다.
#
#     repository_content, tool_observation, external_content는 모두 간접
#     지시를 포함할 수 있다. 사람이 직접 친 요청(USER_TASK)과 시스템 설정
#     (SYSTEM)만 그보다 높은 등급을 받는다.

from __future__ import annotations

from .types import ProvenanceKind, TrustLabel

DEFAULT_TRUST_BY_PROVENANCE = {
    ProvenanceKind.SYSTEM: TrustLabel.TRUSTED,
    ProvenanceKind.USER_TASK: TrustLabel.USER_CONTROLLED,
    ProvenanceKind.REPOSITORY_CONTENT: TrustLabel.UNTRUSTED,
    ProvenanceKind.TOOL_OBSERVATION: TrustLabel.UNTRUSTED,
    ProvenanceKind.EXTERNAL_CONTENT: TrustLabel.UNTRUSTED,
}


# 함수이름: label_trust
# 인자:
#     provenance_kind (ProvenanceKind): 이 입력이 어디서 왔는가
# 반환값:
#     TrustLabel: TRUSTED / USER_CONTROLLED / UNTRUSTED 중 하나
#     KeyError: 대응표에 없는 종류가 들어올 때 발생
# 기능 설명:
#     출처 종류를 신뢰 등급으로 바꾼다. 이 변환이 정책 전체의 출발점이다.
#
#     trust를 각자 계산하면 어떤 모듈은 파일 내용을 신뢰하고 어떤 모듈은
#     신뢰하지 않는 상태가 생긴다. 신뢰 등급은 단일 기준이어야 한다.
#
#     새 출처 종류를 추가하면서 등급을 정하지 않으면 조용히 통과하는 것이
#     아니라 즉시 터진다. 기본값을 두지 않는 것이 fail-closed다.
def label_trust(provenance_kind: ProvenanceKind) -> TrustLabel:
    return DEFAULT_TRUST_BY_PROVENANCE[provenance_kind]
