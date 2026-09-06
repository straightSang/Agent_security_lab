# 모듈이름: security.provenance
# 역할: 출처 기록 생성과 관측 봉투(ObservationEnvelope) 생성
# 호출 주체: runtime, agent, tests
#
# 기능 설명:
#     "이 입력이 어디서 왔는가"를 만들고 다음 turn으로 전파한다.
#
#     관측값의 content는 모델에게 data로 전달할 수 있지만, source·trust·
#     observation ID는 이 모듈과 Runtime이 만든 메타데이터다. 모델 출력으로
#     덮어쓰지 않는다.
#
#     Provenance(kind=..., source=...)를 호출자가 직접 만들면 어느 kind를 줄지
#     호출자가 정하게 된다. 용도별 함수로 좁혀 두면 잘못된 등급을 붙이기 어렵다.

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any
from uuid import uuid4

from .trust import label_trust
from .types import ObservationEnvelope, ProvenanceKind


# 클래스이름: Provenance
# 필드:
#     kind (ProvenanceKind): 출처 종류
#     source (str): 출처 식별자(파일 경로, 도구 이름, URL 등)
#     parent_event_id (str | None): 이 입력을 만든 원본 call ID.
#         필드명은 이전 trace와의 호환을 위해 유지한다
#     received_at (str): 받은 시각 (UTC ISO-8601)
#     attributes (dict): 복수 관측 등 부가 정보
# 메서드:
#     to_dict(): trace 기록용 dict
# 기능 설명:
#     ToolIntent가 어떤 입력 문맥에서 나왔는지를 기록한다.
#
#     "무엇이 쓰여 있는가"(content)와 "그것이 어디서 왔는가"(provenance)는 다른
#     정보다. 둘을 합치면 파일에 적힌 지시가 사용자 지시와 구별되지 않는다.
#
#     출처는 사실 기록이다. 나중에 고칠 수 있으면 증거가 아니다.
@dataclass(frozen=True)
class Provenance:
    kind: ProvenanceKind
    source: str
    # 기존 trace와의 호환을 위해 필드명은 유지한다. Day 6에서 담기는 값은
    # Runtime event ID가 아니라 원본 tool call ID다.
    parent_event_id: str | None = None
    received_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    attributes: dict[str, Any] = field(default_factory=dict)

    # 함수이름: Provenance.to_dict
    # 인자: 없음
    # 반환값:
    #     dict: kind · source · parent_event_id · received_at · attributes
    # 기능 설명:
    #     trace에 그대로 들어갈 수 있는 형태로 바꾼다. Enum은 .value로 푼다.
    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "source": self.source,
            "parent_event_id": self.parent_event_id,
            "received_at": self.received_at,
            "attributes": self.attributes,
        }


# 함수이름: direct_user_provenance
# 인자:
#     source (str): 출처 식별자. 기본값 'interactive-user'
# 반환값:
#     Provenance: kind=USER_TASK인 출처 기록
# 기능 설명:
#     사람이 직접 입력한 요청임을 나타낸다. trust는 USER_CONTROLLED가 된다.
#
#     [주의]
#     이 함수를 모델 응답에 붙이면 안 된다. 모델 출력에 사용자 등급을 주는
#     순간 간접 주입 방어가 무너진다. 호출자가 '정말 사람이 친 요청인가'를
#     책임진다.
def direct_user_provenance(source: str = "interactive-user") -> Provenance:
    return Provenance(ProvenanceKind.USER_TASK, source)


# 함수이름: repository_provenance
# 인자:
#     path (str): 읽은 파일 경로
#     parent_event_id (str | None): 이 읽기를 수행한 call ID. 기본값 None
# 반환값:
#     Provenance: kind=REPOSITORY_CONTENT인 출처 기록
# 기능 설명:
#     파일·저장소에서 읽은 내용임을 나타낸다. trust는 UNTRUSTED가 된다.
#
#     파일은 누가 언제 무엇을 넣었는지 알 수 없다. 저장소 안에 있다는 사실이
#     신뢰의 근거가 되지 않는다.
def repository_provenance(path: str, *, parent_event_id: str | None = None) -> Provenance:
    return Provenance(ProvenanceKind.REPOSITORY_CONTENT, path, parent_event_id)


# 함수이름: observation_provenance
# 인자:
#     tool_name (str): 결과를 만든 도구 이름
#     parent_event_id (str | None): 원본 call ID. 기본값 None
# 반환값:
#     Provenance: kind=TOOL_OBSERVATION인 출처 기록
# 기능 설명:
#     도구 실행 결과에서 유래한 입력임을 나타낸다. trust는 UNTRUSTED가 된다.
#
#     read_file의 결과는 파일 내용이고, 그 파일에는 무엇이든 쓰여 있을 수 있다.
#     도구가 우리 코드라는 사실과 그 도구가 돌려준 내용이 안전하다는 것은 별개다.
def observation_provenance(tool_name: str, *, parent_event_id: str | None = None) -> Provenance:
    return Provenance(ProvenanceKind.TOOL_OBSERVATION, tool_name, parent_event_id)


# 함수이름: external_provenance
# 인자:
#     url_or_service (str): 외부 출처 식별자
#     parent_event_id (str | None): 원본 call ID. 기본값 None
# 반환값:
#     Provenance: kind=EXTERNAL_CONTENT인 출처 기록
# 기능 설명:
#     웹 등 외부에서 온 내용임을 나타낸다. trust는 UNTRUSTED가 된다.
def external_provenance(url_or_service: str, *, parent_event_id: str | None = None) -> Provenance:
    return Provenance(ProvenanceKind.EXTERNAL_CONTENT, url_or_service, parent_event_id)


_OBSERVATION_SOURCE_KINDS = {
    ProvenanceKind.REPOSITORY_CONTENT,
    ProvenanceKind.TOOL_OBSERVATION,
    ProvenanceKind.EXTERNAL_CONTENT,
}


# 함수이름: make_observation
# 인자:
#     source_kind (ProvenanceKind): 관측 출처 종류. 세 가지만 허용된다
#     source (str): 출처 식별자
#     content (str): 도구가 돌려준 실제 내용
#     parent_call_id (str): 이 결과를 만든 도구 호출
# 반환값:
#     ObservationEnvelope: 변경 불가능한 관측 기록
#     ValueError: 허용되지 않은 source_kind일 때 발생
# 기능 설명:
#     성공한 도구 결과를 출처·신뢰와 함께 봉투에 담는다.
#
#     관측은 '도구가 돌려준 것'이다. 사용자 요청이나 시스템 설정을 관측으로
#     포장할 수 있으면, 도구 결과에 사용자 등급을 붙이는 경로가 생긴다.
#
#     source_kind에서 label_trust()로 계산한다. 호출자가 신뢰 등급을 직접
#     지정할 수 있으면 등급 자체가 의미를 잃는다.
def make_observation(
    *,
    source_kind: ProvenanceKind,
    source: str,
    content: str,
    parent_call_id: str,
) -> ObservationEnvelope:
    if source_kind not in _OBSERVATION_SOURCE_KINDS:
        raise ValueError(f"unsupported observation source kind: {source_kind}")

    return ObservationEnvelope(
        observation_id=f"obs_{uuid4().hex}",
        parent_call_id=parent_call_id,
        source_kind=source_kind,
        source=source,
        trust=label_trust(source_kind),
        result_digest=f"sha256:{sha256(content.encode('utf-8')).hexdigest()}",
        content=content,
    )


# 함수이름: provenance_for_observations
# 인자:
#     envelopes (Sequence[ObservationEnvelope]): 현재 문맥에 남아 있는 관측들
# 반환값:
#     Provenance: 다음 ToolIntent에 붙일 출처 기록
#     ValueError: 봉투가 하나도 없을 때 발생
# 기능 설명:
#     문맥에 남은 관측 ID들을 다음 제안의 출처로 전파한다.
#
#     하나면 원래 source kind를 유지한다. 여럿이면 kind=TOOL_OBSERVATION,
#     source='multiple_observations'로 묶고 모든 원본 ID·출처·call ID를
#     attributes에 남긴다.
#
#     세 source kind가 모두 UNTRUSTED이므로, 관측이 하나라도 문맥에 남아 있으면
#     다음 ToolIntent는 UNTRUSTED다. 이것이 간접 주입의 두 번째 홉을 막는 지점
#     이다. 전파가 끊기면 "파일을 읽은 뒤의 제안"이 "사용자가 직접 한 제안"처럼
#     보이게 된다.
def provenance_for_observations(
    envelopes: Sequence[ObservationEnvelope],
) -> Provenance:
    if not envelopes:
        raise ValueError("at least one observation envelope is required")

    if len(envelopes) == 1:
        envelope = envelopes[0]
        kind = envelope.source_kind
        source = envelope.source
        parent_call_id = envelope.parent_call_id
    else:
        kind = ProvenanceKind.TOOL_OBSERVATION
        source = "multiple_observations"
        parent_call_id = envelopes[-1].parent_call_id

    return Provenance(
        kind=kind,
        source=source,
        parent_event_id=parent_call_id,
        attributes={
            "observation_ids": [envelope.observation_id for envelope in envelopes],
            "parent_call_ids": [envelope.parent_call_id for envelope in envelopes],
            "sources": [envelope.source for envelope in envelopes],
            "source_kinds": [envelope.source_kind.value for envelope in envelopes],
        },
    )
