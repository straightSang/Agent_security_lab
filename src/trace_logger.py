# 모듈이름: trace_logger
# 역할: 사건별 필드만 기록하는 append-only JSONL trace
# 호출 주체: runtime, experiment_support, agent
#
# 기능 설명:
#     모든 보안 판정을 기록으로 남긴다. 이 랩의 원칙 하나가 "관측 가능성이 없는
#     보안 주장은 완료되지 않은 것"이므로, 이 파일은 방어만큼 중요하다.
#
#     TRACE_BASE_FIELDS는 모든 사건에 공통이고, TRACE_REQUIRED_FIELDS는 사건
#     종류별 필수 필드를 선언한다. 모든 사건에 같은 빈 필드를 넣지 않는 이유는,
#     "값이 없다"와 "이 사건에는 해당 없다"를 구별하기 위해서다.
#
#     기존 줄을 고치거나 지우지 않는다. 사후에 수정할 수 있는 로그는 증거가
#     아니다. 재현성 비교가 필요할 때도 원본은 그대로 두고 사본을 정규화한다
#     (experiment_support의 _stable_event_projection 참조).

from __future__ import annotations

import json
import uuid
import warnings
from collections.abc import Iterator, Mapping
from datetime import datetime, timezone
from enum import Enum
from hashlib import sha256
from pathlib import Path
from typing import Any

from security.provenance import Provenance
from security.types import (
    ApprovalState,
    AuthorizationDecision,
    ObservationEnvelope,
    PolicyDecision,
    RuntimeResult,
    ToolIntent,
    ToolSchemaDecision,
)

TRACE_BASE_FIELDS = ("event_id", "timestamp", "run_id", "event")

# 모든 사건에 같은 빈 필드를 넣지 않는다. 사건 종류별 필수 필드만 선언하여
# evaluator가 실제 기록 인터페이스를 검사한다.
TRACE_REQUIRED_FIELDS: dict[str, tuple[str, ...]] = {
    "seed_snapshot": ("fixture_id", "seed_manifest", "seed_digest"),
    "tool_schema_decision": (
        "call_id", "tool_schema_decision", "tool_schema_reason",
        "tool_profile", "tool_schema_digest",
    ),
    "control_plane_snapshot": (
        "fixture_id", "phase", "control_plane_digest", "control_plane_state",
    ),
    "validation": ("call_id", "tool_name", "validation_allowed"),
    "tool_intent": (
        "call_id", "actor", "tool_name", "arguments", "provenance",
        "capability", "action",
    ),
    "policy_decision": (
        "call_id", "policy_decision", "reason", "rule_id", "trust",
        "capability", "action",
    ),
    "authorization_decision": (
        "call_id", "authorization_decision", "authorization_reason",
    ),
    "approval": ("call_id", "approval", "approval_id", "required_approver"),
    "runtime_result": ("call_id", "ok", "runtime_status", "end_stage"),
    "observation_created": (
        "call_id", "observation_id", "parent_call_id", "source_kind",
        "source", "source_trust", "result_digest",
    ),
    "experiment_evidence": (
        "fixture_id", "seed_digest", "decision_digest", "result_digest",
    ),
}


# 함수이름: missing_required_fields
# 인자:
#     event (Mapping): 검사할 trace 이벤트 하나
# 반환값:
#     tuple[str, ...]: 누락된 필드 이름들. 비어 있으면 인터페이스를 지킨 것
# 기능 설명:
#     공통 필수 필드(TRACE_BASE_FIELDS)와 사건 종류별 필수 필드를 모두 검사한다.
#
#     evaluator는 남은 기록만 보고 판정한다. 필드가 빠지면 "그 일이 없었다"와
#     "기록하지 않았다"를 구별할 수 없다. trace_completeness 지표가 이 함수를
#     근거로 계산된다.
def missing_required_fields(event: Mapping[str, Any]) -> tuple[str, ...]:
    missing = [name for name in TRACE_BASE_FIELDS if name not in event]
    missing.extend(
        name
        for name in TRACE_REQUIRED_FIELDS.get(str(event.get("event")), ())
        if name not in event
    )
    return tuple(missing)


class TraceLogger:
    # 함수이름: TraceLogger.__init__
    # 인자:
    #     path (Path): JSONL 출력 경로. 상위 디렉터리는 없으면 만든다
    # 반환값:
    #     None: 반환값 없음. 상위 디렉터리를 생성하는 부작용이 있다
    # 기능 설명:
    #     append-only JSONL 로거를 만든다. 실험 하나마다 새로 만든다.
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    # 함수이름: TraceLogger.emit
    # 인자:
    #     event (str): 사건 이름
    #     run_id (str): 실행 식별자
    #     call_id (str | None): 호출 식별자. 해당 사건에 의미가 있을 때만. 기본값 None
    #     **fields: 사건별 추가 필드. 값이 None인 항목은 기록하지 않는다
    # 반환값:
    #     dict: 실제로 기록된 이벤트 레코드
    # 기능 설명:
    #     이벤트 한 줄을 파일 끝에 덧붙인다. 이 클래스에서 실제로 파일을 쓰는 유일한
    #     메서드다.
    #
    #     모든 사건에 같은 빈 필드를 넣으면 로그가 부풀고, "값이 없다"와 "이 사건에는
    #     해당 없다"가 구별되지 않는다. 사건별 필수 필드는 TRACE_REQUIRED_FIELDS가
    #     따로 강제한다.
    #
    #     증거는 덧붙이기만 한다. 기존 줄을 고칠 수 있으면 사후에 결과를 바꿀 수
    #     있고, 그 순간 로그는 증거가 아니다.
    #
    #     같은 내용이면 같은 바이트가 나와야 파일 해시로 비교할 수 있다.
    def emit(self, event: str, run_id: str, *, call_id: str | None = None, **fields: Any) -> dict[str, Any]:
        record = {
            "event_id": f"evt_{uuid.uuid4().hex}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "run_id": run_id,
            "event": event,
        }
        if call_id is not None:
            record["call_id"] = call_id
        record.update({name: value for name, value in fields.items() if value is not None})

        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True, default=str) + "\n")
        return record

    # 함수이름: TraceLogger.canonicalize
    # 인자:
    #     value (Any): 정규화할 값. dict/list/set/Enum/스칼라 모두 가능
    # 반환값:
    #     Any: 정렬 가능하고 JSON으로 안정적으로 직렬화되는 값
    # 기능 설명:
    #     set과 Enum을 포함한 값을 결정론적인 JSON 값으로 바꾼다.
    #
    #     set은 순회 순서가 보장되지 않고, Enum은 표현이 파이썬 버전에 따라 달라질
    #     수 있다. 정규화하지 않으면 내용이 같아도 digest가 달라져 "정책이 변조됐다"는
    #     오탐이 난다.
    #
    #     JSON은 키가 문자열이어야 하고, 순서가 다르면 다른 바이트가 된다.
    @classmethod
    def canonicalize(cls, value: Any) -> Any:
        if isinstance(value, Enum):
            return value.value
        if isinstance(value, Mapping):
            return {
                str(key): cls.canonicalize(item)
                for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
            }
        if isinstance(value, (set, frozenset)):
            return sorted(cls.canonicalize(item) for item in value)
        if isinstance(value, (list, tuple)):
            return [cls.canonicalize(item) for item in value]
        return value

    # 함수이름: TraceLogger.digest
    # 인자:
    #     value (Any): 해시할 값
    # 반환값:
    #     str: 'sha256:...' 형태의 해시
    # 기능 설명:
    #     실험 증거를 비교하기 위한 안정적인 해시를 만든다.
    #
    #     같은 의미의 값이 항상 같은 바이트가 되어야 한다. 그래야 두 실행의 digest
    #     비교가 "결과가 같다"를 뜻하게 된다.
    #
    #     파이썬 기본 JSON 출력은 구분자 뒤에 공백을 넣는다. 버전에 따라 달라질 수
    #     있는 요소를 미리 제거한다.
    @classmethod
    def digest(cls, value: Any) -> str:
        canonical = json.dumps(
            cls.canonicalize(value),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        return f"sha256:{sha256(canonical.encode('utf-8')).hexdigest()}"

    # 함수이름: TraceLogger.record_validation
    # 인자:
    #     run_id / tool_name / call_id (str): 식별 정보
    #     provenance (Provenance): 이 요청의 출처
    #     validation (Mapping): validate_tool_call()의 결과
    #     result (RuntimeResult | None): 검사 실패로 끝났으면 그 결과. 기본값 None
    #     actor (str | None) / agent_step (int | None) / fixture_id (str | None):
    #         감사 메타데이터. 기본값 None
    # 반환값:
    #     None: 반환값 없음. trace에 'validation' 사건을 남긴다
    # 기능 설명:
    #     형식 검사 단계를 기록한다. 통과와 실패 모두 남긴다.
    #
    #     "이 단계를 실제로 거쳤다"가 증거다. 실패만 기록하면 단계를 건너뛴 경우와
    #     통과한 경우가 구별되지 않는다.
    def record_validation(
        self,
        run_id: str,
        tool_name: str,
        call_id: str,
        provenance: Provenance,
        validation: Mapping[str, Any],
        result: RuntimeResult | None = None,
        *,
        actor: str | None = None,
        agent_step: int | None = None,
        fixture_id: str | None = None,
    ) -> None:
        fields: dict[str, Any] = {
            "fixture_id": fixture_id,
            "agent_step": agent_step,
            "actor": actor,
            "tool_name": tool_name,
            "provenance": provenance.to_dict(),
            "validation_allowed": bool(validation["allowed"]),
            "reason": validation.get("reason"),
        }
        if result is not None:
            fields.update({
                "runtime_status": result.status,
                "end_stage": result.end_stage,
                "ok": result.ok,
                "error_code": result.error_code,
            })
        self.emit("validation", run_id, call_id=call_id, **fields)

    # 함수이름: TraceLogger.record_tool_schema
    # 인자:
    #     run_id / call_id (str): 식별 정보
    #     actor (str | None) / fixture_id (str | None): 감사 메타데이터
    #     decision (ToolSchemaDecision): schema gate 판정 결과
    # 반환값:
    #     None: 반환값 없음. 'tool_schema_decision' 사건을 남긴다
    # 기능 설명:
    #     MCP 도구 노출·인자 인터페이스 판정을 기록한다. Runtime의 첫 관문 기록이다.
    def record_tool_schema(
        self,
        run_id: str,
        call_id: str,
        *,
        actor: str,
        fixture_id: str | None,
        decision: ToolSchemaDecision,
    ) -> None:
        self.emit(
            "tool_schema_decision",
            run_id,
            call_id=call_id,
            actor=actor,
            fixture_id=fixture_id,
            tool_name=decision.tool_name,
            **decision.trace_fields(),
        )

    # 함수이름: TraceLogger.record_early_result
    # 인자:
    #     run_id / call_id (str): 식별 정보
    #     actor (str | None) / fixture_id (str | None): 감사 메타데이터
    #     result (RuntimeResult): 조기 종료 결과
    # 반환값:
    #     None: 반환값 없음. 'runtime_result' 사건을 남긴다
    # 기능 설명:
    #     ToolIntent를 만들기 전에 끝난 호출의 결과를 기록한다.
    #
    #     schema gate에서 막히면 ToolIntent가 아직 없다. record_result()는 intent를
    #     요구하므로 쓸 수 없다. 이 경로가 없으면 조기 차단이 trace에 남지 않고,
    #     그러면 evaluator가 "판정 없이 실행됐는가"를 검사할 근거를 잃는다.
    def record_early_result(
        self,
        run_id: str,
        call_id: str,
        *,
        actor: str,
        fixture_id: str | None,
        result: RuntimeResult,
    ) -> None:
        result_fields = {
            "ok": result.ok,
            "runtime_status": result.status,
            "end_stage": result.end_stage,
            "error_code": result.error_code,
            **dict(result.security),
        }
        self.emit(
            "runtime_result",
            run_id,
            call_id=call_id,
            fixture_id=fixture_id,
            actor=actor,
            tool_name=result.tool_name,
            result_digest=self.digest(result_fields),
            **result_fields,
        )

    # 함수이름: TraceLogger.record_intent
    # 인자:
    #     intent (ToolIntent): 정규화된 요청
    # 반환값:
    #     None: 반환값 없음. 'tool_intent' 사건을 남긴다
    # 기능 설명:
    #     Policy에 들어가는 입력을 기록한다.
    #
    #     "무엇을 판정했는가"가 남아야 판정 결과의 의미가 생긴다. 제안과 결과를 같은
    #     call_id로 묶어 두면 나중에 둘을 대조할 수 있다.
    def record_intent(self, intent: ToolIntent) -> None:
        self.emit("tool_intent", intent.run_id, call_id=intent.call_id, fixture_id=intent.fixture_id, agent_step=intent.agent_step, actor=intent.actor, tool_name=intent.tool_name, arguments=dict(intent.arguments), provenance=intent.provenance.to_dict(), capability=intent.capability.value, action=intent.action, resource=intent.resource)

    # 함수이름: TraceLogger.record_policy
    # 인자:
    #     intent (ToolIntent): 판정 대상
    #     decision (PolicyDecision): 정책 판정 결과
    # 반환값:
    #     None: 반환값 없음. 'policy_decision' 사건을 남긴다
    # 기능 설명:
    #     정책 판정을 reason·rule_id와 함께 기록한다. 어떤 규칙이 적용됐는지가
    #     남아야 나중에 규칙을 바꿨을 때 영향 범위를 알 수 있다.
    def record_policy(self, intent: ToolIntent, decision: PolicyDecision) -> None:
        self.emit("policy_decision", intent.run_id, call_id=intent.call_id, fixture_id=intent.fixture_id, agent_step=intent.agent_step, actor=intent.actor, tool_name=intent.tool_name, provenance=intent.provenance.to_dict(), **decision.trace_fields())

    # 함수이름: TraceLogger.record_authorization
    # 인자:
    #     intent (ToolIntent): 판정 대상
    #     decision (AuthorizationDecision): 인가 판정 결과
    # 반환값:
    #     None: 반환값 없음. 'authorization_decision' 사건을 남긴다
    # 기능 설명:
    #     actor-resource 판정을 기록한다. Policy 사건과 분리해 남기므로, 두 계층이
    #     실제로 따로 동작했음을 trace만으로 확인할 수 있다.
    def record_authorization(self, intent: ToolIntent, decision: AuthorizationDecision) -> None:
        self.emit("authorization_decision", intent.run_id, call_id=intent.call_id, fixture_id=intent.fixture_id, actor=intent.actor, tool_name=intent.tool_name, action=intent.action, resource=intent.resource, **decision.trace_fields())

    # 함수이름: TraceLogger.record_approval
    # 인자:
    #     intent (ToolIntent): 판정 대상
    #     approval (ApprovalState): 승인 상태
    # 반환값:
    #     None: 반환값 없음. 'approval' 사건을 남긴다
    # 기능 설명:
    #     승인 상태를 기록한다. pending 발급, 승인 확인, 소비를 각각 남기므로
    #     "승인 없이 실행됐는가"와 "같은 승인이 두 번 쓰였는가"를 검사할 수 있다.
    def record_approval(self, intent: ToolIntent, approval: ApprovalState) -> None:
        self.emit("approval", intent.run_id, call_id=intent.call_id, fixture_id=intent.fixture_id, actor=intent.actor, tool_name=intent.tool_name, action=intent.action, resource=intent.resource, approval=approval.status.value, approval_id=approval.approval_id, required_approver=approval.required_approver)

    # 함수이름: TraceLogger.record_result
    # 인자:
    #     intent (ToolIntent): 판정 대상
    #     result (RuntimeResult): 최종 결과
    # 반환값:
    #     None: 반환값 없음. 'runtime_result' 사건을 남긴다
    # 기능 설명:
    #     실행 또는 차단의 최종 결과를 기록한다. end_stage가 함께 남으므로 공격이
    #     어느 관문까지 도달했는지가 드러난다.
    def record_result(self, intent: ToolIntent, result: RuntimeResult) -> None:
        security = dict(result.security)
        result_fields = {
            "ok": result.ok,
            "runtime_status": result.status,
            "end_stage": result.end_stage,
            "error_code": result.error_code,
            **security,
        }
        self.emit("runtime_result", intent.run_id, call_id=intent.call_id, fixture_id=intent.fixture_id, actor=intent.actor, tool_name=intent.tool_name, result_digest=self.digest(result_fields), **result_fields)

    # 함수이름: TraceLogger.record_observation
    # 인자:
    #     run_id (str): 실행 식별자
    #     envelope (ObservationEnvelope): 관측 봉투
    #     fixture_id (str | None): 실험 케이스 라벨. 기본값 None
    # 반환값:
    #     None: 반환값 없음. 'observation_created' 사건을 남긴다
    # 기능 설명:
    #     도구 결과의 출처·신뢰·해시를 기록한다. content 자체가 아니라 메타데이터가
    #     핵심이다.
    #
    #     evaluator가 observation_metadata_tamper를 계산할 때 이 사건을 본다.
    #     비신뢰 출처인데 trust가 untrusted가 아니면 메타데이터가 변조된 것이다.
    def record_observation(self, run_id: str, envelope: ObservationEnvelope, *, fixture_id: str | None = None) -> None:

        self.emit(
            "observation_created",
            run_id,
            call_id=envelope.parent_call_id,
            fixture_id=fixture_id,
            observation_id=envelope.observation_id,
            parent_call_id=envelope.parent_call_id,
            source_kind=envelope.source_kind.value,
            source=envelope.source,
            source_trust=envelope.trust.value,
            result_digest=envelope.result_digest,
        )

    # 함수이름: TraceLogger.record_experiment_evidence
    # 인자:
    #     run_id (str): 실행 식별자
    #     fixture_id (str | None): 실험 케이스 라벨
    #     seed_digest / decision_digest / result_digest (str): 재현성 해시 3종
    #     control_plane_before_digest / control_plane_after_digest (str | None):
    #         공격 전후 정책 상태 해시
    #     control_plane_mutation (bool | None): 정책이 바뀌었는가.
    #         비교할 수 없으면 None
    # 반환값:
    #     None: 반환값 없음. 'experiment_evidence' 사건을 남긴다
    # 기능 설명:
    #     실험이 끝난 뒤 증거 요약을 trace의 마지막 사건으로 남긴다.
    #
    #     요약을 별도 파일에만 두면 trace와 요약이 따로 놀 수 있다. 같은 파일 끝에
    #     넣으면 원시 기록과 요약이 항상 함께 이동한다.
    def record_experiment_evidence(self, run_id: str, *, fixture_id: str,
                                   seed_digest: str, decision_digest: str,
                                   result_digest: str,
                                   control_plane_before_digest: str | None = None,
                                   control_plane_after_digest: str | None = None,
                                   control_plane_mutation: bool | None = None) -> None:
        self.emit(
            "experiment_evidence",
            run_id,
            fixture_id=fixture_id,
            seed_digest=seed_digest,
            decision_digest=decision_digest,
            result_digest=result_digest,
            control_plane_before_digest=control_plane_before_digest,
            control_plane_after_digest=control_plane_after_digest,
            control_plane_mutation=control_plane_mutation,
        )


    # 함수이름: TraceLogger.iter_events
    # 인자:
    #     run_id (str | None): 이 실행의 사건만 걸러낸다. 기본값 None이면 전부
    #     strict (bool): 필수 필드 누락 시 경고할지 여부. 기본값 False
    # 반환값:
    #     Iterator[dict]: 기록된 이벤트를 순서대로 돌려주는 반복자
    # 기능 설명:
    #     기록한 JSONL을 다시 읽는다. evaluator와 experiment_support가 이 메서드로
    #     증거를 읽는다.
    #
    #     기록 인터페이스 위반은 조용히 넘어가면 안 되지만, 예외로 중단하면 그때까지의
    #     증거를 읽지 못한다. 경고로 알리고 읽기는 계속하는 절충이다.
    #
    #     메모리의 리스트를 쓰면 "파일에 실제로 남았는가"를 검증하지 못한다. 평가가
    #     기록된 것만 보게 해야 관측 가능성이 실제로 성립한다.
    def iter_events(self, *, run_id: str | None = None, strict: bool = False) -> Iterator[dict[str, Any]]:

        if not self.path.exists():
            return
        comment_lines = 0
        malformed_lines = 0
        with self.path.open(encoding="utf-8") as handle:
            for line in handle:

                line = line.strip()

                if not line:
                    continue

                if line.startswith("//"):
                    if strict:
                        raise ValueError(f"JSONL trace에 주석 줄이 있습니다: {self.path}")
                    comment_lines += 1
                    continue

                try:
                    event = json.loads(line.lstrip("\ufeff"))
                except json.JSONDecodeError as exc:
                    if strict:
                        raise ValueError(f"malformed JSONL trace: {self.path}") from exc
                    malformed_lines += 1
                    continue

                if run_id is None or event["run_id"] == run_id:
                    yield event
        warnings_to_report = []
        if comment_lines:
            warnings_to_report.append(f"JSONL 이벤트가 아닌 주석 {comment_lines}줄")
        if malformed_lines:
            warnings_to_report.append(f"파싱할 수 없는 JSON {malformed_lines}줄")
        if warnings_to_report:
            warnings.warn(
                f"{self.path}에서 {', '.join(warnings_to_report)}을 건너뛰었습니다. "
                "실험 설명은 EXP_LOG.md에 두고, 감사 시에는 strict=True로 다시 확인하세요.",
                RuntimeWarning,
                stacklevel=2,
            )
