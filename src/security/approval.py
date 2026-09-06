# 모듈이름: security.approval
# 역할: 위험한 행동에 대한 1회용 승인의 발급·승인·소비를 관리한다
# 호출 주체: runtime.Runtime.execute_tool()의 5단계, approval_control.py
#
# 기능 설명:
#     "이 행동은 사람이 명시적으로 동의했는가"에 답한다.
#
#     [상태 전이]
#
#         (없음)
#           |  request()          정책이 APPROVAL_REQUIRED일 때만 발급
#           v
#         PENDING
#           |  approve()          required_approver와 일치할 때만
#           v                     reject() -> REJECTED,  시간 초과 -> EXPIRED
#         APPROVED
#           |  consume()          dispatch 직전에 1회만
#           v
#         CONSUMED                같은 ID 재제출은 여기서 막힌다
#
#     [1회용인 이유 — replay 차단]
#
#         요청 A: consume(apr_123)  -> APPROVED 확인 -> CONSUMED로 변경
#                                   -> consumed_now=True  -> Dispatcher 실행
#         요청 B: consume(apr_123)  -> 이미 CONSUMED
#                                   -> consumed_now=False -> Dispatcher 미호출
#
#     한 번 받은 승인으로 같은 행동을 두 번 할 수 있으면 승인의 의미가 사라진다.
#     소비 시점을 dispatch 직전에 두는 것도 같은 이유다. 더 일찍 소비하면 실행에
#     실패한 승인이 낭비되고, 더 늦게 소비하면 그 사이에 재사용이 가능해진다.
#
#     approval record는 ToolIntent의 지문(fingerprint)을 함께 저장한다. 인자가
#     하나라도 다르면 지문이 달라져 그 승인은 쓸 수 없다. "쓰기를 승인했다"가
#     아니라 "이 내용을 이 경로에 쓰는 것을 승인했다"이다.
#
#     RLock은 같은 프로세스 안에서만 consume 경쟁을 막는다. 여러 프로세스나 서버로
#     배포하면 DB의 compare-and-set 또는 트랜잭션으로 교체해야 한다.


from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from threading import RLock

from .types import ApprovalState, ApprovalStatus, Decision, PolicyDecision, ToolIntent


# 클래스이름: ApprovalStore
# 필드:
#     _records (dict[str, ApprovalState]): approval_id -> 상태
#     _lock (RLock): 같은 프로세스 안의 consume 경쟁 방지
# 메서드:
#     request(): PENDING 발급
#     approve() / reject(): PENDING -> APPROVED / REJECTED
#     resolve(): 현재 상태 조회. 만료를 여기서 판정한다
#     consume(): APPROVED -> CONSUMED. dispatch 직전 1회
#     audit_snapshot(): 실험 전후 비교용 정렬된 사본
# 기능 설명:
#     승인 레코드를 메모리에 보관하는 저장소다.
#
#     승인 상태 전이를 한 곳에 모아야 "APPROVED가 아닌데 실행됐다" 같은
#     불변조건을 한 파일에서 검증할 수 있다. 상태 전이가 흩어지면 어디서
#     규칙이 깨졌는지 추적할 수 없다.
class ApprovalStore:

    # 함수이름: ApprovalStore.__init__
    # 인자: 없음
    # 반환값:
    #     None: 반환값 없음
    # 기능 설명:
    #     빈 레코드 저장소와 재진입 가능 락을 만든다. 실험마다 새로 만들어
    #     쓰며 재사용하지 않는다.
    def __init__(self) -> None:
        self._records: dict[str, ApprovalState] = {}
        # Lab의 같은 프로세스 안에서만 consume 경쟁을 막는다. 여러 프로세스/서버
        # 배포에서는 DB의 compare-and-set 또는 transaction으로 교체해야 한다.
        self._lock = RLock()

    # 함수이름: ApprovalStore.request
    # 인자:
    #     intent (ToolIntent): 승인을 요청하는 정규화된 행동
    #     decision (PolicyDecision): 정책 판정. APPROVAL_REQUIRED여야 한다
    #     required_approver (str): 이 승인을 할 수 있는 유일한 주체.
    #         Authorization이 정한다
    #     ttl_minutes (int): 유효 시간. 기본값 10분
    # 반환값:
    #     ApprovalState: PENDING 상태의 새 레코드
    #     ValueError: decision이 APPROVAL_REQUIRED가 아닐 때 발생
    # 기능 설명:
    #     새 승인 요청 레코드를 만든다.
    #
    #     정책이 요구하지 않은 승인을 만들 수 있으면, 승인 레코드의 존재
    #     자체가 "이 행동은 위험하다"는 신호가 되지 못한다. 발급 조건을
    #     정책에 결속시킨다.
    #
    #     intent.fingerprint()를 함께 저장해 승인을 이 행동에 묶는다. 나중에
    #     인자를 바꿔 제출하면 지문이 달라져 consume()에서 걸린다.
    #
    #     승인은 그 시점의 맥락에 대한 동의다. 몇 시간 뒤에도 유효하면 사람이
    #     무엇에 동의했는지 기억하지 못하는 상태에서 실행된다.
    def request(
        self,
        intent: ToolIntent,
        decision: PolicyDecision,
        *,
        required_approver: str,
        ttl_minutes: int = 10,
    ) -> ApprovalState:
        if decision.outcome is not Decision.APPROVAL_REQUIRED:
            raise ValueError("approval can be requested only for APPROVAL_REQUIRED decisions")

        now = datetime.now(timezone.utc)
        approval_id = f"apr_{uuid.uuid4().hex}"

        state = ApprovalState(
            approval_id,
            ApprovalStatus.PENDING,
            intent.fingerprint(),
            now.isoformat(),
            (now + timedelta(minutes=ttl_minutes)).isoformat(),
            None,
            intent.actor,
            required_approver,
            intent.resource,
            intent.action,
        )

        with self._lock:
            self._records[approval_id] = state

        return state

    # 함수이름: ApprovalStore.approve
    # 인자:
    #     approval_id (str): 승인할 레코드 ID
    #     approver (str): 인증된 승인자 신원. 이 값은 인증 계층에서만 온다
    # 반환값:
    #     ApprovalState: 성공하면 APPROVED 상태, 아니면 현재 상태 그대로
    # 기능 설명:
    #     PENDING 상태이고 required_approver와 일치할 때만 APPROVED로 바꾼다.
    #
    #     승인 실패는 정상적인 결과다. 잘못된 승인자가 시도했다는 사실이
    #     현재 상태와 함께 호출자에게 돌아가고 trace에 남는 편이, 예외로
    #     흐름을 끊는 것보다 감사에 유리하다.
    #
    #     이 클래스는 인증을 하지 않는다. 신원 확인은 바깥(session/IdP,
    #     랩에서는 test harness)의 책임이고, 여기서는 그 신원이 규칙과
    #     맞는지만 본다. 책임을 섞으면 둘 다 약해진다.
    def approve(self, approval_id: str, *, approver: str) -> ApprovalState:
        with self._lock:

            state = self.resolve(approval_id)

            # pending 상태가 아니라면 그대로 return
            if state.status is not ApprovalStatus.PENDING or state.required_approver != approver:
                return state

            # ApprovalStatus.state: PENDING -> APPROVED
            approved = ApprovalState(
                state.approval_id, ApprovalStatus.APPROVED,
                state.intent_fingerprint, state.requested_at, state.expires_at,
                approver, state.requested_actor, state.required_approver,
                state.resource, state.action,
            )
            self._records[approval_id] = approved

            return approved


    # 함수이름: ApprovalStore.reject
    # 인자:
    #     approval_id (str): 거부할 레코드 ID
    #     approver (str): 인증된 승인자 신원
    # 반환값:
    #     ApprovalState: 성공하면 REJECTED 상태, 아니면 현재 상태 그대로
    # 기능 설명:
    #     approve()의 대칭 동작이다. 조건과 실패 처리 방식이 동일하다.
    #
    #     거부도 레코드로 남긴다. 삭제하면 "요청이 있었는데 거부됐다"는 사실이
    #     사라지고, 승인 피로나 반복 시도를 관측할 수 없게 된다.
    def reject(self, approval_id: str, *, approver: str) -> ApprovalState:
        with self._lock:
            state = self.resolve(approval_id)
            if state.status is not ApprovalStatus.PENDING or state.required_approver != approver:
                return state
            rejected = ApprovalState(
                state.approval_id, ApprovalStatus.REJECTED,
                state.intent_fingerprint, state.requested_at, state.expires_at,
                approver, state.requested_actor, state.required_approver,
                state.resource, state.action,
            )
            self._records[approval_id] = rejected
            return rejected

    # 함수이름: ApprovalStore.resolve
    # 인자:
    #     approval_id (str | None): 조회할 ID. None이나 빈 문자열도 허용된다
    # 반환값:
    #     ApprovalState: 현재 상태
    #         None/빈 문자열 -> NOT_REQUIRED
    #         등록되지 않은 ID -> INVALID
    #         만료됨 -> EXPIRED (저장된 상태도 갱신된다)
    #         그 외 -> 저장된 상태 그대로
    # 기능 설명:
    #     승인 상태를 조회하면서 만료 여부를 함께 판정한다.
    #
    #     만료는 시간이 지나면 저절로 일어나는 사건이지만, 아무도 조회하지
    #     않으면 기록될 기회가 없다. 조회 시점에 만료를 확정하고 저장해야
    #     audit_snapshot에도 EXPIRED가 남는다.
    #
    #     승인이 필요 없는 요청(읽기 등)은 approval_id를 주지 않는다. 이를
    #     INVALID로 처리하면 정상 흐름이 오류처럼 보인다. '제출하지 않음'과
    #     '잘못된 것을 제출함'은 다른 사건이다.
    def resolve(self, approval_id: str | None) -> ApprovalState:
        with self._lock:

            if not approval_id:
                return ApprovalState(None, ApprovalStatus.NOT_REQUIRED)

            # record 안에 approval_id 가 들어있다면 정상 state. 안 들어있으면 INVALID로 return
            if approval_id not in self._records:
                return ApprovalState(approval_id, ApprovalStatus.INVALID)

            state = self._records[approval_id]

            if state.expires_at and datetime.fromisoformat(state.expires_at) <= datetime.now(timezone.utc):
                expired = ApprovalState(
                    state.approval_id, ApprovalStatus.EXPIRED,
                    state.intent_fingerprint, state.requested_at, state.expires_at,
                    state.approver, state.requested_actor, state.required_approver,
                    state.resource, state.action
                )

                self._records[approval_id] = expired
                return expired

            return state


    # 함수이름: ApprovalStore.consume
    # 인자:
    #     approval_id (str): 소비할 레코드 ID
    #     intent_fingerprint (str): 지금 실행하려는 ToolIntent의 지문
    # 반환값:
    #     tuple[ApprovalState, bool]: (소비 후 상태, consumed_now)
    #         consumed_now가 True인 호출만 dispatcher에 진입할 수 있다
    # 기능 설명:
    #     APPROVED 상태를 CONSUMED로 바꾸는 1회용 소비다. Runtime이
    #     _dispatch() 직전에 호출한다.
    #
    #     1. 상태가 APPROVED인가 — 아직 승인 전이거나 이미 소비됐는가
    #     2. 지문이 일치하는가 — 승인받은 그 행동이 맞는가
    #
    #     둘 중 하나라도 어긋나면 (현재 상태, False)를 돌려주고 실행되지
    #     않는다.
    #
    #     확인과 변경 사이에 다른 호출이 끼어들면 같은 승인이 두 번 소비될 수
    #     있다. 검사 시점과 사용 시점의 불일치(TOCTOU)를 막으려면 두 동작이
    #     원자적이어야 한다.
    #
    #     [주의]
    #     RLock은 프로세스 안에서만 유효하다. 다중 프로세스 배포에서는 DB의
    #     compare-and-set으로 교체해야 한다.
    def consume(self, approval_id: str, *, intent_fingerprint: str) -> tuple[ApprovalState, bool]:
        with self._lock:

            state = self.resolve(approval_id)
            if (
                state.status is not ApprovalStatus.APPROVED
                or state.intent_fingerprint != intent_fingerprint ):

                return state, False

            consumed = ApprovalState(
                state.approval_id, ApprovalStatus.CONSUMED,
                state.intent_fingerprint, state.requested_at, state.expires_at,
                state.approver, state.requested_actor, state.required_approver,
                state.resource, state.action,
            )

            self._records[approval_id] = consumed

            return consumed, True

    # 함수이름: ApprovalStore.audit_snapshot
    # 인자: 없음
    # 반환값:
    #     list[dict]: approval_id 기준으로 정렬된 승인 상태 사본.
    #         각 항목은 approval_id · status · intent_fingerprint ·
    #         requested_actor · required_approver · resource · action
    # 기능 설명:
    #     control plane 스냅샷에 들어가는 승인 상태 사본을 만든다.
    #
    #     이 목록이 control_plane_digest의 입력이 된다. dict 순회 순서가
    #     흔들리면 상태가 같은데도 digest가 달라져 "정책이 변조됐다"는 오탐이
    #     난다.
    #
    #     experiment_support가 이 값을 읽어 해시할 때 내부 상태가 함께 노출되면
    #     안 된다. 관측이 대상을 바꾸지 않게 한다.
    def audit_snapshot(self) -> list[dict[str, str | None]]:
        with self._lock:
            return [
                {
                    "approval_id": state.approval_id,
                    "status": state.status.value,
                    "intent_fingerprint": state.intent_fingerprint,
                    "requested_actor": state.requested_actor,
                    "required_approver": state.required_approver,
                    "resource": state.resource,
                    "action": state.action,
                }
                for _, state in sorted(self._records.items())
            ]
