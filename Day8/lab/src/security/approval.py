"""

Intent와 연결되어 있는 승인 상태. 

[승인 및 실행 흐름]
approval_id = apr_123
상태 = APPROVED

요청 A: consume(apr_123)
  -> APPROVED 확인
  -> CONSUMED로 변경
  -> consumed_now = True
  -> Dispatcher 실행

요청 B: consume(apr_123)
  -> CONSUMED 확인
  -> consumed_now = False
  -> Dispatcher 미호출

"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from threading import RLock

from .types import ApprovalState, ApprovalStatus, Decision, PolicyDecision, ToolIntent


class ApprovalStore:
    def __init__(self) -> None:
        self._records: dict[str, ApprovalState] = {}
        # Lab의 같은 프로세스 안에서만 consume 경쟁을 막는다. 여러 프로세스/서버
        # 배포에서는 DB의 compare-and-set 또는 transaction으로 교체해야 한다.
        self._lock = RLock()

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

    # ApprovalStatus.state == PENDING이고, state.required_approver == approver 이어야 승인.
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

    # 승인이 필요한 record 맞는지, 기간이 만료되지는 않았는지, 형식이 멀쩡한지
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


    # APPROVED 이후 dispatcher 진입 전 ApprovalStatus.state: APPROVED -> CONSUMED 로 변경 (일회성 승인 유지)
    def consume(self, approval_id: str, *, intent_fingerprint: str) -> tuple[ApprovalState, bool]:
        """
        ``consumed_now``가 True인 호출만 dispatcher에 진입할 수 있다.
        """
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
