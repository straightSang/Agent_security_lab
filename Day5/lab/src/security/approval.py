"""Intent에 결속된 메모리 내 승인 상태. 저장소만 교체하고 의미는 유지한다."""

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

    def approve(self, approval_id: str, *, approver: str) -> ApprovalState:
        with self._lock:
            state = self.resolve(approval_id)
            if state.status is not ApprovalStatus.PENDING or state.required_approver != approver:
                return state
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

    def resolve(self, approval_id: str | None) -> ApprovalState:
        with self._lock:
            if not approval_id:
                return ApprovalState(None, ApprovalStatus.NOT_REQUIRED)
            if approval_id not in self._records:
                return ApprovalState(approval_id, ApprovalStatus.INVALID)
            state = self._records[approval_id]
            if state.expires_at and datetime.fromisoformat(state.expires_at) <= datetime.now(timezone.utc):
                expired = ApprovalState(
                    state.approval_id, ApprovalStatus.EXPIRED,
                    state.intent_fingerprint, state.requested_at, state.expires_at,
                    state.approver, state.requested_actor, state.required_approver,
                    state.resource, state.action,
                )
                self._records[approval_id] = expired
                return expired
            return state

    def consume(self, approval_id: str, *, intent_fingerprint: str) -> tuple[ApprovalState, bool]:
        """승인을 소비하고, 이 호출이 실제 소비자인지를 함께 반환한다.

        ``consumed_now``가 True인 단 하나의 호출만 dispatcher에 진입할 수 있다.
        """
        with self._lock:
            state = self.resolve(approval_id)
            if (
                state.status is not ApprovalStatus.APPROVED
                or state.intent_fingerprint != intent_fingerprint
            ):
                return state, False
            consumed = ApprovalState(
                state.approval_id, ApprovalStatus.CONSUMED,
                state.intent_fingerprint, state.requested_at, state.expires_at,
                state.approver, state.requested_actor, state.required_approver,
                state.resource, state.action,
            )
            self._records[approval_id] = consumed
            return consumed, True
