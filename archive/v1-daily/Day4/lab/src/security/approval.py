"""Intent에 결속된 메모리 내 승인 상태. 저장소만 교체하고 의미는 유지한다."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from .types import ApprovalState, ApprovalStatus, Decision, PolicyDecision, ToolIntent


class ApprovalStore:
    def __init__(self) -> None:
        self._records: dict[str, ApprovalState] = {}

    def request(self, intent: ToolIntent, decision: PolicyDecision, *, ttl_minutes: int = 10) -> ApprovalState:
        if decision.outcome is not Decision.APPROVAL_REQUIRED:
            raise ValueError("approval can be requested only for APPROVAL_REQUIRED decisions")
        now = datetime.now(timezone.utc)
        approval_id = f"apr_{uuid.uuid4().hex}"
        state = ApprovalState(approval_id, ApprovalStatus.PENDING, intent.fingerprint(), now.isoformat(), (now + timedelta(minutes=ttl_minutes)).isoformat())
        self._records[approval_id] = state
        return state

    def approve(self, approval_id: str, *, approver: str) -> ApprovalState:
        state = self.resolve(approval_id)
        if state.status is not ApprovalStatus.PENDING:
            return state
        approved = ApprovalState(state.approval_id, ApprovalStatus.APPROVED, state.intent_fingerprint, state.requested_at, state.expires_at, approver)
        self._records[approval_id] = approved
        return approved

    def reject(self, approval_id: str, *, approver: str) -> ApprovalState:
        state = self.resolve(approval_id)
        if state.status is not ApprovalStatus.PENDING:
            return state
        rejected = ApprovalState(state.approval_id, ApprovalStatus.REJECTED, state.intent_fingerprint, state.requested_at, state.expires_at, approver)
        self._records[approval_id] = rejected
        return rejected

    def resolve(self, approval_id: str | None) -> ApprovalState:
        if not approval_id:
            return ApprovalState(None, ApprovalStatus.NOT_REQUIRED)
        if approval_id not in self._records:
            return ApprovalState(approval_id, ApprovalStatus.INVALID)
        state = self._records[approval_id]
        if state.expires_at and datetime.fromisoformat(state.expires_at) <= datetime.now(timezone.utc):
            expired = ApprovalState(state.approval_id, ApprovalStatus.EXPIRED, state.intent_fingerprint, state.requested_at, state.expires_at, state.approver)
            self._records[approval_id] = expired
            return expired
        return state

    def consume(self, approval_id: str, *, intent_fingerprint: str) -> ApprovalState:
        """일치하는 승인 record를 도구 dispatch 직전에 일회용으로 소비한다."""
        state = self.resolve(approval_id)
        if (
            state.status is not ApprovalStatus.APPROVED
            or state.intent_fingerprint != intent_fingerprint
        ):
            return state
        consumed = ApprovalState(
            state.approval_id,
            ApprovalStatus.CONSUMED,
            state.intent_fingerprint,
            state.requested_at,
            state.expires_at,
            state.approver,
        )
        self._records[approval_id] = consumed
        return consumed
