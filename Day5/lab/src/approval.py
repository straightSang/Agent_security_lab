"""Trusted approval control-plane helpers for the Day 5 Lab.

This is not an Agent tool.  The caller must provide an already authenticated
approver identity (a test harness in this Lab, a session/IdP in production).

이 파일은 인증 시스템이 아니라 테스트용 control-plane이다. approval security domain 은 security/approval.py에 있다. 

Agent_v0.4.py가 approval.py를 호출하고, approval.py가 내부적으로 security/approval.py의 ApprovalStore를 사용한다.
"""

from __future__ import annotations

from dataclasses import dataclass

from security.approval import ApprovalStore
from security.types import ApprovalState, ApprovalStatus


@dataclass(frozen=True)
class ApprovalControlResult:
    state: ApprovalState
    changed: bool
    reason: str


def approve_pending_request(
    approvals: ApprovalStore,
    approval_id: str,
    *,
    authenticated_approver: str,
) -> ApprovalControlResult:
    """Approve only when the authenticated approver matches the record rule."""
    state = approvals.resolve(approval_id)
    if state.status is not ApprovalStatus.PENDING:
        return ApprovalControlResult(state, False, "APPROVAL_NOT_PENDING")
    if state.required_approver != authenticated_approver:
        return ApprovalControlResult(state, False, "APPROVER_NOT_AUTHORIZED")
    approved = approvals.approve(approval_id, approver=authenticated_approver)
    return ApprovalControlResult(approved, approved.status is ApprovalStatus.APPROVED, "APPROVED")
