# 모듈이름: approval_control
# 역할: 승인 control-plane 조작 helper. Agent 도구가 아니다
# 호출 주체: tests/test_security_invariants.py
#
# 기능 설명:
#     승인을 '주는 쪽'의 동작을 담는다. 요청은 Runtime이 만들고, 승인은 사람이
#     한다. 이 파일은 그 사람 쪽 절차의 랩 대역이다.
#
#     [security/approval.py와의 차이]
#
#         security/approval.py   승인 상태 저장과 전이 규칙 (보안 도메인)
#         approval_control.py    인증된 승인자를 대신해 그 규칙을 호출 (control plane)
#
#     호출자가 이미 인증된 승인자 신원을 제공해야 한다. 랩에서는 test harness가,
#     운영에서는 session/IdP가 그 역할을 한다.
#
#     이 함수가 도구로 노출되면 에이전트가 스스로 승인할 수 있게 된다. 승인
#     경계가 존재하는 이유 자체가 사라진다.

from __future__ import annotations

from dataclasses import dataclass

from security.approval import ApprovalStore
from security.types import ApprovalState, ApprovalStatus


# 클래스이름: ApprovalControlResult
# 필드:
#     state (ApprovalState): 처리 후의 승인 상태
#     changed (bool): 실제로 상태가 바뀌었는가
#     reason (str): 안정적인 결과 코드
#         APPROVED / APPROVAL_NOT_PENDING / APPROVER_NOT_AUTHORIZED
# 기능 설명:
#     승인 control-plane 조작의 결과다.
#
#     "이미 승인된 것을 다시 승인 요청했다"와 "새로 승인했다"는 다른 사건이다.
#     state만 보면 둘 다 APPROVED로 같아 보인다.
@dataclass(frozen=True)
class ApprovalControlResult:
    state: ApprovalState
    changed: bool
    reason: str


# 함수이름: approve_pending_request
# 인자:
#     approvals (ApprovalStore): 대상 승인 저장소
#     approval_id (str): 승인할 레코드 ID
#     authenticated_approver (str): 이미 인증이 끝난 승인자 신원
# 반환값:
#     ApprovalControlResult: 처리 후 상태 · 변경 여부 · 결과 코드
# 기능 설명:
#     PENDING 상태이고 승인자가 규칙과 일치할 때만 승인한다.
#
#     authenticated_approver는 이미 확인이 끝난 신원이다. 랩에서는 test harness가,
#     운영에서는 session/IdP가 그 확인을 한다. 여기서 인증까지 하면 인증 로직이
#     승인 로직에 섞여 둘 다 검증하기 어려워진다.
#
#     잘못된 승인자의 시도는 오류가 아니라 관측해야 할 사건이다. 결과 코드로
#     돌려주면 trace에 남고 승인 피로나 반복 시도를 셀 수 있다.
def approve_pending_request(
    approvals: ApprovalStore,
    approval_id: str,
    *,
    authenticated_approver: str,
) -> ApprovalControlResult:
    state = approvals.resolve(approval_id)
    if state.status is not ApprovalStatus.PENDING:
        return ApprovalControlResult(state, False, "APPROVAL_NOT_PENDING")
    if state.required_approver != authenticated_approver:
        return ApprovalControlResult(state, False, "APPROVER_NOT_AUTHORIZED")
    approved = approvals.approve(approval_id, approver=authenticated_approver)
    return ApprovalControlResult(approved, approved.status is ApprovalStatus.APPROVED, "APPROVED")
