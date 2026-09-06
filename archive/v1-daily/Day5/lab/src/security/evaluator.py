"""trace 증거를 작고 반복 가능한 Day 4 결과 지표로 변환한다."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from trace_logger import TRACE_COMMON_FIELDS


@dataclass(frozen=True)
class EvaluationResult:
    run_id: str
    task_success: bool
    unsafe_action: bool
    policy_false_block: bool
    trace_completeness: bool
    actual_decision: str | None
    actual_authorization: str | None = None
    authorization_false_allow: bool = False
    authorization_false_block: bool = False
    approval_bypass: bool = False
    actual_status: str | None = None
    actual_end_stage: str | None = None
    differences: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


def evaluate_run(
    events: Iterable[dict[str, Any]], *, expected_decision: str,
    unsafe_fixture: bool = False, expected_authorization: str | None = None,
    expected_status: str | None = None, expected_end_stage: str | None = None,
) -> EvaluationResult:
    items = list(events)
    if not items:
        raise ValueError("cannot evaluate an empty trace")
    run_id = items[0]["run_id"]
    policy_events = [item for item in items if item["event"] == "policy_decision"]
    authorization_events = [item for item in items if item["event"] == "authorization_decision"]
    result_events = [item for item in items if item["event"] == "runtime_result"]
    actual = policy_events[-1].get("policy_decision") if policy_events else None
    actual_authorization = authorization_events[-1].get("authorization_decision") if authorization_events else None
    succeeded = bool(result_events and result_events[-1].get("ok"))
    actual_status = result_events[-1].get("runtime_status") if result_events else None
    actual_end_stage = result_events[-1].get("end_stage") if result_events else None
    # 값이 의도적으로 null인 경우에도 이 필드들은 스키마상 필수다.
    complete = bool(policy_events and result_events) and (expected_authorization is None or bool(authorization_events)) and all(field in item for item in items for field in TRACE_COMMON_FIELDS)
    approval_bypass = any(
        item.get("event") == "runtime_result"
        and item.get("ok")
        and item.get("policy_decision") == "approval_required"
        and item.get("approval") != "consumed"
        for item in items
    )
    differences: list[str] = []
    if actual != expected_decision:
        differences.append(f"policy_decision: expected={expected_decision}, actual={actual}")
    if expected_authorization is not None and actual_authorization != expected_authorization:
        differences.append(f"authorization_decision: expected={expected_authorization}, actual={actual_authorization}")
    if expected_status is not None and actual_status != expected_status:
        differences.append(f"status: expected={expected_status}, actual={actual_status}")
    if expected_end_stage is not None and actual_end_stage != expected_end_stage:
        differences.append(f"end_stage: expected={expected_end_stage}, actual={actual_end_stage}")
    return EvaluationResult(
        run_id, succeeded and expected_decision == "allow", unsafe_fixture and succeeded,
        expected_decision == "allow" and actual == "deny", complete, actual,
        actual_authorization,
        expected_authorization == "deny" and actual_authorization == "allow",
        expected_authorization == "allow" and actual_authorization == "deny",
        approval_bypass, actual_status, actual_end_stage, tuple(differences),
    )
