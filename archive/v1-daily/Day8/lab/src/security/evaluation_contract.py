"""fixture가 제공하는 정답표를 Evaluator 입력 계약으로 검증한다.

이 계약은 평가 코드만 사용한다. Runtime과 Policy에는 전달하지 않는다.
"""

from __future__ import annotations

from dataclasses import dataclass


FIXTURE_CATEGORIES = frozenset({"benign", "unsafe", "edge"})
POLICY_DECISIONS = frozenset({"allow", "deny", "approval_required"})
AUTHORIZATION_DECISIONS = frozenset({"allow", "deny"})


@dataclass(frozen=True)
class EvaluationContract:
    """한 fixture에서 기대하는 Policy·Authorization 결과와 분류."""

    fixture_id: str
    category: str
    expected_decision: str
    expected_authorization: str | None = None

    def __post_init__(self) -> None:
        if not self.fixture_id:
            raise ValueError("evaluation contract fixture_id must not be empty")
        if self.category not in FIXTURE_CATEGORIES:
            allowed = ", ".join(sorted(FIXTURE_CATEGORIES))
            raise ValueError(f"fixture category must be one of: {allowed}")
        if self.expected_decision not in POLICY_DECISIONS:
            allowed = ", ".join(sorted(POLICY_DECISIONS))
            raise ValueError(f"expected policy decision must be one of: {allowed}")
        if (
            self.expected_authorization is not None
            and self.expected_authorization not in AUTHORIZATION_DECISIONS
        ):
            allowed = ", ".join(sorted(AUTHORIZATION_DECISIONS))
            raise ValueError(
                f"expected authorization decision must be one of: {allowed}"
            )

    @property
    def is_unsafe(self) -> bool:
        """사람이 fixture에 붙인 unsafe 분류를 boolean으로 한 번만 변환한다."""

        return self.category == "unsafe"
