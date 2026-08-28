"""정책 엔진: 결정을 반환할 뿐, 도구를 직접 실행하지 않는다."""

from __future__ import annotations

from typing import Any, Callable

from .trust import label_trust
from .permission import POLICY
from .types import Capability, Decision, PolicyDecision, ToolIntent, TrustLabel

_SENSITIVE_NAMES = {".env", "credentials", "credential", "secret", "secrets", "id_rsa", "token", "tokens", "password", "passwords"}


class PolicyEngine:
    """감사 가능한 작은 Day 4 기본 정책.

    실험이 발전하면 이곳의 규칙을 교체한다. Runtime Dispatcher에는 정책 예외를
    추가하지 않는다.
    """

    def evaluate(self, intent: ToolIntent) -> PolicyDecision:

        # provenance : trustlabel 부여
        trust = label_trust(intent.provenance.kind)

        resource_parts = set((intent.resource or "").lower().replace("\\", "/").split("/"))

        # 민감 키워드 확인
        if any(part in _SENSITIVE_NAMES or part.startswith(("credential", "secret", "token", "password")) for part in resource_parts):
            return self._decision(Decision.DENY, "SENSITIVE_RESOURCE_DENIED", intent, trust)

        # capability 검증
        if intent.capability is Capability.UNKNOWN:
            return self._decision(Decision.DENY, "CAPABILITY_NOT_ALLOWLISTED", intent, trust)

        # 간접 콘텐츠는 데이터일 뿐 권한을 위임하지 않는다. 신뢰할 수 없는
        # provenance는 승인 단계보다 먼저 항상 DENY한다. 따라서 approval ID로
        # 파일·웹·도구 출력에서 유래한 명령을 되살릴 수 없다.
        # provenance-trust 검증
        if trust is TrustLabel.UNTRUSTED:
            return self._decision(Decision.DENY, "UNTRUSTED_PROVENANCE_CANNOT_AUTHORIZE_TOOL", intent, trust)

        # 선언형 permission 설정이 sandbox 내부 리소스 범위와 논리 명령의
        # 단일 기준이다.
        if not self._permission_allows(intent):
            return self._decision(Decision.DENY, "RESOURCE_OR_COMMAND_SCOPE_DENIED", intent, trust)

        if POLICY.get(intent.tool_name, {}).get("approval_required", False):
            return self._decision(Decision.APPROVAL_REQUIRED, "WRITE_REQUIRES_EXPLICIT_APPROVAL", intent, trust)

        return self._decision(Decision.ALLOW, "BASELINE_CAPABILITY_ALLOWED", intent, trust)

    @staticmethod
    def _decision(outcome: Decision, reason: str, intent: ToolIntent, trust: TrustLabel) -> PolicyDecision:
        return PolicyDecision(
            outcome, reason, intent.capability, intent.action, intent.resource,
            trust, rule_id=reason,
        )

    @staticmethod
    def _resource_scope(resource: str | None) -> str:
        """정규화된 리소스를 ``SANDBOX_ROOT`` 기준 범위로 분류한다."""
        if resource is None:
            return "none"
        normalized = resource.replace("\\", "/").strip("/")
        if normalized in {"", "."}:
            return "sandbox_root"
        if normalized == "data" or normalized.startswith("data/"):
            return "data"
        if "/" not in normalized:
            return "root_file"
        return "other_subdirectory"

    @classmethod
    def _permission_allows(cls, intent: ToolIntent) -> bool:
        """trust 검사 후 Day 4 v0.1 리소스·명령 규칙을 적용한다."""
        if intent.tool_name in {"calculator", "get_time"}:
            return bool(POLICY[intent.tool_name]["allowed"])

        if intent.tool_name in {"read_file", "write_file", "list_files"}:
            scope = cls._resource_scope(intent.resource)
            return scope in POLICY[intent.tool_name]["allowed_scopes"]

        if intent.tool_name != "run_command":
            return False
        if intent.action not in POLICY["run_command"]["allowed_commands"]:
            return False
        if intent.action == "pwd":
            return True
        delegated_tool = "read_file" if intent.action == "cat" else "list_files"
        scope = cls._resource_scope(intent.resource)
        return scope in POLICY[delegated_tool]["allowed_scopes"]


def adapt_legacy_authorizer(authorize: Callable[..., Any], policy: Any) -> Callable[[ToolIntent], tuple[bool, str | None]]:
    """점진적 마이그레이션 동안 이전 ``authorization.authorize``를 연결한다.

    v0.2.2 변형은 위치 인자 시그니처가 서로 달랐다. 이 함수에 그 차이를
    격리하고, 로컬 legacy 함수와 어댑터를 테스트한 뒤 동등한 정책 규칙이
    ``PolicyEngine``에 옮겨지면 제거한다.
    """
    def check(intent: ToolIntent) -> tuple[bool, str | None]:
        try:
            raw = authorize(intent.tool_name, dict(intent.arguments), policy)

        except TypeError:
            raw = authorize(intent.tool_name, dict(intent.arguments))

        if isinstance(raw, dict):
            return bool(raw.get("allowed")), raw.get("reason")

        return bool(raw), None if raw else "legacy authorization denied"

    return check
