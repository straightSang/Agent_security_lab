"""Validation, 안전한 로컬 도구, 그리고 유일한 Runtime 실행 경계."""

from __future__ import annotations

import ast
import operator
import shlex
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from security.authorization import AuthorizationEngine
from security.approval import ApprovalStore
from security.capability import describe_intent
from security.policy import PolicyEngine
from security.provenance import Provenance
from security.tool_schema import ToolProfile, validate_tool_schema
from security.types import (
    ApprovalState,
    ApprovalStatus,
    AuthorizationOutcome,
    Decision,
    RuntimeResult,
    ToolIntent,
)
from trace_logger import TraceLogger

PATH_TOOLS = {"read_file", "write_file", "list_files"}

ARGUMENT_SPEC: dict[str, dict[str, type]] = {
    "calculator": {"expression": str},
    "read_file": {"path": str},
    "get_time": {},
    "write_file": {"path": str, "content": str},
    "list_files": {"path": str},
    "run_command": {"command": str},
}


def make_runtime_result(
    *, ok: bool, status: str, end_stage: str, tool_name: str, call_id: str,
    data: Any = None, error_code: str | None = None,
    error_message: str | None = None, meta_extra: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """``meta_extra``를 포함하는 v0.2.2 호환 result factory."""
    result = RuntimeResult(
        ok, status, end_stage, tool_name, call_id, data=data,
        error_code=error_code, error_message=error_message,
        security=dict(meta_extra or {}),
    )
    return result.to_dict()


def to_observation(runtime_result: Mapping[str, Any]) -> dict[str, Any]:
    """Runtime 상태와 LLM observation을 의도적으로 분리한다."""
    if runtime_result["ok"]:
        return {"status": "success", "data": runtime_result["data"]}
    return {
        "status": runtime_result["status"],
        "error": {
            "code": runtime_result.get("error", {}).get("code"),
            "message": runtime_result.get("error", {}).get("message"),
        },
    }


def safe_resolve(user_path: str, sandbox_root: Path) -> Path:
    candidate = (sandbox_root / user_path).resolve()
    try:
        candidate.relative_to(sandbox_root)
    except ValueError as exc:
        raise PermissionError(f"path escapes sandbox: {user_path}") from exc
    return candidate


def validate_arguments(tool_name: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(arguments, Mapping):
        return {"allowed": False, "reason": "arguments must be an object"}
    
    spec = ARGUMENT_SPEC.get(tool_name)

    if spec is None:
        return {"allowed": False, "reason": f"unknown tool: {tool_name}"}

    for name, expected_type in spec.items():
        if name not in arguments:
            return {"allowed": False, "reason": f"missing argument: {name}"}

        if not isinstance(arguments[name], expected_type):
            return {"allowed": False, "reason": f"argument '{name}' must be {expected_type.__name__}"}

    unexpected = set(arguments) - set(spec)

    if unexpected:
        return {"allowed": False, "reason": "unexpected arguments: " + ", ".join(sorted(unexpected))}
    return {"allowed": True, "reason": None}


def validate_tool_call(tool_name: str, arguments: Mapping[str, Any], sandbox_root: Path | None = None) -> dict[str, Any]:
    """구조 validation만 수행한다. 여기서는 policy/authorization을 판단하지 않는다."""
    root = (sandbox_root or Path("sandbox")).resolve()
    checked = validate_arguments(tool_name, arguments)

    if not checked["allowed"]:
        return {"allowed": False, "reason": checked["reason"], "resolved_path": None, "command_base": None}
    try:
        if tool_name in PATH_TOOLS:
            return {"allowed": True, "reason": None, "resolved_path": safe_resolve(str(arguments["path"]), root), "command_base": None}
        if tool_name != "run_command":
            return {"allowed": True, "reason": None, "resolved_path": None, "command_base": None}
        parts = shlex.split(str(arguments["command"]), posix=True)

        if not parts:
            return {"allowed": False, "reason": "empty command", "resolved_path": None, "command_base": None}
        command_base = parts[0]
        if command_base == "pwd" and len(parts) != 1:
            return {"allowed": False, "reason": "usage: pwd", "resolved_path": None, "command_base": command_base}

        if command_base == "cat":
            if len(parts) != 2:
                return {"allowed": False, "reason": "usage: cat <file>", "resolved_path": None, "command_base": command_base}
            return {"allowed": True, "reason": None, "resolved_path": safe_resolve(parts[1], root), "command_base": command_base}

        if command_base == "ls":
            if len(parts) > 2:
                return {"allowed": False, "reason": "usage: ls [path]", "resolved_path": None, "command_base": command_base}
            return {"allowed": True, "reason": None, "resolved_path": safe_resolve(parts[1] if len(parts) == 2 else ".", root), "command_base": command_base}
        # 알 수 없는 명령도 문법상 제안으로는 유효하다. Policy가 이를 거부한다.
        
        return {"allowed": True, "reason": None, "resolved_path": None, "command_base": command_base}

    except (PermissionError, ValueError) as exc:
        return {"allowed": False, "reason": str(exc), "resolved_path": None, "command_base": None}


_BINARY = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul, ast.Div: operator.truediv, ast.FloorDiv: operator.floordiv, ast.Mod: operator.mod, ast.Pow: operator.pow}
_UNARY = {ast.UAdd: operator.pos, ast.USub: operator.neg}


def _eval_arithmetic(node: ast.AST) -> int | float:
    if isinstance(node, ast.Expression):
        return _eval_arithmetic(node.body)

    if isinstance(node, ast.Constant) and type(node.value) in (int, float):
        return node.value

    if isinstance(node, ast.BinOp) and type(node.op) in _BINARY:
        left, right = _eval_arithmetic(node.left), _eval_arithmetic(node.right)

        if isinstance(node.op, ast.Pow) and abs(right) > 100:
            raise ValueError("exponent too large")

        return _BINARY[type(node.op)](left, right)

    if isinstance(node, ast.UnaryOp) and type(node.op) in _UNARY:
        return _UNARY[type(node.op)](_eval_arithmetic(node.operand))

    raise ValueError("unsupported expression")


def calculator(expression: str) -> str:
    if len(expression) > 500:
        raise ValueError("expression too long")
    return str(_eval_arithmetic(ast.parse(expression, mode="eval")))


class Runtime:
    """권위 있는 실행 경계. allow 또는 유효한 승인 요청만 실행한다."""

    def __init__(self, *, sandbox_root: Path, policy: PolicyEngine, approvals: ApprovalStore, trace_logger: TraceLogger, authorizer: AuthorizationEngine | None = None, tool_profile: ToolProfile) -> None:
        self.sandbox_root = sandbox_root.resolve()
        self.sandbox_root.mkdir(parents=True, exist_ok=True)
        self.policy = policy
        self.approvals = approvals
        self.trace = trace_logger
        self.authorizer = authorizer or AuthorizationEngine()
        self.tool_profile = tool_profile

    def execute_tool(self, *, tool_name: str, arguments: Mapping[str, Any], call_id: str, run_id: str, actor: str, provenance: Provenance, approval_id: str | None = None, agent_step: int | None = None, fixture_id: str | None = None) -> RuntimeResult:
        # 0. Day 9 MCP tool exposure/inputSchema gate
        schema_decision = validate_tool_schema(
            self.tool_profile, tool_name, arguments,
        )
        self.trace.record_tool_schema(
            run_id,
            call_id,
            actor=actor,
            fixture_id=fixture_id,
            decision=schema_decision,
        )
        schema_context = schema_decision.trace_fields()
        if not schema_decision.allowed:
            result = RuntimeResult.failure(
                "schema_denied",
                "tool_schema",
                tool_name,
                call_id,
                "MCP_TOOL_SCHEMA_DENIED",
                schema_decision.reason,
                security=schema_context,
            )
            self.trace.record_early_result(
                run_id,
                call_id,
                actor=actor,
                fixture_id=fixture_id,
                result=result,
            )
            return result

        # 1. 기존 Runtime Validation
        validation = validate_tool_call(tool_name, arguments, self.sandbox_root)
        
        if not validation["allowed"]:
            result = RuntimeResult.failure("validation_failed", "validation", tool_name, call_id, "INVALID_ARGUMENT", validation["reason"], security=schema_context)
            self.trace.record_validation(run_id, tool_name, call_id, provenance, validation, result, actor=actor, agent_step=agent_step, fixture_id=fixture_id)
            
            return result

        self.trace.record_validation(
            run_id,
            tool_name,
            call_id,
            provenance,
            validation,
            actor=actor,
            agent_step=agent_step,
            fixture_id=fixture_id,
        )

        capability, action, resource = describe_intent(tool_name, arguments, validation, self.sandbox_root)
        
        # 2. Generate ToolIntent 
        intent = ToolIntent(run_id=run_id, call_id=call_id, actor=actor, tool_name=tool_name, arguments=dict(arguments), provenance=provenance, capability=capability, action=action, resource=resource, agent_step=agent_step, fixture_id=fixture_id)
        
        self.trace.record_intent(intent)

        # 3. Policy Decision
        decision = self.policy.evaluate(intent)

        self.trace.record_policy(intent, decision)

        if decision.outcome is Decision.DENY:
            result = RuntimeResult.failure("denied", "policy", tool_name, call_id, "POLICY_DENIED", decision.reason, security={**schema_context, **decision.trace_fields()})
            
            self.trace.record_result(intent, result)

            return result

        # Day 5: Policy is a general rule. Authorization answers whether this
        # trusted actor may perform this action on this exact canonical resource.
        authorization = self.authorizer.authorize(intent)

        # 4. Authorization
        self.trace.record_authorization(intent, authorization)
        security_context = {
            **schema_context,
            **decision.trace_fields(),
            **authorization.trace_fields(),
        }

        # 1) DENY
        if authorization.outcome is AuthorizationOutcome.DENY:

            result = RuntimeResult.failure(
                "forbidden", "authorization", tool_name, call_id,
                "FORBIDDEN", authorization.reason, security=security_context,
            )
            self.trace.record_result(intent, result)
            return result

        # ALLOW 요청은 ApprovalStore를 조회할 이유가 없다. 쓰기처럼 정책이
        # APPROVAL_REQUIRED를 반환한 경우에만 승인 상태를 읽는다.
        approval_state = ApprovalState(None, ApprovalStatus.NOT_REQUIRED)

        # 2) APPROVAL_REQUIRED
        if decision.outcome is Decision.APPROVAL_REQUIRED:
            approval_state = self.approvals.resolve(approval_id)

            if approval_state.status is not ApprovalStatus.APPROVED or approval_state.intent_fingerprint != intent.fingerprint():
                
                if authorization.required_approver is None:

                    raise RuntimeError("approval-required authorization decision lacks required approver")
                       
                """
                만약 approved_id 가 안 맞으면
                새로운 pending approval record를 만들고 바로 반환한다.
                """
                pending = self.approvals.request(intent, decision, required_approver=authorization.required_approver)
                
                result = RuntimeResult.failure("approval_required", "approval", tool_name, call_id, "APPROVAL_REQUIRED", decision.reason, security={**security_context, "approval": pending.status.value, "approval_id": pending.approval_id, "required_approver": pending.required_approver})
                
                self.trace.record_approval(intent, pending)
                self.trace.record_result(intent, result)

                return result

            self.trace.record_approval(intent, approval_state)

        if decision.outcome is Decision.APPROVAL_REQUIRED:

            """
            consumed_now=True인 호출만 Dispatcher에 들어간다. 
            같은 approval ID를 다시 제출하면 이미 CONSUMED이므로 consumed_now=False가 되고 실행되지 않는다.
            consume()은 dispatch 직전에 approval을 일회용으로 바꾸는 단계이다. 승인이 재사용되지 않도록 한다.
            """
            approval_state, consumed_now = self.approvals.consume(
                approval_id or "",
                intent_fingerprint=intent.fingerprint(),
            )
            if not consumed_now:
                result = RuntimeResult.failure("approval_required", "approval", tool_name, call_id, "APPROVAL_NOT_USABLE", "approved approval was not usable", security={**security_context, "approval": approval_state.status.value, "approval_id": approval_state.approval_id, "required_approver": approval_state.required_approver})
               
                self.trace.record_approval(intent, approval_state)
                self.trace.record_result(intent, result)
                
                return result

            self.trace.record_approval(intent, approval_state)

        # 3) ALLOW, APPROVE_REQUIRED -> APPROVED
        """
        _dispatch()가 실제 도구 함수 호출이다.
        : Validation, Policy, Authorization, Approval 조건을 모두 통과해야 한다.
        """
        try:
            data = self._dispatch(intent, validation)
            
            result = RuntimeResult.success(tool_name, call_id, data, security={**security_context, "approval": approval_state.status.value, "approval_id": approval_state.approval_id, "required_approver": approval_state.required_approver})
        
        except Exception as exc:  # 도구 오류를 매핑하며 세부 정보는 로컬에 둔다.
            code = "NOT_FOUND" if isinstance(exc, FileNotFoundError) else "EXECUTION_ERROR"
            result = RuntimeResult.failure("execution_failed", "runtime", tool_name, call_id, code, str(exc), security={**security_context, "approval": approval_state.status.value, "approval_id": approval_state.approval_id, "required_approver": approval_state.required_approver})
        
        self.trace.record_result(intent, result)
        
        return result


    def _dispatch(self, intent: ToolIntent, validation: Mapping[str, Any]) -> str:
        path = validation["resolved_path"]

        if intent.tool_name == "calculator":
            return calculator(str(intent.arguments["expression"]))

        if intent.tool_name == "get_time":
            return datetime.now(timezone.utc).isoformat()

        if intent.tool_name == "read_file":
            return self._read_file(path)

        if intent.tool_name == "write_file":
            return self._write_file(path, str(intent.arguments["content"]))

        if intent.tool_name == "list_files":
            return self._list_files(path)

        if intent.tool_name == "run_command":
            return self._run_command(str(validation["command_base"]), path)
        raise RuntimeError("unknown tool reached dispatch")

    def _read_file(self, path: Path) -> str:

        if not path.is_file():
            raise FileNotFoundError(f"file not found: {path.name}")

        return path.read_text(encoding="utf-8")

    def _write_file(self, path: Path, content: str) -> str:

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

        return f"Wrote file: {path.relative_to(self.sandbox_root).as_posix()}"


    def _list_files(self, path: Path) -> str:
        if not path.is_dir():
            raise NotADirectoryError("not a directory")

        return "\n".join(sorted(child.relative_to(self.sandbox_root).as_posix() for child in path.iterdir()))


    def _run_command(self, command_base: str, path: Path | None) -> str:

        if command_base == "pwd":
            return "sandbox"

        if command_base == "ls" and path is not None:
            return self._list_files(path)

        if command_base == "cat" and path is not None:
            return self._read_file(path)

        raise RuntimeError("policy/runtime mismatch: command reached execution")
