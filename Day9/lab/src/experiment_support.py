"""Day 9 fixture의 최소 sandbox·ToolProfile·실험 증거 기록 지원 함수.

Agent나 Runtime은 이 모듈을 호출하지 않는다. test harness만 호출하므로 기존
실행 경계와 tool 흐름은 바뀌지 않는다.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import shutil
import tempfile
import uuid
from typing import Any, Iterable

from Agent import SANDBOX_ROOT, build_runtime
from runtime import Runtime
from security.capability import capability_mapping_snapshot
from security.permission import POLICY
from security.tool_schema import ToolProfile, WRITE_ENABLED_PROFILE, profile_snapshot
from security.trust import DEFAULT_TRUST_BY_PROVENANCE
from trace_logger import TraceLogger
from trace_reader import write_run_summary


def _relative_seed_path(raw_path: str) -> Path:
    relative = Path(raw_path.replace("\\", "/"))
    if relative.is_absolute() or ".." in relative.parts or not relative.parts:
        raise ValueError(f"seed path must stay inside sandbox: {raw_path}")
    return relative


def copy_seed_files(
    source_sandbox: Path,
    target_sandbox: Path,
    seed_files: Iterable[str],
) -> tuple[str, ...]:
    """fixture가 선언한 파일만 임시 sandbox로 복사한다."""
    source_root = source_sandbox.resolve()
    copied: list[str] = []
    target_sandbox.mkdir(parents=True, exist_ok=True)
    for raw_path in seed_files:
        relative = _relative_seed_path(raw_path)
        source = (source_root / relative).resolve()
        try:
            source.relative_to(source_root)
        except ValueError as exc:
            raise ValueError(f"seed path escapes source sandbox: {raw_path}") from exc
        if not source.is_file():
            raise FileNotFoundError(f"seed file not found: {relative.as_posix()}")
        target = target_sandbox / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        copied.append(relative.as_posix())
    return tuple(sorted(set(copied)))


def seed_manifest(
    sandbox_root: Path,
    seed_files: Iterable[str],
) -> list[dict[str, Any]]:
    """복사한 seed 파일만 읽어 결정론적 목록과 digest를 만든다."""
    entries: list[dict[str, Any]] = []
    for raw_path in sorted(set(seed_files)):
        relative = _relative_seed_path(raw_path)
        path = sandbox_root / relative
        if not path.is_file():
            raise FileNotFoundError(f"copied seed file not found: {relative.as_posix()}")
        entries.append({
            "path": relative.as_posix(),
            "size": path.stat().st_size,
            "sha256": sha256(path.read_bytes()).hexdigest(),
        })
    return entries


def _per_run_trace_path(base_path: Path, fixture_id: str, run_id: str) -> Path:
    trace_root = base_path if not base_path.suffix else base_path.parent / base_path.stem
    return trace_root / fixture_id / run_id / "trace.jsonl"


@dataclass(frozen=True)
class ExperimentRuntime:
    fixture_id: str
    run_id: str
    root: Path
    sandbox_root: Path
    trace_path: Path
    runtime: Runtime
    seed_digest: str
    seed_files: tuple[str, ...]
    summary_path: Path


def make_experiment_runtime(
    fixture_id: str, *, trace_path: Path, seed_files: Iterable[str] = (),
    source_sandbox: Path = SANDBOX_ROOT,
    tool_profile: ToolProfile = WRITE_ENABLED_PROFILE,
) -> ExperimentRuntime:
    """필요한 seed 파일만 복사하고 run별 Runtime과 trace를 만든다."""
    run_id = f"run-{fixture_id.lower()}-{uuid.uuid4().hex}"
    root = Path(tempfile.mkdtemp(prefix=f"day8-{fixture_id.lower()}-"))
    sandbox_root = root / "sandbox"
    copied = copy_seed_files(source_sandbox, sandbox_root, seed_files)
    run_trace_path = _per_run_trace_path(trace_path, fixture_id, run_id)
    runtime = build_runtime(
        trace_path=run_trace_path,
        sandbox_root=sandbox_root,
        tool_profile=tool_profile,
    )
    manifest = seed_manifest(sandbox_root, copied)
    seed_digest = runtime.trace.digest(manifest)
    runtime.trace.emit(
        "seed_snapshot", run_id, fixture_id=fixture_id,
        seed_manifest=manifest, seed_digest=seed_digest,
    )
    return ExperimentRuntime(
        fixture_id, run_id, root, sandbox_root, run_trace_path, runtime,
        seed_digest, copied, run_trace_path.with_name("summary.md"),
    )


def control_plane_state(runtime: Runtime) -> dict[str, Any]:
    """Policy·trust·capability·approval 상태의 사람이 읽을 수 있는 복사본."""
    return TraceLogger.canonicalize({
        "permission_policy": POLICY,
        "trust_policy": DEFAULT_TRUST_BY_PROVENANCE,
        "capability_mapping": capability_mapping_snapshot(),
        "mcp_tool_profile": profile_snapshot(runtime.tool_profile),
        "approval_records": runtime.approvals.audit_snapshot(),
    })


def record_control_plane_snapshot(
    experiment: ExperimentRuntime,
    *,
    phase: str,
) -> str:
    """공격 전후 보안 상태와 MCP profile digest를 trace에 남긴다."""
    if phase not in {"before", "after"}:
        raise ValueError("control-plane snapshot phase must be before or after")
    state = control_plane_state(experiment.runtime)
    digest = experiment.runtime.trace.digest(state)
    experiment.runtime.trace.emit(
        "control_plane_snapshot",
        experiment.run_id,
        fixture_id=experiment.fixture_id,
        phase=phase,
        control_plane_digest=digest,
        control_plane_state=state,
    )
    return digest


_VOLATILE_EVIDENCE_FIELDS = {
    "event_id",
    "timestamp",
    "run_id",
    "call_id",
    "received_at",
    "observation_id",
    "observation_ids",
    "parent_call_id",
    "parent_call_ids",
    "approval_id",
    "requested_at",
    "expires_at",
    # runtime_result 사건 안의 result_digest도 임의 approval ID를 포함할 수
    # 있으므로 재현성 digest에서는 원래 결과 필드를 다시 정규화한다.
    "result_digest",
}


def _without_volatile_evidence(value: Any) -> Any:
    """원본 trace는 유지하고 재현성 비교 입력에서 임의 시각·ID만 제거한다."""
    if isinstance(value, dict):
        return {
            key: _without_volatile_evidence(item)
            for key, item in value.items()
            if key not in _VOLATILE_EVIDENCE_FIELDS
        }
    if isinstance(value, list):
        return [_without_volatile_evidence(item) for item in value]
    return value


def _stable_event_projection(event: dict[str, Any]) -> dict[str, Any]:
    """중첩 provenance까지 재실행마다 달라지는 식별자·시각을 제외한다."""
    return _without_volatile_evidence(event)


def record_run_evidence(experiment: ExperimentRuntime) -> dict[str, Any]:
    """정책·결과 이벤트의 digest와 fixture ID를 trace 마지막에 저장한다."""
    events = list(experiment.runtime.trace.iter_events(run_id=experiment.run_id, strict=True))
    decisions = [event for event in events if event["event"] in {
        "tool_schema_decision", "policy_decision",
        "authorization_decision", "approval",
    }]
    results = [event for event in events if event["event"] == "runtime_result"]
    decision_digest = experiment.runtime.trace.digest(
        [_stable_event_projection(event) for event in decisions]
    )
    result_digest = experiment.runtime.trace.digest(
        [_stable_event_projection(event) for event in results]
    )
    snapshots = {
        event.get("phase"): event
        for event in events
        if event.get("event") == "control_plane_snapshot"
    }
    before_digest = snapshots.get("before", {}).get("control_plane_digest")
    after_digest = snapshots.get("after", {}).get("control_plane_digest")
    mutation = (
        before_digest != after_digest
        if before_digest is not None and after_digest is not None
        else None
    )
    experiment.runtime.trace.record_experiment_evidence(
        experiment.run_id,
        fixture_id=experiment.fixture_id,
        seed_digest=experiment.seed_digest,
        decision_digest=decision_digest,
        result_digest=result_digest,
        control_plane_before_digest=before_digest,
        control_plane_after_digest=after_digest,
        control_plane_mutation=mutation,
    )
    write_run_summary(experiment.trace_path, experiment.summary_path)
    evidence: dict[str, Any] = {
        "seed_digest": experiment.seed_digest,
        "decision_digest": decision_digest,
        "result_digest": result_digest,
        "trace_path": str(experiment.trace_path),
        "summary_path": str(experiment.summary_path),
    }
    if mutation is not None:
        evidence.update({
            "control_plane_before_digest": before_digest,
            "control_plane_after_digest": after_digest,
            "control_plane_mutation": mutation,
        })
    return evidence
