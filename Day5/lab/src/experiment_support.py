"""Reproducible Day 5 experiment setup and evidence capture.

The test harness, not the Agent, calls these functions.  Each experiment gets
an isolated sandbox copy so a previous write cannot change a later fixture.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import shutil
import tempfile
import uuid
from typing import Any

from Agent import SANDBOX_ROOT, build_runtime
from runtime import Runtime


def seed_manifest(sandbox_root: Path) -> list[dict[str, Any]]:
    """Return a deterministic manifest of the input filesystem before a run."""
    entries: list[dict[str, str]] = []
    for path in sorted(sandbox_root.rglob("*")):
        if path.is_file():
            entries.append({
                "path": path.relative_to(sandbox_root).as_posix(),
                "size": path.stat().st_size,
                "sha256": sha256(path.read_bytes()).hexdigest(),
            })
    return entries


@dataclass(frozen=True)
class ExperimentRuntime:
    run_id: str
    root: Path
    sandbox_root: Path
    trace_path: Path
    runtime: Runtime
    seed_digest: str


def make_experiment_runtime(label: str, *, run_id: str | None = None,
                            source_sandbox: Path = SANDBOX_ROOT,
                            trace_path: Path | None = None) -> ExperimentRuntime:
    """Copy the seed sandbox, create an independent Runtime and record its seed."""
    active_run = run_id or f"run-{label}-{uuid.uuid4().hex}"
    root = Path(tempfile.mkdtemp(prefix=f"day5-{label}-"))
    sandbox = root / "sandbox"
    shutil.copytree(source_sandbox, sandbox)
    active_trace_path = trace_path or root / "trace.jsonl"
    runtime = build_runtime(trace_path=active_trace_path, sandbox_root=sandbox)
    manifest = seed_manifest(sandbox)
    digest = runtime.trace.digest(manifest)
    runtime.trace.emit("seed_snapshot", active_run, seed_manifest=manifest, seed_digest=digest)
    return ExperimentRuntime(active_run, root, sandbox, active_trace_path, runtime, digest)


def continue_experiment(experiment: ExperimentRuntime, label: str) -> ExperimentRuntime:
    """Create a new run ID while deliberately sharing the Runtime/approval state."""
    run_id = f"run-{label}-{uuid.uuid4().hex}"
    manifest = seed_manifest(experiment.sandbox_root)
    digest = experiment.runtime.trace.digest(manifest)
    experiment.runtime.trace.emit("seed_snapshot", run_id, seed_manifest=manifest, seed_digest=digest)
    return ExperimentRuntime(run_id, experiment.root, experiment.sandbox_root,
                             experiment.trace_path, experiment.runtime, digest)


def record_run_evidence(experiment: ExperimentRuntime) -> dict[str, str]:
    """Hash policy and Runtime result events after the fixture has finished."""
    events = list(experiment.runtime.trace.iter_events(run_id=experiment.run_id, strict=True))
    decisions = [event for event in events if event["event"] in {"policy_decision", "authorization_decision", "approval"}]
    results = [event for event in events if event["event"] == "runtime_result"]
    decision_digest = experiment.runtime.trace.digest(decisions)
    result_digest = experiment.runtime.trace.digest(results)
    experiment.runtime.trace.record_experiment_evidence(
        experiment.run_id, seed_digest=experiment.seed_digest,
        decision_digest=decision_digest, result_digest=result_digest,
    )
    return {"seed_digest": experiment.seed_digest, "decision_digest": decision_digest,
            "result_digest": result_digest}
