"""Day 7 fixture의 sandbox reset과 증거 digest 기록 지원 함수.

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
from typing import Any

from Agent import SANDBOX_ROOT, build_runtime
from runtime import Runtime


def seed_manifest(sandbox_root: Path) -> list[dict[str, Any]]:
    """실행 전 sandbox 입력 파일의 결정론적 목록과 digest를 만든다."""
    entries: list[dict[str, Any]] = []
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
    fixture_id: str
    run_id: str
    root: Path
    sandbox_root: Path
    trace_path: Path
    runtime: Runtime
    seed_digest: str


def make_experiment_runtime(
    fixture_id: str, *, trace_path: Path, source_sandbox: Path = SANDBOX_ROOT,
) -> ExperimentRuntime:
    """seed sandbox을 복제하고 독립 Runtime과 `seed_snapshot`을 만든다."""
    run_id = f"run-{fixture_id.lower()}-{uuid.uuid4().hex}"
    root = Path(tempfile.mkdtemp(prefix=f"day7-{fixture_id.lower()}-"))
    sandbox_root = root / "sandbox"
    shutil.copytree(source_sandbox, sandbox_root)
    runtime = build_runtime(trace_path=trace_path, sandbox_root=sandbox_root)
    manifest = seed_manifest(sandbox_root)
    seed_digest = runtime.trace.digest(manifest)
    runtime.trace.emit(
        "seed_snapshot", run_id, fixture_id=fixture_id,
        seed_manifest=manifest, seed_digest=seed_digest,
    )
    return ExperimentRuntime(
        fixture_id, run_id, root, sandbox_root, trace_path, runtime, seed_digest,
    )


def record_run_evidence(experiment: ExperimentRuntime) -> dict[str, str]:
    """정책·결과 이벤트의 digest와 fixture ID를 trace 마지막에 저장한다."""
    events = list(experiment.runtime.trace.iter_events(run_id=experiment.run_id, strict=True))
    decisions = [event for event in events if event["event"] in {
        "policy_decision", "authorization_decision", "approval",
    }]
    results = [event for event in events if event["event"] == "runtime_result"]
    decision_digest = experiment.runtime.trace.digest(decisions)
    result_digest = experiment.runtime.trace.digest(results)
    experiment.runtime.trace.record_experiment_evidence(
        experiment.run_id,
        fixture_id=experiment.fixture_id,
        seed_digest=experiment.seed_digest,
        decision_digest=decision_digest,
        result_digest=result_digest,
    )
    return {
        "seed_digest": experiment.seed_digest,
        "decision_digest": decision_digest,
        "result_digest": result_digest,
    }
