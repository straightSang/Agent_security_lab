"""원본 JSONL trace를 사람이 읽는 Markdown 요약으로 변환한다."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Iterable


EVENT_LABELS = {
    "seed_snapshot": "입력 상태",
    "control_plane_snapshot": "보안 상태",
    "validation": "형식 검사",
    "tool_intent": "실행 요청",
    "policy_decision": "정책 판단",
    "authorization_decision": "인가 판단",
    "approval": "승인 상태",
    "runtime_result": "최종 결과",
    "observation_created": "관찰 결과",
    "experiment_evidence": "실험 증거",
}

SUMMARY_FIELDS = {
    "seed_snapshot": ("seed_digest",),
    "control_plane_snapshot": ("phase", "control_plane_digest"),
    "validation": ("validation_allowed", "reason"),
    "tool_intent": ("actor", "tool_name", "capability", "action", "resource"),
    "policy_decision": ("policy_decision", "reason", "rule_id", "trust"),
    "authorization_decision": (
        "authorization_decision", "authorization_reason", "required_approver",
    ),
    "approval": ("approval", "approval_id", "required_approver"),
    "runtime_result": ("ok", "runtime_status", "end_stage", "error_code"),
    "observation_created": ("source_kind", "source_trust", "source"),
    "experiment_evidence": (
        "seed_digest", "decision_digest", "result_digest",
        "control_plane_mutation",
    ),
}


def read_trace(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_number} JSONL 형식 오류") from exc
    return events


def _display(value: Any) -> str:
    if isinstance(value, bool):
        return "참" if value else "거짓"
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value).replace("|", "\\|").replace("\n", " ")


def summarize_events(events: Iterable[dict[str, Any]]) -> str:
    items = list(events)
    if not items:
        raise ValueError("요약할 trace 사건이 없습니다")
    run_id = str(items[0].get("run_id", "알 수 없음"))
    fixture_id = next(
        (str(item["fixture_id"]) for item in items if item.get("fixture_id")),
        "없음",
    )
    lines = [
        f"# 실행 요약 — {fixture_id}",
        "",
        f"- 실행 번호: `{run_id}`",
        f"- 사건 수: {len(items)}",
        "",
        "| 순서 | 단계 | 호출 번호 | 핵심 내용 |",
        "|---:|---|---|---|",
    ]
    for index, event in enumerate(items, start=1):
        event_name = str(event.get("event", "unknown"))
        label = EVENT_LABELS.get(event_name, event_name)
        call_id = str(event.get("call_id", "-"))
        details = []
        for field in SUMMARY_FIELDS.get(event_name, ()):
            if field in event:
                details.append(f"{field}={_display(event[field])}")
        lines.append(
            f"| {index} | {label} | `{call_id}` | {'; '.join(details) or '-'} |"
        )
    lines.append("")
    lines.append("원본 JSONL은 같은 폴더의 `trace.jsonl`에 보존된다.")
    lines.append("")
    return "\n".join(lines)


def write_run_summary(trace_path: Path, output_path: Path | None = None) -> Path:
    destination = output_path or trace_path.with_name("summary.md")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        summarize_events(read_trace(trace_path)),
        encoding="utf-8",
    )
    return destination


def main() -> None:
    parser = argparse.ArgumentParser(description="JSONL trace를 Markdown으로 요약")
    parser.add_argument("trace_path", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = write_run_summary(args.trace_path, args.output)
    print(result)


if __name__ == "__main__":
    main()
