# 모듈이름: trace_reader
# 역할: 원본 JSONL trace를 사람이 읽는 Markdown 요약으로 변환한다
# 호출 주체: experiment_support(실험 종료 시), 명령행
#
# 기능 설명:
#     기계가 읽는 증거(trace.jsonl)와 사람이 읽는 요약(summary.md)을 분리한다.
#
#     증거는 빠짐없이 남아야 하고 요약은 읽을 수 있어야 한다. 두 요구를 한 파일로
#     만족시키려 하면 증거가 줄거나 요약이 못 읽을 것이 된다.
#
#     보고서가 인용하는 것은 언제나 원시 JSONL이다. 이 모듈의 출력은 파생물이며,
#     둘이 어긋나면 원시 기록이 기준이다.

from __future__ import annotations

import argparse
import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

EVENT_LABELS = {
    "seed_snapshot": "입력 상태",
    "control_plane_snapshot": "보안 상태",
    "tool_schema_decision": "MCP 도구 스키마",
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
    "tool_schema_decision": (
        "tool_schema_decision", "tool_schema_reason", "tool_profile",
        "declared_capability",
    ),
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


# 함수이름: read_trace
# 인자:
#     path (Path): JSONL trace 파일 경로
# 반환값:
#     list[dict]: 파싱된 이벤트 목록
#     ValueError: JSONL 형식이 깨진 줄이 있을 때 줄 번호와 함께 발생
# 기능 설명:
#     trace 파일을 읽어 이벤트 목록으로 만든다.
#
#     한 줄이라도 읽지 못하면 그 증거는 불완전하다. 조용히 건너뛰면 누락된
#     판정이 있는데도 요약은 정상으로 보인다. 줄 번호를 붙여 즉시 실패한다.
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


# 함수이름: _display
# 인자:
#     value (Any): 표시할 값
# 반환값:
#     str: 사람이 읽기 좋은 짧은 문자열
# 기능 설명:
#     요약 표에 넣을 값을 한 줄로 다듬는다. 원본 trace는 그대로 두고 표시만
#     바꾼다.
def _display(value: Any) -> str:
    if isinstance(value, bool):
        return "참" if value else "거짓"
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value).replace("|", "\\|").replace("\n", " ")


# 함수이름: summarize_events
# 인자:
#     events (Iterable[dict]): trace 이벤트들
# 반환값:
#     str: Markdown 형식의 요약 본문
# 기능 설명:
#     사건을 순서대로 훑어 한국어 라벨과 핵심 필드만 표로 만든다.
#
#     SUMMARY_FIELDS에 사건별로 선언한 필드만 쓴다. 전부 보여 주면 사람이 읽는
#     의미가 없어진다. 원시 정보가 필요하면 같은 디렉터리의 trace.jsonl을 본다.
#
#     보고서가 인용하는 근거는 언제나 원시 JSONL이다. 이 파일은 읽기 편의를 위한
#     파생물이며, 둘이 어긋나면 원시 기록이 기준이다.
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


# 함수이름: write_run_summary
# 인자:
#     trace_path (Path): 원시 JSONL 경로
#     output_path (Path): 요약 Markdown 출력 경로
# 반환값:
#     Path: 실제로 쓴 요약 파일 경로
# 기능 설명:
#     한 run의 요약 파일을 만든다. experiment_support가 실험 종료 시 호출한다.
#
#     원시 JSONL과 같은 run 디렉터리에 나란히 둔다. 기계용과 사람용이 함께
#     이동해야 나중에 둘이 어긋나지 않는다.
def write_run_summary(trace_path: Path, output_path: Path | None = None) -> Path:
    destination = output_path or trace_path.with_name("summary.md")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        summarize_events(read_trace(trace_path)),
        encoding="utf-8",
    )
    return destination


# 함수이름: main
# 인자: 없음 (명령행 인자를 argparse로 읽는다)
# 반환값:
#     None: 반환값 없음. 요약 파일을 쓰는 부작용이 있다
# 기능 설명:
#     명령행에서 직접 요약을 만들 때 쓰는 진입점이다.
#
#     실험 중이 아니라 사후에 특정 trace를 다시 읽어 볼 때 쓴다.
def main() -> None:
    parser = argparse.ArgumentParser(description="JSONL trace를 Markdown으로 요약")
    parser.add_argument("trace_path", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = write_run_summary(args.trace_path, args.output)
    print(result)


if __name__ == "__main__":
    main()
