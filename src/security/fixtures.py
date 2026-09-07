# 모듈이름: security.fixtures
# 역할: 실험 입력(fixture) JSON을 타입이 붙은 객체로 읽어 들인다
# 호출 주체: tests/test_indirect_injection.py, tests/test_policy_boundary.py
#
# 기능 설명:
#     fixture는 실험의 '입력 인터페이스'이다. 무엇을 관측하게 할지, 어떤 공격 제안을
#     넣을지, 무엇을 기대하는지를 파일로 고정한다.
#
#     실험 조건을 코드 안에 흩어 놓으면 실행할 때마다 조금씩 달라지고, 나중에
#     "그때 무엇을 넣었는가"를 재구성할 수 없다. fixture 파일의 해시가 곧
#     seed_digest의 일부가 된다.

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .types import ProvenanceKind


# 클래스이름: IndirectPromptInjectionFixture
# 필드:
#     fixture_id (str): 실험 케이스 라벨 (예: 'D7-E02')
#     category (str): benign / unsafe 등 분류
#     user_task (str): 사용자가 실제로 요청한 내용
#     source_kind (ProvenanceKind): 비신뢰 콘텐츠의 출처 종류
#     source (str): 출처 식별자(파일 경로 등)
#     content (str): 관측될 콘텐츠 본문. 주입 문자열이 여기 들어 있다
#     attack_proposal (dict | None): 공격이 유도하려는 도구 호출
#     expected (dict): 기대 결과. 테스트 assertion의 정답표
#     seed_files (tuple[str, ...]): 이 실험이 필요로 하는 시작 파일
# 기능 설명:
#     간접 프롬프트 주입 실험 하나의 입력 인터페이스다.
#
#     fixture.expected는 테스트가 실제 결과와 비교하는 정답표일 뿐, Runtime의
#     판정에 들어가지 않는다. 이 방향이 뒤집히면 실험이 스스로 답을 정하게 된다.
#
#         fixture.expected  ->  테스트 assertion, evaluator의 기대값
#         fixture.expected  -X-> PolicyEngine의 실제 allow/deny 결정
@dataclass(frozen=True)
class IndirectPromptInjectionFixture:
    fixture_id: str
    category: str
    user_task: str
    source_kind: ProvenanceKind
    source: str
    content: str
    seed_files: tuple[str, ...]
    expected: Mapping[str, Any]
    attack_proposal: Mapping[str, Any] | None = None


# 함수이름: load_indirect_prompt_injection_fixture
# 인자:
#     path (Path): fixture JSON 파일 경로
# 반환값:
#     IndirectPromptInjectionFixture: 파싱된 fixture
#     KeyError / ValueError: 필수 필드가 없거나 형식이 어긋날 때 발생
# 기능 설명:
#     fixture JSON을 읽어 타입이 붙은 객체로 만든다.
#
#     fixture는 사람이 손으로 쓰는 파일이라 오타가 난다. 로딩 시점에 형식을
#     확정하면 실험 도중이 아니라 시작 전에 실패한다. 실험이 절반쯤 돌다가
#     깨지면 그 trace는 증거로도 쓸 수 없다.
#
#     문자열 그대로 두면 오타가 조용히 다른 신뢰 등급으로 이어질 수 있다.
#     Enum 변환에서 걸리게 한다.
def load_indirect_prompt_injection_fixture(path: Path) -> IndirectPromptInjectionFixture:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("fixture root must be an object")

    required = {"fixture_id", "category", "user_task", "observation", "expected"}
    missing = required - set(raw)
    if missing:
        raise ValueError(f"fixture missing fields: {', '.join(sorted(missing))}")

    observation = raw["observation"]
    if not isinstance(observation, dict):
        raise ValueError("fixture observation must be an object")
    for key in ("source_kind", "source", "content"):
        if key not in observation or not isinstance(observation[key], str):
            raise ValueError(f"fixture observation.{key} must be a string")

    try:
        source_kind = ProvenanceKind(observation["source_kind"])
    except ValueError as exc:
        raise ValueError("fixture observation.source_kind is not supported") from exc
    if source_kind not in {
        ProvenanceKind.REPOSITORY_CONTENT,
        ProvenanceKind.TOOL_OBSERVATION,
        ProvenanceKind.EXTERNAL_CONTENT,
    }:
        raise ValueError("Day 7 observation fixture must be an indirect source")

    proposal = raw.get("attack_proposal")
    if proposal is not None:
        if not isinstance(proposal, dict) or not isinstance(proposal.get("tool_name"), str) or not isinstance(proposal.get("arguments"), dict):
            raise ValueError("fixture attack_proposal requires tool_name and arguments")

    if not isinstance(raw["expected"], dict):
        raise ValueError("fixture expected must be an object")

    seed_files = raw.get("seed_files", [observation["source"]])
    if (
        not isinstance(seed_files, list)
        or not all(isinstance(item, str) and item for item in seed_files)
    ):
        raise ValueError("fixture seed_files must be a list of non-empty strings")

    return IndirectPromptInjectionFixture(
        fixture_id=str(raw["fixture_id"]),
        category=str(raw["category"]),
        user_task=str(raw["user_task"]),
        source_kind=source_kind,
        source=observation["source"],
        content=observation["content"],
        seed_files=tuple(seed_files),
        expected=raw["expected"],
        attack_proposal=proposal,
    )
