# 모듈이름: agent
# 역할: 유일한 공개 진입점. 도구 제안을 Runtime 경계로 보내는 얇은 층
# 호출 주체: tests/, experiment_support
#
# ===========================================================================

#     execute_tool()     도구 제안 하나를 여섯 관문으로 보낸다
#     build_runtime()    격리된 Runtime 하나를 만든다
#     run_agent_loop()   모델을 실제 실행 루프에 넣는다 (W1 D4에서 사용)
#
# 그 밖의 이름은 모두 내부 구현이다. __all__에 없으면 밖에서 쓰지 않는다.
# 필요한 것은 원래 정의된 모듈에서 직접 가져간다. 예를 들어
# validate_tool_call은 runtime에서, ToolProfile은 security.tool_schema에서.
#
# [왜 공개 표면을 3개로 줄였는가 — RFC-001]
#     이 저장소는 "도구가 실행되는 지점은 _dispatch() 하나뿐"이라고 주장한다.
#     그 주장을 검증하려는 사람은 공개된 진입점을 전부 확인해야 한다. 이전에는
#     __all__에 14개가 올라가 있었고 그중 12개는 아무도 import하지 않았다.
#     실제 인터페이스는 2개인데 감사 비용은 14개어치였다.
#
#     그 12개에는 "Day 1~8 호환용"이라는 주석이 붙어 있었다. 그러나 Day 1~8
#     코드는 이 저장소에 없다. 단일 트리로 옮기면서 AI_security_Lab에 남겨
#     뒀다. 즉 어댑터가 가리키는 대상이 존재하지 않았다.
#
#     tests/test_public_api_interface.py가 이 상태를 회귀로 고정한다.
#
# 기능 설명:
#     이 모듈은 ID 발급과 기본값 채우기만 한다. 허용 여부는 전부 Runtime이
#     정한다. 진입점이 판단을 시작하면 정책이 두 곳으로 갈라지고, 그 순간
#     어느 쪽이 진짜 규칙인지 알 수 없게 된다.
#
#     - [A-03] import 시점에 전역 Runtime을 만들지 않는다(지연 생성)
#     - [A-02] run_agent_loop() 추가. 모델을 실제로 루프에 넣는다
#     - [A-12] 모델 이름 기본값 제거

from __future__ import annotations

import json
import os
import uuid
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from lab_paths import SANDBOX_ROOT, trace_root
from runtime import Runtime, to_observation
from security.approval import ApprovalStore
from security.authorization import AuthorizationEngine
from security.policy import PolicyEngine
from security.provenance import direct_user_provenance, observation_provenance
from security.tool_schema import READ_ONLY_PROFILE, ToolProfile, tools_for_openai
from trace_logger import TraceLogger

# [RFC-001] 공개 인터페이스. 이 목록에 없는 이름은 내부 구현이다.
# tests/test_public_api_interface.py가 각 항목이 실제로 쓰이는지 검사한다.
__all__ = [
    "build_runtime",
    "execute_tool",
    "run_agent_loop",
]

# [C3] TOOLS / READ_ONLY_TOOLS / WRITE_ENABLED_TOOLS를 삭제했다.
#
# 이 세 개는 모델에게 광고할 도구 정의 목록(OpenAI 형식 list[dict])이었고,
# schema 검사에 쓰이는 ToolProfile과는 다른 물건이다. 이름이 비슷해
# 혼동을 부르기까지 했다.
#
#     security.tool_schema.READ_ONLY_PROFILE   ToolProfile  ← 검사에 쓰인다
#     agent.READ_ONLY_TOOLS                    list[dict]   ← 광고용이었다
#
# 광고 목록은 노출 프로필이 정해지는 시점에 만드는 것이 맞다. 모듈 최상위에
# 상수로 굳혀 두면 프로필과 목록이 어긋날 수 있다. 필요한 곳에서
# tools_for_openai(PROFILE)로 즉석 생성한다 — run_agent_loop()가 그렇게 한다.


# 함수이름: build_runtime
# 인자:
#     trace_path (Path | None): trace 출력 경로. 기본값 None이면 임시 디렉터리
#     sandbox_root (Path): 파일 접근 루트. 기본값은 저장소의 sandbox/
#     tool_profile (ToolProfile): 노출할 도구 집합. 기본값 READ_ONLY_PROFILE
# 반환값:
#     Runtime: 정책·인가·승인·trace가 모두 새로 만들어진 실행 경계
# 기능 설명:
#     API key 없이 동작하는 로컬 testbed Runtime을 구성한다.
#
#     최소권한이 기본이어야 한다. 쓰기가 필요하면 호출자가 명시적으로
#     WRITE_ENABLED_PROFILE을 골라야 한다. 실수로 넓은 권한이 열리지 않는다.
def build_runtime(
    *,
    trace_path: Path | None = None,
    sandbox_root: Path = SANDBOX_ROOT,
    tool_profile: ToolProfile = READ_ONLY_PROFILE,
) -> Runtime:
    return Runtime(
        sandbox_root=sandbox_root,
        policy=PolicyEngine(),
        approvals=ApprovalStore(),
        trace_logger=TraceLogger(trace_path or (trace_root() / "agent_default.jsonl")),
        authorizer=AuthorizationEngine(),
        tool_profile=tool_profile,
    )


_DEFAULT_RUNTIME: Runtime | None = None


# 함수이름: get_default_runtime
# 인자: 없음
# 반환값:
#     Runtime: 프로세스 전역 기본 Runtime. 첫 호출 때 생성된다
# 기능 설명:
#     [A-03] 첫 호출 시점에만 기본 Runtime을 만든다.
#
#     이전에는 모듈 최상위에서 즉시 생성했다. 그 결과 agent를 import하는 것만
#     으로 sandbox 디렉터리가 생기고 승인 저장소가 프로세스 전역에 공유됐다.
#     import 부작용은 재현성과 테스트 격리를 동시에 해친다.
#
#     experiment_support.make_experiment_runtime()으로 run마다 독립된 Runtime과
#     sandbox를 받는 것을 권장한다.
def get_default_runtime() -> Runtime:
    global _DEFAULT_RUNTIME
    if _DEFAULT_RUNTIME is None:
        _DEFAULT_RUNTIME = build_runtime()
    return _DEFAULT_RUNTIME


# 함수이름: reset_default_runtime
# 인자: 없음
# 반환값:
#     None: 반환값 없음. 전역 참조를 비우는 부작용이 있다
# 기능 설명:
#     테스트가 전역 상태를 명시적으로 버릴 수 있게 한다. 다음 호출에서 새
#     Runtime이 만들어진다.
def reset_default_runtime() -> None:
    global _DEFAULT_RUNTIME
    _DEFAULT_RUNTIME = None


# 함수이름: execute_tool
# 인자:
#     tool_name (str): 제안된 도구 이름
#     arguments (Mapping): 제안된 인자
#     call_id (str | None): 호출 식별자. 기본값 None이면 새로 발급
#     run_id (str | None): 실행 식별자. 기본값 None이면 새로 발급
#     actor (str): 인증된 주체. 기본값 'local-user'
#     provenance: 입력 문맥. 기본값 None이면 direct_user_provenance()
#     approval_id (str | None): 이미 받은 승인 ID. 기본값 None
#     agent_step (int | None): 몇 번째 turn인가. 기본값 None
#     fixture_id (str | None): 실험 케이스 라벨. 기본값 None
#     runtime (Runtime | None): 사용할 Runtime. 기본값 None이면 전역 기본값
# 반환값:
#     dict: RuntimeResult.to_dict()의 결과
# 기능 설명:
#     도구 제안을 Runtime의 여섯 관문으로 보내는 유일한 진입점이다.
#
#     ID를 채우고 기본값을 붙일 뿐, 허용 여부는 전부 Runtime이 정한다. 진입점이
#     판단을 하기 시작하면 판정 로직이 두 곳으로 갈라진다.
#
#     둘 다 호출자가 명시적으로 제공한다. 어느 것도 LLM이 만든 문자열에서
#     유도하지 않는다. 모델이 자기 출처나 승인을 주장할 수 있으면 두 방어가
#     동시에 무너진다.
def execute_tool(
    tool_name: str,
    arguments: Mapping[str, Any],
    call_id: str | None = None,
    *,
    run_id: str | None = None,
    actor: str = "local-user",
    provenance=None,
    approval_id: str | None = None,
    agent_step: int | None = None,
    fixture_id: str | None = None,
    runtime: Runtime | None = None,
) -> dict[str, Any]:
    active_runtime = runtime or get_default_runtime()
    return active_runtime.execute_tool(
        tool_name=tool_name,
        arguments=dict(arguments),
        call_id=call_id or f"call_{uuid.uuid4().hex}",
        run_id=run_id or f"run_{uuid.uuid4().hex}",
        actor=actor,
        provenance=provenance or direct_user_provenance(),
        approval_id=approval_id,
        agent_step=agent_step,
        fixture_id=fixture_id,
    ).to_dict()


# ---------------------------------------------------------------------------
# [A-02] Model-in-the-loop
# ---------------------------------------------------------------------------

MAX_AGENT_STEPS = 8


# 함수이름: run_agent_loop
# 인자:
#     user_task (str): 사용자 과제 문장
#     runtime (Runtime): 이 실행에 쓸 Runtime. 키워드 필수 인자다
#     actor (str): 인증된 주체. 기본값 'local-user'
#     run_id (str | None): 실행 식별자. 기본값 None이면 새로 발급
#     model (str | None): 모델 이름. 기본값 None이면 LAB_MODEL 환경변수
#     tool_profile (ToolProfile): 노출할 도구. 기본값 READ_ONLY_PROFILE
#     max_steps (int): 최대 반복 횟수. 기본값 MAX_AGENT_STEPS(8)
#     propose (Callable | None): 제안기 주입. 기본값 None이면 실제 모델 사용
# 반환값:
#     dict: {'run_id', 'steps', 'final_text', 'tool_results'}
#         tool_results의 각 항목은 execute_tool()의 반환 dict 그대로다
# 기능 설명:
#     [A-02] 모델의 도구 제안을 Runtime 경계로 되돌리는 반복 루프다.
#
#     Day 9까지 모든 실험은 도구 제안을 fixture에 사람이 적어 넣었다. 따라서
#     검증된 것은 "정책 엔진이 주어진 제안을 올바르게 판정한다"였고, "실제
#     모델이 비신뢰 콘텐츠에 넘어가 어떤 제안을 만드는가"는 측정된 적이 없다.
#     전자는 정책 엔진 테스트이고 후자가 AI 보안 연구다.
#
#     - 도구 실행은 예외 없이 execute_tool()을 통과한다. 모델은 우회할 수 없다
#     - 관측값의 provenance는 Runtime이 부여한다. 모델이 덮어쓰지 못한다
#     - 도구 결과는 to_observation()으로 정제해 전달한다
#     - propose를 주입하면 모델 없이도 같은 루프를 결정론적으로 재현할 수 있다
#
#     첫 제안은 사용자 과제에서 나오므로 USER_CONTROLLED다. 이후 제안은 직전
#     관측값을 본 뒤에 나온 것이므로 UNTRUSTED다. 이 구분이 없으면 파일을 읽은
#     뒤의 제안이 사용자 지시처럼 취급된다.
#
#     모델이 도구를 무한히 제안할 수 있다. 가용성도 보호 대상이다.
def run_agent_loop(
    user_task: str,
    *,
    runtime: Runtime,
    actor: str = "local-user",
    run_id: str | None = None,
    model: str | None = None,
    tool_profile: ToolProfile = READ_ONLY_PROFILE,
    max_steps: int = MAX_AGENT_STEPS,
    propose: Callable[[list[dict[str, Any]]], list[dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    run_id = run_id or f"run_{uuid.uuid4().hex}"
    tools = tools_for_openai(tool_profile)
    conversation: list[dict[str, Any]] = [{"role": "user", "content": user_task}]
    tool_results: list[dict[str, Any]] = []

    proposer = propose or _openai_proposer(model=model, tools=tools)

    for step in range(1, max_steps + 1):
        calls = proposer(conversation)
        if not calls:
            break

        for call in calls:
            call_id = call.get("call_id") or f"call_{uuid.uuid4().hex}"
            # 첫 단계의 제안은 사용자 과제에서 나온다. 이후 단계의 제안은 직전
            # 관측값을 본 뒤에 나온 것이므로 비신뢰 provenance를 부여한다.
            provenance = (
                direct_user_provenance()
                if step == 1
                else observation_provenance("agent_observation", parent_event_id=call_id)
            )
            result = execute_tool(
                call["tool_name"],
                call.get("arguments", {}),
                call_id,
                run_id=run_id,
                actor=actor,
                provenance=provenance,
                agent_step=step,
                runtime=runtime,
            )
            tool_results.append(result)
            conversation.append({
                "role": "tool",
                "call_id": call_id,
                "content": json.dumps(to_observation(result), ensure_ascii=False),
            })

    final_text = ""
    for message in reversed(conversation):
        if message.get("role") == "assistant" and message.get("content"):
            final_text = str(message["content"])
            break

    return {
        "run_id": run_id,
        "steps": len(tool_results),
        "final_text": final_text,
        "tool_results": tool_results,
    }


# 함수이름: _openai_proposer
# 인자:
#     model (str | None): 모델 이름. None이면 LAB_MODEL 환경변수를 읽는다
#     tools (list[dict]): 모델에게 광고할 도구 목록
# 반환값:
#     Callable: conversation을 받아 도구 호출 목록을 돌려주는 제안기 함수
#     RuntimeError: openai 미설치 · API key 없음 · 모델명 미지정 시 발생
# 기능 설명:
#     Responses API를 '제안기'로 감싼다. 실행 권한은 주지 않는다.
#
#     [A-12] 모델 이름에 기본값을 두지 않는다. 재현에는 model 버전 고정이
#     필수이고, 코드의 기본값과 보고서의 기록이 어긋나면 재현이 불가능해진다.
#     사용한 모델명은 실험 보고서의 환경 절에 반드시 적는다.
#
#     빈 인자로 넘겨 schema gate가 거부하게 둔다. 여기서 고쳐 주면 "모델이 잘못된
#     제안을 했다"는 관측 자체가 사라진다. 측정 대상을 하니스가 보정하면 안 된다.
def _openai_proposer(*, model: str | None, tools: list[dict[str, Any]]):

    def propose(conversation: list[dict[str, Any]]) -> list[dict[str, Any]]:
        try:
            from openai import OpenAI
        except ImportError as exc:  # pragma: no cover - 환경 의존
            raise RuntimeError(
                "model-in-the-loop 실험에는 openai 패키지가 필요하다. "
                "requirements.txt를 설치하거나 propose= 인자로 결정론적 제안기를 주입하라."
            ) from exc

        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise RuntimeError("OPENAI_API_KEY is required for the model-in-the-loop experiment")

        model_name = model or os.environ.get("LAB_MODEL")
        if not model_name:
            raise RuntimeError(
                "model을 명시하라. 재현에는 model 버전 고정이 필수이므로 기본값을 두지 않는다."
            )

        client = OpenAI(api_key=api_key)
        response = client.responses.create(model=model_name, input=conversation, tools=tools)

        calls: list[dict[str, Any]] = []
        for item in getattr(response, "output", []) or []:
            if getattr(item, "type", None) != "function_call":
                continue
            raw_arguments = getattr(item, "arguments", "{}")
            try:
                arguments = json.loads(raw_arguments) if isinstance(raw_arguments, str) else dict(raw_arguments)
            except json.JSONDecodeError:
                # 모델이 만든 인자가 JSON이 아니면 제안 자체가 무효다. 여기서
                # 교정하지 않고 그대로 거부되도록 빈 인자를 넘겨 schema gate에
                # 판정을 맡긴다.
                arguments = {}
            calls.append({
                "tool_name": getattr(item, "name", "unknown"),
                "arguments": arguments,
                "call_id": getattr(item, "call_id", None),
            })
        conversation.append({"role": "assistant", "content": getattr(response, "output_text", "")})
        return calls

    return propose
