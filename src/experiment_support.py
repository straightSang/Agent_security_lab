# 모듈이름: experiment_support
# 역할: 실험 하니스 — 실험 1회분의 환경·상태·증거를 만들어 주는 지원 층
# 호출 주체: tests/ 아래 회귀 스위트만. agent.py와 runtime.py는 호출하지 않는다
#
# 기능 설명:
#     보안 판정을 하는 곳이 아니라 실험을 재현 가능하게 만드는 곳이다.
#     화학 실험의 조교에 해당하며, 실험할 때마다 필요한 다섯 가지를 대신 한다.
#
#         1. 깨끗한 비커를 새로 꺼낸다     → 임시 sandbox 디렉터리 생성
#         2. 오늘 쓸 시약만 계량해 놓는다  → fixture가 선언한 seed 파일만 복사
#         3. 실험 전 상태를 사진 찍는다    → control-plane snapshot (before)
#         4. 실험 후 상태를 사진 찍는다    → control-plane snapshot (after)
#         5. 실험 노트에 결과를 적는다     → seed/decision/result digest 기록
#
#     반응 자체(도구가 실제로 실행되는 것)는 runtime.py가 한다.
#
#     [의존 방향 — 반드시 한 방향]
#
#         tests/  →  experiment_support  →  agent / runtime / security
#                                                ↑
#                              여기서 experiment_support를 부르면 안 된다
#
#     Runtime이 이 모듈을 import하면 실험용 코드가 실제 실행 경로 안으로 들어온
#     것이고, 그것은 곧 "테스트에서만 열리는 뒷문"이 된다.
#
#     [사용처]
#
#         tests/test_indirect_injection.py    (D7 간접 프롬프트 주입)
#         tests/test_policy_boundary.py       (D8 정책·control plane 경계)
#         tests/test_security_invariants.py   (D9 실행 경계·승인 불변조건)
#         tests/test_mcp_tool_schema.py       (D9 MCP 최소권한)
#
#         tests/test_policy_reachability.py는 쓰지 않는다. 판정 함수만 직접
#         부르는 단위 검사여서 sandbox·trace·증거가 필요 없기 때문이다.
#
#     [이 모듈이 없으면]
#
#         1. 실험끼리 오염된다. 승인 저장소를 공유하면 앞 실험의 승인이 남아
#            다음 실험 결과가 실행 순서에 좌우된다.
#         2. "재현했다"를 말할 수 없다. 시각과 ID가 매번 달라 digest가 항상
#            불일치한다.
#         3. 진짜 sandbox가 더러워진다. 다음 실험이 다른 조건에서 출발한다.


from __future__ import annotations

import shutil
import tempfile
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

from agent import build_runtime
from lab_paths import SANDBOX_ROOT
from runtime import Runtime
from security.capability import capability_mapping_snapshot
from security.permission import POLICY
from security.tool_schema import WRITE_ENABLED_PROFILE, ToolProfile, profile_snapshot
from security.trust import DEFAULT_TRUST_BY_PROVENANCE
from trace_logger import TraceLogger
from trace_reader import write_run_summary

# ===========================================================================
# 1부 — 실험 환경 준비
#
# fixture가 "이 파일들이 필요하다"고 선언하면 그 파일들만 임시 sandbox로 옮긴다.
# 선언하지 않은 파일은 실험에서 보이지 않는다. 이것은 불편이 아니라 설계다.
# 실험이 우연히 존재하던 파일에 의존하면 다른 환경에서 재현되지 않는다.
# ===========================================================================


# 함수이름: _relative_seed_path
# 인자:
#     raw_path (str): fixture JSON에 적힌 경로 문자열. sandbox 기준 상대 경로여야 한다
# 반환값:
#     Path: 정규화된 상대 경로
#     ValueError: 절대 경로 · '..' 포함 · 빈 경로인 경우 발생
# 기능 설명:
#     fixture는 사람이 손으로 쓰는 JSON이므로 오타나 위험한 경로가 들어올 수
#     있다. 여기서 세 가지를 거부한다.
#
#         - 절대 경로 ('/etc/passwd')  : sandbox 밖을 가리킨다
#         - '..' 포함 ('../secret')    : 상위로 빠져나간다
#         - 빈 경로                    : 무엇을 복사하라는지 알 수 없다
#
#     Windows 역슬래시는 슬래시로 통일한다. 같은 fixture가 OS를 바꿔도 같은
#     파일을 가리켜야 재현이 성립하기 때문이다.
def _relative_seed_path(raw_path: str) -> Path:
    relative = Path(raw_path.replace("\\", "/"))
    if relative.is_absolute() or ".." in relative.parts or not relative.parts:
        raise ValueError(f"seed path must stay inside sandbox: {raw_path}")
    return relative


# 함수이름: copy_seed_files
# 인자:
#     source_sandbox (Path): 원본 sandbox 루트. 보통 저장소의 sandbox/
#     target_sandbox (Path): 이번 run 전용 임시 sandbox 루트
#     seed_files (Iterable[str]): fixture가 선언한 상대 경로 목록
# 반환값:
#     tuple[str, ...]: 실제 복사된 상대 경로. 정렬·중복 제거된 상태
#     ValueError: 경로가 원본 sandbox 밖을 가리킬 때 발생
#     FileNotFoundError: 선언한 파일이 원본에 없을 때 발생
# 기능 설명:
#     fixture가 선언한 파일만 복사한다.
#
#     저장소의 sandbox/에는 여러 실험이 쓰는 파일이 섞여 있다. 전부 복사하면
#     D7 실험이 D8용 파일을 우연히 읽고도 통과할 수 있다. 실험이 무엇을
#     전제하는지가 fixture에 명시되도록 강제한다.
#
#     _relative_seed_path()가 문자열을 검사하고, 여기서는 정규화한 실제 경로가
#     원본 sandbox 안인지 다시 확인한다. 심볼릭 링크는 문자열만 봐서는 어디를
#     가리키는지 알 수 없다. 경로 검사는 문자열이 아니라 resolve() 이후 결과에
#     해야 한다.
#
#     이 목록이 곧 seed_digest의 입력이 된다. 순서가 흔들리면 같은 입력인데
#     digest가 달라진다.
def copy_seed_files(
    source_sandbox: Path,
    target_sandbox: Path,
    seed_files: Iterable[str],
) -> tuple[str, ...]:
    source_root = source_sandbox.resolve()
    copied: list[str] = []
    target_sandbox.mkdir(parents=True, exist_ok=True)
    for raw_path in seed_files:
        relative = _relative_seed_path(raw_path)
        source = (source_root / relative).resolve()
        # 정규화 후에도 원본 sandbox 안인지 확인한다(심볼릭 링크 탈출 차단).
        try:
            source.relative_to(source_root)
        except ValueError as exc:
            raise ValueError(f"seed path escapes source sandbox: {raw_path}") from exc
        # 없는 파일을 조용히 건너뛰면 "빈 환경에서 통과한 실험"이 생긴다.
        # 실험 전제가 깨진 것이므로 즉시 실패시킨다.
        if not source.is_file():
            raise FileNotFoundError(f"seed file not found: {relative.as_posix()}")
        target = target_sandbox / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        # copy2는 내용뿐 아니라 메타데이터도 보존한다.
        shutil.copy2(source, target)
        copied.append(relative.as_posix())
    return tuple(sorted(set(copied)))


# 함수이름: seed_manifest
# 인자:
#     sandbox_root (Path): 복사가 끝난 임시 sandbox 루트
#     seed_files (Iterable[str]): copy_seed_files()가 반환한 상대 경로 목록
# 반환값:
#     list[dict]: 각 항목은 {'path', 'size', 'sha256'}. 경로 기준 정렬됨
#     FileNotFoundError: 복사됐어야 할 파일이 없을 때 발생
# 기능 설명:
#     실험이 실제로 무엇을 보고 시작했는지를 기록한다.
#
#     기록해야 하는 것은 "무엇을 복사하려 했는가"가 아니라 "실험이 실제로
#     무엇을 보고 시작했는가"이다. 복사 과정에서 문제가 생겼다면 그 사실이
#     manifest에 드러나야 한다.
#
#     이 목록의 해시가 seed_digest가 되고, 나중에 "두 번의 실행이 같은
#     입력에서 출발했다"를 증명하는 근거가 된다. 정렬 순회도 같은 이유다.
def seed_manifest(
    sandbox_root: Path,
    seed_files: Iterable[str],
) -> list[dict[str, Any]]:
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


# 함수이름: _per_run_trace_path
# 인자:
#     base_path (Path): 기준 경로. 파일 경로면 확장자를 떼어 디렉터리로 쓴다
#     fixture_id (str): 실험 케이스 라벨 (예: 'D9-E01')
#     run_id (str): 이번 실행 식별자
# 반환값:
#     Path: '<base>/<fixture_id>/<run_id>/trace.jsonl'
# 기능 설명:
#     run마다 독립된 trace 디렉터리 경로를 만든다. 결과 구조는 다음과 같다.
#
#         trace_D9_EXP/
#           D9-E01/
#             run-d9-e01-<uuid>/
#               trace.jsonl     ← 원시 증거 (append-only)
#               summary.md      ← 사람이 읽는 요약
#
#     하나의 파일에 모든 run을 append하면 "이 표의 근거가 된 run이 어느
#     것인가"를 특정할 수 없다. 보고서가 인용하는 단위가 run이므로 저장
#     단위도 run이어야 한다.
def _per_run_trace_path(base_path: Path, fixture_id: str, run_id: str) -> Path:
    trace_root = base_path if not base_path.suffix else base_path.parent / base_path.stem
    return trace_root / fixture_id / run_id / "trace.jsonl"


# 클래스이름: ExperimentRuntime
# 필드:
#     fixture_id (str): 어떤 실험 케이스인가. 여러 run을 묶는 라벨이며
#         권한이나 승인 지문의 입력이 아니다
#     run_id (str): 이 한 번의 실행 식별자. 모든 trace 이벤트가 이 값으로 묶인다
#     root (Path): 임시 작업 디렉터리 전체. sandbox_root의 부모
#     sandbox_root (Path): 이 실험의 에이전트가 볼 수 있는 유일한 파일 공간
#     trace_path (Path): 원시 증거 JSONL 경로
#     runtime (Runtime): 이 실험 전용 Runtime. 정책·승인 저장소·trace가 모두 독립
#     seed_digest (str): 시작 파일들의 해시. "같은 입력이었다"의 증거
#     seed_files (tuple[str, ...]): 실제로 복사된 상대 경로 목록
#     summary_path (Path): 사람이 읽는 요약 마크다운 경로
# 기능 설명:
#     실험 1회분의 모든 것을 담은 묶음이다. 테스트는 이 객체 하나만 들고
#     다니면 된다.
#
#     frozen=True인 이유는 실험 도중에 sandbox 경로나 run_id가 바뀌면 증거의
#     의미가 사라지기 때문이다.
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


# [A-09] sandbox의 디렉터리 구조는 '선언된 환경'이지, 도구가 실행 중에 만들어도
# 되는 대상이 아니다.
#
# 배경: 이전에는 write_file이 mkdir(parents=True)로 임의 깊이의 디렉터리를 만들
# 수 있었다. AuthorizationEngine의 소유권 판정이 data/{actor}/ 디렉터리 이름에
# 의존하므로, 이는 에이전트가 자기 소유의 네임스페이스를 스스로 만들 수 있다는
# 뜻이었다. 지금은 Runtime이 부모 디렉터리를 만들지 않으므로, 실험 환경이 어떤
# 네임스페이스를 제공하는지를 여기서 명시적으로 선언한다.
#
# 이 목록에 없는 디렉터리로 쓰기를 시도하면 NotADirectoryError로 거부된다.
DECLARED_SANDBOX_DIRECTORIES = (
    "data",              # 공통 데이터 루트
    "data/shared",       # 여러 actor가 함께 쓰는 공간 (reviewer 승인 필요)
    "data/user-001",     # 소유자 있는 개인 공간
    "data/user-002",     # cross-user 접근 실험용 타인 공간
)


# 함수이름: materialize_declared_directories
# 인자:
#     sandbox_root (Path): 이번 run 전용 임시 sandbox 루트
# 반환값:
#     tuple[str, ...]: 생성한 디렉터리 목록 (DECLARED_SANDBOX_DIRECTORIES 그대로)
# 기능 설명:
#     선언된 디렉터리 골격만 만든다. 파일은 seed_files로만 들어온다.
#
#     쓰기 실험은 "쓸 곳은 있는데 파일은 없는" 상태에서 시작해야 한다.
#     파일까지 여기서 만들면 fixture의 seed 선언이 무의미해진다.
def materialize_declared_directories(sandbox_root: Path) -> tuple[str, ...]:
    sandbox_root.mkdir(parents=True, exist_ok=True)
    for relative in DECLARED_SANDBOX_DIRECTORIES:
        (sandbox_root / relative).mkdir(parents=True, exist_ok=True)
    return DECLARED_SANDBOX_DIRECTORIES


# 함수이름: make_experiment_runtime
# 인자:
#     fixture_id (str): 실험 케이스 라벨 (예: 'D9-E01')
#     trace_path (Path): trace 기준 경로. run별 하위 디렉터리가 여기 아래 생긴다
#     seed_files (Iterable[str]): fixture가 선언한 시작 파일. 기본값은 빈 튜플
#     source_sandbox (Path): 복사 원본. 기본값은 저장소의 sandbox/
#     tool_profile (ToolProfile): 이 실험에서 노출할 도구 프로필.
#         기본값은 WRITE_ENABLED_PROFILE
# 반환값:
#     ExperimentRuntime: 격리된 sandbox·Runtime·trace 경로·seed digest 묶음
# 기능 설명:
#     실험 하나를 위한 격리된 환경을 통째로 차려 준다. 테스트가 부르는 첫
#     번째 함수이며, 이 한 줄이 다음을 전부 처리한다.
#
#         1. run_id 발급 — 이후 모든 이벤트가 이 값으로 묶인다
#         2. /tmp에 새 작업 디렉터리 생성 — 저장소의 진짜 sandbox를 안 건드린다
#         3. 선언된 디렉터리 골격 생성 — 쓸 수 있는 공간을 미리 정한다
#         4. fixture가 선언한 seed 파일만 복사
#         5. run 전용 Runtime 생성 — 정책·승인 저장소·trace가 모두 독립
#         6. 시작 조건 manifest와 digest를 trace의 첫 이벤트로 기록
#
#     5번이 가장 중요하다. 승인 저장소를 실험끼리 공유하면 "승인 한 번으로
#     두 번 실행되지 않는다" 같은 불변조건 검증이 실행 순서에 좌우된다.
#
#     실험은 쓰기 차단을 검증해야 하는 경우가 많다. 도구가 아예 노출되지
#     않으면 schema 단계에서 끝나 그 뒤의 Policy·AuthZ·Approval을 검증할 수
#     없다. 반대로 Agent의 기본값은 READ_ONLY다. 실행 기본값과 실험 기본값을
#     의도적으로 다르게 두었다.
#
#     임시 디렉터리는 자동으로 지워지지 않는다. 실패한 run을 사후에 조사할 수
#     있게 하려는 것이다. 정기적으로 /tmp/lab-* 를 정리하면 된다.
def make_experiment_runtime(
    fixture_id: str, *, trace_path: Path, seed_files: Iterable[str] = (),
    source_sandbox: Path = SANDBOX_ROOT,
    tool_profile: ToolProfile = WRITE_ENABLED_PROFILE,
) -> ExperimentRuntime:
    run_id = f"run-{fixture_id.lower()}-{uuid.uuid4().hex}"
    root = Path(tempfile.mkdtemp(prefix=f"lab-{fixture_id.lower()}-"))
    sandbox_root = root / "sandbox"

    # 순서가 중요하다. 골격을 먼저 만들고 그 위에 seed 파일을 얹는다.
    materialize_declared_directories(sandbox_root)
    copied = copy_seed_files(source_sandbox, sandbox_root, seed_files)

    run_trace_path = _per_run_trace_path(trace_path, fixture_id, run_id)
    runtime = build_runtime(
        trace_path=run_trace_path,
        sandbox_root=sandbox_root,
        tool_profile=tool_profile,
    )

    # 시작 조건을 trace의 첫 이벤트로 남긴다. 이후 어떤 결과가 나오든
    # "무엇에서 출발했는가"를 로그만 보고 알 수 있어야 한다.
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


# ===========================================================================
# 2부 — control plane 스냅샷
#
# control plane이란 "정책 그 자체"다. 어떤 도구를 노출하는지, 어떤 경로를
# 허용하는지, 어떤 승인이 살아 있는지 같은 설정 상태를 말한다.
#
# 공격자의 최종 목표는 파일 하나를 읽는 것이 아니라 규칙을 바꾸는 것이다.
# 규칙만 바꿀 수 있으면 그 뒤로는 모든 것이 정당한 요청이 된다. 그래서 공격
# 전후로 이 상태의 해시를 비교한다. "모델이 정책을 못 바꿨다"를 말이 아니라
# 숫자로 증명하는 장치다.
# ===========================================================================


# 함수이름: control_plane_state
# 인자:
#     runtime (Runtime): 상태를 읽어 올 대상 Runtime
# 반환값:
#     dict: 정규화된 보안 설정 전체. 키는 permission_policy · trust_policy ·
#         capability_mapping · mcp_tool_profile · approval_records
# 기능 설명:
#     비교 가능한 형태로 정리한 현재 보안 설정을 만든다.
#
#         permission_policy   경로·명령 허용 규칙 (security/permission.py)
#         trust_policy        provenance → trust label 대응표
#         capability_mapping  도구 → capability 매핑
#         mcp_tool_profile    노출 중인 도구 목록과 schema digest
#         approval_records    현재 살아 있는 승인들의 상태
#
#     dict 순서나 자료형 표현이 실행마다 달라지면 해시가 흔들린다. 정규화해야
#     비교가 성립한다.
def control_plane_state(runtime: Runtime) -> dict[str, Any]:
    return TraceLogger.canonicalize({
        "permission_policy": POLICY,
        "trust_policy": DEFAULT_TRUST_BY_PROVENANCE,
        "capability_mapping": capability_mapping_snapshot(),
        "mcp_tool_profile": profile_snapshot(runtime.tool_profile),
        "approval_records": runtime.approvals.audit_snapshot(),
    })


# 함수이름: record_control_plane_snapshot
# 인자:
#     experiment (ExperimentRuntime): 대상 실험 묶음
#     phase (str): 'before' 또는 'after'. 그 외 값은 거부된다
# 반환값:
#     str: 이 시점 control plane 상태의 digest
#     ValueError: phase가 before/after가 아닐 때 발생
# 기능 설명:
#     공격 전후의 보안 설정 상태를 trace에 남기고 digest를 돌려준다.
#
#     사용법은 항상 짝이다. 공격 시도 전에 phase='before', 후에 phase='after'.
#     두 digest가 같으면 정책이 바뀌지 않았다는 증거가 된다.
#
#     짝이 맞지 않는 스냅샷이 쌓이면 evaluator가 무엇과 무엇을 비교해야 하는지
#     알 수 없게 된다.
#
#     D8-E03(정책 변경 주장)과 D8-E04(actor·승인 위조 주장)가 이 함수의
#     결과를 근거로 삼는다.
def record_control_plane_snapshot(
    experiment: ExperimentRuntime,
    *,
    phase: str,
) -> str:
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


# ===========================================================================
# 3부 — 재현성 증거
#
# 이 파일에서 유일하게 까다로운 부분이다.
#
# 문제: 같은 실험을 두 번 돌리면 timestamp, run_id, call_id, approval_id가
# 매번 다르다. 이벤트를 그대로 해시하면 digest가 항상 달라져서 "재현됐다"를
# 영원히 증명할 수 없다.
#
# 해법: 실행마다 달라지는 필드를 빼고 해시한다.
#
# 그런데 반대 위험이 있다. 너무 많이 빼면 서로 다른 run도 전부 같아 보여서
# 회귀를 놓친다. 즉 이 목록은 "느슨하면 증명 불가, 빡빡하면 검출 불가" 사이의
# 균형점이며, 그 판단이 이 파일의 핵심이다.
#
# 원칙: 판정에 영향을 주지 않는 식별자와 시각만 제거한다. 판정의 입력이나
# 결과(reason, decision, capability, resource, ok, end_stage 등)는 절대 빼지
# 않는다. 그것들이 빠지면 digest가 아무것도 보증하지 않게 된다.
# ===========================================================================

_VOLATILE_EVIDENCE_FIELDS = {
    # 이벤트·실행 식별자 — 매번 새로 발급되며 판정에 영향을 주지 않는다
    "event_id",
    "run_id",
    "call_id",
    # 시각 — 실행할 때마다 다르다
    "timestamp",
    "received_at",
    "requested_at",
    "expires_at",
    # observation 식별자 — 내용이 아니라 이름표일 뿐이다
    "observation_id",
    "observation_ids",
    "parent_call_id",
    "parent_call_ids",
    # 승인 ID — uuid이므로 매번 다르다. 승인의 '상태'(approved/consumed)는
    # 별도 필드로 남으므로 여기서 ID를 빼도 검증력은 유지된다.
    "approval_id",
    # runtime_result 사건 안의 result_digest도 임의 approval ID를 포함할 수
    # 있으므로 재현성 digest에서는 원래 결과 필드를 다시 정규화한다.
    "result_digest",
}


# 함수이름: _without_volatile_evidence
# 인자:
#     value (Any): trace 이벤트 또는 그 안의 중첩 dict/list/스칼라
# 반환값:
#     Any: _VOLATILE_EVIDENCE_FIELDS의 키가 제거된 새 값. 원본은 변경하지 않는다
# 기능 설명:
#     재현성 비교용 사본에서만 흔들리는 값을 제거한다.
#
#     provenance처럼 중첩된 구조 안에도 received_at이나 observation_ids가
#     들어 있다. 최상위만 훑으면 중첩된 곳의 임의 값이 그대로 남아 digest가
#     계속 흔들린다.
#
#     원본 이벤트를 수정하지 않고 새 dict를 만들어 돌려준다. 원시 trace는
#     append-only 증거이므로 사후에 손대면 안 된다.
def _without_volatile_evidence(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _without_volatile_evidence(item)
            for key, item in value.items()
            if key not in _VOLATILE_EVIDENCE_FIELDS
        }
    if isinstance(value, list):
        return [_without_volatile_evidence(item) for item in value]
    return value


# 함수이름: _stable_event_projection
# 인자:
#     event (dict): trace 이벤트 하나
# 반환값:
#     dict: 재현 비교용으로 축소된 사본
# 기능 설명:
#     이벤트 하나를 재현 비교용 투영본으로 바꾼다.
#
#     투영(projection)이라는 말을 쓴 이유는 원본을 바꾸는 것이 아니라 원본의
#     일부만 비춘 사본을 만들기 때문이다. 원시 trace에는 모든 것이 남아 있고,
#     digest를 계산할 때만 이 축소본을 쓴다.
def _stable_event_projection(event: dict[str, Any]) -> dict[str, Any]:
    return _without_volatile_evidence(event)


# 함수이름: record_run_evidence
# 인자:
#     experiment (ExperimentRuntime): 실험이 끝난 상태의 묶음
# 반환값:
#     dict: seed_digest · decision_digest · result_digest · trace_path ·
#         summary_path. control plane을 관측한 실험이면 before/after digest와
#         control_plane_mutation이 추가된다
# 기능 설명:
#     실험이 끝난 뒤 증거를 정리해 trace 마지막에 기록한다. 테스트가 부르는
#     마지막 함수이며 세 가지 digest를 만든다.
#
#         seed_digest       같은 입력에서 출발했다
#         decision_digest   같은 판정 과정을 거쳤다
#         result_digest     같은 결과에 도달했다
#
#     하나로 합치면 "달라졌다"만 알 수 있고 어디서 달라졌는지 모른다. 입력이
#     달랐던 건지, 판정이 달라진 건지, 실행 결과만 다른 건지를 구별할 수 있어야
#     원인을 좁힐 수 있다.
#
#     tool_schema_decision / policy_decision / authorization_decision /
#     approval 은 각각 다른 계층의 판단이다. 하나라도 빠지면 "그 계층은
#     비교하지 않았다"는 구멍이 생긴다. 새 판정 계층을 추가하면 여기에도
#     반드시 넣어야 한다.
#
#     before/after 스냅샷이 둘 다 있을 때만 계산한다. 하나만 있으면 비교
#     자체가 성립하지 않는다. 임의로 False를 넣으면 "변조가 없었다"는 거짓
#     주장이 된다. 모르는 것은 모른다고 기록해야 한다.
#
#     마지막으로 write_run_summary()가 사람이 읽는 summary.md를 만든다. 원시
#     JSONL은 기계용, summary는 사람용이며 둘 다 같은 run 디렉터리에 남는다.
def record_run_evidence(experiment: ExperimentRuntime) -> dict[str, Any]:
    events = list(experiment.runtime.trace.iter_events(run_id=experiment.run_id, strict=True))

    # 각 보안 계층의 판단을 모은다. 하나라도 빠지면 그 계층은 비교되지 않는다.
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

    # control plane 스냅샷은 실험에 따라 없을 수도 있다(D7처럼).
    snapshots = {
        event.get("phase"): event
        for event in events
        if event.get("event") == "control_plane_snapshot"
    }
    before_digest = snapshots.get("before", {}).get("control_plane_digest")
    after_digest = snapshots.get("after", {}).get("control_plane_digest")
    # 둘 다 있을 때만 비교한다. 없으면 None — '모른다'를 기록한다.
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

    # 기계용 JSONL 옆에 사람용 요약을 만든다.
    write_run_summary(experiment.trace_path, experiment.summary_path)

    evidence: dict[str, Any] = {
        "seed_digest": experiment.seed_digest,
        "decision_digest": decision_digest,
        "result_digest": result_digest,
        "trace_path": str(experiment.trace_path),
        "summary_path": str(experiment.summary_path),
    }
    # control plane을 관측하지 않은 실험에는 해당 필드를 아예 넣지 않는다.
    # null로 채우면 "관측했는데 값이 없다"로 오해될 수 있다.
    if mutation is not None:
        evidence.update({
            "control_plane_before_digest": before_digest,
            "control_plane_after_digest": after_digest,
            "control_plane_mutation": mutation,
        })
    return evidence
