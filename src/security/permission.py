# 모듈이름: security.permission
# 역할: 경로·명령 허용 규칙의 단일 기준 선언
# 호출 주체: security.policy.PolicyEngine, experiment_support(스냅샷용)
#
# 기능 설명:
#     [A-01] 이 파일이 "어떤 경로에 어떤 작업을 허용하는가"의 단일 기준이다.
#     MCP schema 단계는 구조적 안전성만 검사하고 범위 판정을 하지 않으며,
#     AuthorizationEngine은 그 위에서 actor-resource 소유 관계만 판정한다.
#     세 계층이 같은 질문에 답하지 않도록 역할을 분리했다.
#
#     tests/test_policy_reachability.py가 여기 선언된 모든 scope가 실제로
#     도달 가능한지를 회귀로 검사한다.
#
#     모든 경로는 SANDBOX_ROOT 기준 상대 경로다. Runtime이 이미 root를 붙이므로
#     도구 인자에 'sandbox/' 문자열을 넣지 않는다.
#
#     정책은 사람이 읽고 검토하는 대상이다. 함수로 흩어 놓으면 문서와 코드가
#     어긋나고, 무엇이 허용되는지 한눈에 볼 수 없게 된다.

POLICY = {
    "calculator": {"allowed": True},
    "get_time": {"allowed": True},
    # root file은 ``notes.txt`` 같은 파일이다. ``data``는 data 디렉터리와
    # 그 하위 항목을 뜻한다. 다른 하위 디렉터리는 Day 4 v0.1 범위 밖이다.
    "read_file": {"allowed_scopes": {"data"}},
    "list_files": {"allowed_scopes": {"sandbox_root", "data"}},
    # Day 5: write는 일반 policy상 승인 필요다. 정확한 actor-resource 관계는
    # AuthorizationEngine이 별도로 확인한다. 즉 data/** 쓰기가 여기서
    # APPROVAL_REQUIRED여도 non-owner는 Authorization에서 FORBIDDEN이다.
    "write_file": {
        "allowed_scopes": {"root_file", "data"},
        "approval_required": True,
    },
    "run_command": {"allowed_commands": {"pwd", "ls", "cat"}},
}
