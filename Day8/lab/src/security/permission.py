"""``PolicyEngine``이 읽는 선언형 Day 4 리소스 정책.

모든 경로는 ``SANDBOX_ROOT`` 기준 상대 경로다. Runtime이 이미 root를 붙이므로
도구 인자에 ``sandbox/`` 문자열을 넣지 않는다.
"""

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
