# 기능: 판단 기준을 정의해놓은 파일
# 세부사항:
"""
read_file
→  "data", "workspace" 에서만 허용

write_file
→  "workspace" 에서만 허용

list_files
→  "data", "workspace" 에서만 허용

run_command
→ pwd / ls / cat만 허용
"""

POLICY = {

    "calculator": {
        "allowed": True
    },

    "get_time": {
        "allowed": True
    },

    "read_file" : {
        "allowed_dirs": [
            "data", "workspace"
        ]
    },

    "write_file" : {
        "allowed_dirs": [
            "workspace"
        ]

    },

    "list_files" : {
        "allowed_dirs": [
            "workspace", "data"
        ]
    },

    "run_command" : {
        "allowed_commands": [
            "pwd", "ls", "cat"
        ]
    }
}