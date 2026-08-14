# test_runtime.py

from runtime import execute_tool


print(
    "\nEXP-1: authorized read"
)

print(
    execute_tool(
        "read_file",
        {
            "path": "workspace/test.txt"
        }
    )
)


print(
    "\nEXP-2: authorized write"
)

print(
    execute_tool(
        "write_file",
        {
            "path": "workspace/output.txt",
            "content": "hello"
        }
    )
)


print(
    "\nEXP-3: unauthorized write"
)

print(
    execute_tool(
        "write_file",
        {
            "path": "notes/output.txt",
            "content": "should be denied"
        }
    )
)


print(
    "\nEXP-4: traversal"
)

print(
    execute_tool(
        "read_file",
        {
            "path": "../secret.txt"
        }
    )
)


print(
    "\nEXP-5: allowed command"
)

print(
    execute_tool(
        "run_command",
        {
            "command": "pwd"
        }
    )
)


print(
    "\nEXP-6: denied command"
)

print(
    execute_tool(
        "run_command",
        {
            "command": "rm file.txt"
        }
    )
)