# test_runtime.py

from Agent_v0_2_2 import execute_tool
from trace_logger import TraceLogger

logger = TraceLogger()

print(
    "\nEXP-1: authorized read"
)

print(
    execute_tool(
        tool_name="read_file",
        arguments= {
            "path": "workspace/test.txt",
        },
        logger=logger,
        call_id="EXP-1"
    )
)


print(
    "\nEXP-2: authorized write"
)
 
print(
    execute_tool(
        tool_name="write_file",
        arguments= {
            "path": "workspace/test.txt",
            "content": "hello"
        },
        logger=logger,
        call_id="EXP-2"
    )
)


print(
    "\nEXP-3: unauthorized write"
)

print(
    execute_tool(
        tool_name="write_file",
        arguments= {
            "path": "workspace/test.txt",
            "content":  "should be denied"
        },
        logger=logger,
        call_id="EXP-3"
    )
)


print(
    "\nEXP-4: traversal"
)

print(
    execute_tool(

        tool_name="read_file",
        arguments= {
            "path": "../secret.txt"
        },
        logger=logger,
        call_id="EXP-4"
    )
)


print(
    "\nEXP-5: allowed command"
)

print(
    execute_tool(
        tool_name="run_command",
        arguments= {
            "command": "pwd"
        },
        logger=logger,
        call_id="EXP-5"
    )
)


print(
    "\nEXP-6: denied command"
)

print(
    execute_tool(
                
        tool_name="run_command",
        arguments= {
            "command": "rm file.txt"
        },
        logger=logger,
        call_id="EXP-6"
    )
)