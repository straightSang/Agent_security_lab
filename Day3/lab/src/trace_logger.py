import json
import uuid

from datetime import datetime
from pathlib import Path

TRACE_DIR = Path("traces")
TRACE_DIR.mkdir(exist_ok=True)

TRACE_FILE = TRACE_DIR / "agent_trace.jsonl"

class TraceLogger:

    def __init__(self):

        self.run_id = str(uuid.uuid4()) # agent 실행 구분 ID 생성기
        self.step=0
        self.event_index=0

    def log(
        self, 
        event_type: str, 
        tool: dict = None,
        validation: dict = None,
        authorization: dict = None,
        execution: dict = None,
        result: dict = None
        data: dict = None, 
        ):
        
        self.event_index += 1

        record = {
            "timestamp": datetime.now().isoformat(),
            "run_id":self.run_id,
            "step": self.step,
            "event_index": self.event_index,
            
            "event": event_type,

            "tool": tool,

            "validation": validation,
            
            "authorization": authorization,
            
            "execution": execution,

            "result": result,
            
            "data": data or {}
        }

        with TRACE_FILE.open( "a", encoding="utf-8" ) as f:
            f.write( json.dumps(record, ensure_ascii=False, default=str) + "\n" )


    def next_step(self):
        self.step += 1