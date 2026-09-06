import json
import uuid

from datetime import datetime
from pathlib import Path

TRACE_DIR = Path("traces")
TRACE_DIR.mkdir(exist_ok=True)

TRACE_FILE = TRACE_DIR / "agent_trace.jsonl"

class TraceLogger:

    def __init__(self):

        self.run_id = str(uuid.uuid4())
        self.step=0

    def log(self, event_type: str, data: dict):
        
        record = {
            "timestamp": datetime.now().isoformat(),
            "run_id":self.run_id,
            "step": self.step,
            "event": event_type,
            "data": data
        }

        with TRACE_FILE.open( "a", encoding="utf-8" ) as f:
            f.write( json.dumps(record, ensure_ascii=False, default=str) + "\n" )


    def next_step(self):
        self.step += 1