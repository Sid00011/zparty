"""
Launch Zparty Web UI.
Usage: python ui_launch.py
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

import uvicorn

if __name__ == "__main__":
    print("  ** ZPARTY Web UI — http://localhost:8000  (Ctrl+C to stop) **")
    uvicorn.run(
        "ui.server:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        log_level="warning",
    )
