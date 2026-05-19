import os
import json
import logging
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


def init_output_folder(results_dir: str = "results") -> Path:
    """Create a timestamped scan session folder and return its Path."""
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    session = Path(results_dir) / f"scan_{ts}"
    for sub in ("raw", "findings", "report"):
        (session / sub).mkdir(parents=True, exist_ok=True)
    logger.info(f"Session folder: {session}")
    return session


def checkpoint(session: Path, phase: str, data: object) -> None:
    """Write phase data to raw/ as a JSON checkpoint."""
    out = session / "raw" / f"{phase}.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)
    logger.debug(f"Checkpoint written: {out}")
