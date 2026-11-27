"""On-disk copy of Build Console output for each integration job."""

from __future__ import annotations

import re
import threading
from datetime import datetime
from pathlib import Path
from typing import IO, Optional

from config import BUILD_CONSOLE_LOG_DIR

_log_lock = threading.Lock()


def open_job_log(app_id: str, job_id: str) -> tuple[Optional[IO[str]], Optional[Path]]:
    """Create one log file per job; never fail the run over logging."""
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", (app_id or "app").strip()).strip("._-") or "app"
    path = BUILD_CONSOLE_LOG_DIR / f"{stem}_{job_id}_{datetime.now():%Y%m%d_%H%M%S}.log"
    with _log_lock:
        try:
            BUILD_CONSOLE_LOG_DIR.mkdir(parents=True, exist_ok=True)
            handle = path.open("w", encoding="utf-8")
            handle.write(
                f"=== Build Console {app_id} job={job_id} "
                f"started {datetime.now():%Y-%m-%d %H:%M:%S} ===\n"
            )
            handle.flush()
            return handle, path
        except Exception:
            return None, None


def write_job_log(handle: Optional[IO[str]], line: str) -> None:
    if handle is None:
        return
    with _log_lock:
        try:
            stamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            handle.write(f"[{stamp}] {line}\n")
            handle.flush()
        except Exception:
            pass


def close_job_log(
    handle: Optional[IO[str]],
    *,
    status: str = "finished",
) -> None:
    if handle is None:
        return
    with _log_lock:
        try:
            handle.write(
                f"=== Build Console {status} {datetime.now():%Y-%m-%d %H:%M:%S} ===\n"
            )
            handle.close()
        except Exception:
            pass
