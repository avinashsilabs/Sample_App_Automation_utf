"""Serial port listing and background read for DUT logs."""

from __future__ import annotations

import re
import threading
import time
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import IO, Deque, Dict, List, Optional, Pattern

try:
    import serial
    from serial.tools import list_ports
except ImportError:  # pragma: no cover
    serial = None
    list_ports = None

from config import SERIAL_LOG_DIR

DEFAULT_BAUD = 115200
_MAX_LINES = 5000

_lock = threading.Lock()
_reader_thread: Optional[threading.Thread] = None
_serial: Optional["serial.Serial"] = None
_lines: Deque[str] = deque(maxlen=_MAX_LINES)
_active = False
_config: Dict[str, object] = {}
_serial_cursor: int = 0

# On-disk copy of the console. The deque above is capped and cleared on every
# restart, so a run's output is otherwise unrecoverable once the next run starts.
_log_lock = threading.Lock()
_log_file: Optional[IO[str]] = None
_log_path: Optional[Path] = None


def mark_serial_cursor() -> int:
    """Ignore serial lines before this index (avoids stale passkey/MAC after reboot)."""
    global _serial_cursor
    with _lock:
        _serial_cursor = len(_lines)
        return _serial_cursor


def serial_cursor() -> int:
    with _lock:
        return _serial_cursor


def _require_pyserial() -> None:
    if serial is None or list_ports is None:
        raise RuntimeError("pyserial not installed — run: pip install pyserial")


def list_serial_ports() -> List[dict]:
    _require_pyserial()
    ports = []
    for info in list_ports.comports():
        ports.append({
            "device": info.device,
            "description": info.description or "",
            "hwid": info.hwid or "",
            "manufacturer": getattr(info, "manufacturer", "") or "",
        })
    return ports


def guess_vcom_port() -> Optional[str]:
    _require_pyserial()
    preferred = ("jlink", "silicon", "si labs", "usb serial", "uart", "vcom", "cp210", "ftdi")
    for info in list_ports.comports():
        blob = f"{info.description} {info.manufacturer} {info.hwid}".lower()
        if any(token in blob for token in preferred):
            return info.device
    items = list(list_ports.comports())
    return items[0].device if items else None


def _open_log_file(port: str, baud: int, label: Optional[str]) -> None:
    """Create one log file per capture session; never fail the run over logging."""
    global _log_file, _log_path
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", (label or "dut").strip()).strip("._-") or "dut"
    path = SERIAL_LOG_DIR / f"{stem}_{datetime.now():%Y%m%d_%H%M%S}.log"
    with _log_lock:
        _log_file = None
        _log_path = None
        try:
            SERIAL_LOG_DIR.mkdir(parents=True, exist_ok=True)
            handle = path.open("w", encoding="utf-8")
            handle.write(
                f"=== DUT serial capture {port} @ {baud} "
                f"started {datetime.now():%Y-%m-%d %H:%M:%S} ===\n"
            )
            handle.flush()
        except Exception:
            return
        _log_file = handle
        _log_path = path


def _write_log_line(line: str) -> None:
    with _log_lock:
        if _log_file is None:
            return
        try:
            stamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            _log_file.write(f"[{stamp}] {line}\n")
            _log_file.flush()
        except Exception:
            pass


def _close_log_file() -> None:
    global _log_file
    with _log_lock:
        if _log_file is None:
            return
        try:
            _log_file.write(f"=== capture stopped {datetime.now():%Y-%m-%d %H:%M:%S} ===\n")
            _log_file.close()
        except Exception:
            pass
        _log_file = None


def serial_log_path() -> Optional[str]:
    """Path of the current (or most recent) console log file."""
    with _log_lock:
        return str(_log_path) if _log_path else None


def serial_log_note(text: str) -> None:
    """Mark a run boundary in the log file so one session can hold several runs."""
    _write_log_line(f"---- {text} ----")


def serial_log_append_block(text: str) -> None:
    """Append a multi-line readme block to the log file (no per-line timestamps)."""
    with _log_lock:
        if _log_file is None:
            return
        try:
            _log_file.write("\n")
            for line in (text or "").splitlines():
                _log_file.write(f"{line}\n")
            _log_file.write("\n")
            _log_file.flush()
        except Exception:
            pass


def _reader_loop() -> None:
    global _active
    while _active and _serial is not None and _serial.is_open:
        try:
            raw = _serial.readline()
            if not raw:
                time.sleep(0.02)
                continue
            line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
            with _lock:
                _lines.append(line)
            _write_log_line(line)
        except Exception as exc:
            with _lock:
                _lines.append(f"[serial error] {exc}")
            _write_log_line(f"[serial error] {exc}")
            break
    _active = False


def start_serial(port: str, baud: int = DEFAULT_BAUD, label: Optional[str] = None) -> dict:
    global _reader_thread, _serial, _active, _config, _serial_cursor
    _require_pyserial()
    stop_serial()
    with _lock:
        _lines.clear()
        _serial_cursor = 0
    _serial = serial.Serial(port=port, baudrate=baud, timeout=0.2)
    _active = True
    _config = {"port": port, "baud": baud}
    _open_log_file(port, baud, label)
    _reader_thread = threading.Thread(target=_reader_loop, daemon=True)
    _reader_thread.start()
    return {"port": port, "baud": baud, "started": True, "log_path": serial_log_path()}


def stop_serial() -> dict:
    global _reader_thread, _serial, _active
    _active = False
    if _serial is not None:
        try:
            if _serial.is_open:
                _serial.close()
        except Exception:
            pass
        _serial = None
    if _reader_thread is not None:
        _reader_thread.join(timeout=1.0)
        _reader_thread = None
    _close_log_file()
    return {"stopped": True, "log_path": serial_log_path()}


def serial_status() -> dict:
    with _lock:
        status = {
            "active": _active,
            "port": _config.get("port"),
            "baud": _config.get("baud"),
            "line_count": len(_lines),
        }
    status["log_path"] = serial_log_path()
    return status


def get_lines(since: int = 0) -> dict:
    with _lock:
        items = list(_lines)
    if since < 0:
        since = 0
    if since > len(items):
        since = len(items)
    return {
        "lines": items[since:],
        "total": len(items),
    }


def get_all_text() -> str:
    with _lock:
        return "\n".join(_lines)


def wait_for_pattern(
    pattern: Pattern[str],
    timeout_sec: float = 60.0,
    *,
    since_index: Optional[int] = None,
) -> re.Match[str]:
    """Block until regex matches serial lines (optionally only after since_index)."""
    if since_index is None:
        since_index = _serial_cursor
    deadline = time.time() + timeout_sec
    seen_len = max(since_index, 0)
    while time.time() < deadline:
        with _lock:
            items = list(_lines)
        if len(items) > seen_len:
            chunk = "\n".join(items[seen_len:])
            seen_len = len(items)
            match = pattern.search(chunk)
            if match:
                return match
        if since_index <= len(items):
            chunk = "\n".join(items[since_index:])
            match = pattern.search(chunk)
            if match:
                return match
        time.sleep(0.25)
    raise TimeoutError(f"Timed out after {timeout_sec}s waiting for serial pattern: {pattern.pattern}")
