"""Launch per-example WLAN+BLE coexistence test scripts."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


COEX_ROOT = Path(__file__).resolve().parent / "coex"
COEX_SCRIPTS = {
    "out_of_box_demo": COEX_ROOT / "out_of_box_demo_test_scripts" / "run_test.py",
    "wifi_throughput_ble_dual_role": COEX_ROOT / "throughput_dual_role_scripts" / "run_test.py",
    "wifi_station_ble_throughput_app": COEX_ROOT / "wifi_sta_throughput_scripts" / "run_test.py",
    "wifi_station_ble_provisioning_aws": COEX_ROOT / "wifi_station_ble_provisioning_aws_test_scripts" / "run_test.py",
    "wifi_ble_provisioning_aws_devkit": COEX_ROOT / "wifi_station_ble_provisioning_aws_devkit_test_scripts" / "run_test.py",
}


@dataclass
class CoexJob:
    id: str
    app_id: str
    status: str = "queued"
    logs: List[str] = field(default_factory=list)
    error: Optional[str] = None
    started_at: float = field(default_factory=time.time)
    finished_at: Optional[float] = None
    _proc: Optional[subprocess.Popen] = field(default=None, repr=False)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "app_id": self.app_id,
            "status": self.status,
            "logs": self.logs,
            "error": self.error,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
        }


_jobs: Dict[str, CoexJob] = {}
_lock = threading.Lock()


def get_coex_job(job_id: str) -> Optional[CoexJob]:
    return _jobs.get(job_id)


def list_coex_jobs() -> list:
    return [
        job.to_dict()
        for job in sorted(_jobs.values(), key=lambda item: item.started_at, reverse=True)
    ]


def run_coex_test(
    app_id: str,
    studio_overrides: Optional[dict] = None,
    wifi_overrides: Optional[dict] = None,
) -> str:
    script = COEX_SCRIPTS.get(app_id)
    if script is None:
        raise ValueError(f"No coexistence test script registered for {app_id}")
    if not script.is_file():
        raise FileNotFoundError(f"Coexistence test script not found: {script}")
    config = script.with_name("config.local.json")
    if not config.is_file():
        raise FileNotFoundError(
            f"Coexistence config missing: {config}. "
            "Copy config.example.json to config.local.json and fill in SDK/Wi-Fi values."
        )

    job = CoexJob(id=str(uuid.uuid4())[:8], app_id=app_id)
    run_config = config
    if studio_overrides or wifi_overrides:
        payload = json.loads(config.read_text(encoding="utf-8"))
        studio = payload.setdefault("studio", {})
        for key, value in (studio_overrides or {}).items():
            if value not in (None, ""):
                studio[key] = value
        wifi = payload.setdefault("wifi", {})
        for key, value in (wifi_overrides or {}).items():
            # Blank UI fields mean "keep what the config already has", so an
            # empty box cannot wipe the saved credentials. Security 0 is real.
            if value not in (None, ""):
                wifi[key] = value
        run_config = Path(tempfile.gettempdir()) / f"wcbs_coex_{job.id}.json"
        run_config.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    with _lock:
        _jobs[job.id] = job
    threading.Thread(
        target=_worker,
        args=(job, script, run_config, run_config != config),
        daemon=True,
    ).start()
    return job.id


def stop_coex_job(job_id: str) -> dict:
    job = get_coex_job(job_id)
    if job is None:
        raise FileNotFoundError("Coexistence job not found")
    proc = job._proc
    if job.status == "running" and proc is not None and proc.poll() is None:
        proc.terminate()
        job.logs.append("=== Stopped by user ===")
        job.status = "stopped"
        job.finished_at = time.time()
        return {"stopped": True, "status": job.status}
    return {"stopped": False, "status": job.status}


def _worker(job: CoexJob, script: Path, config: Path, remove_config: bool) -> None:
    cmd = [sys.executable, "-u", str(script), "--config", str(config)]
    try:
        job.status = "running"
        job.logs.append(f"$ {' '.join(cmd)}")
        proc = subprocess.Popen(
            cmd,
            cwd=str(script.parent),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            shell=False,
        )
        job._proc = proc
        assert proc.stdout is not None
        for line in proc.stdout:
            job.logs.append(line.rstrip("\r\n"))
        code = proc.wait()
        if job.status == "stopped":
            return
        if code == 0:
            job.status = "success"
            job.logs.append("=== Coexistence test finished successfully ===")
        else:
            job.status = "failed"
            job.error = f"Coexistence test exited with code {code}"
    except Exception as exc:
        job.status = "failed"
        job.error = str(exc)
        job.logs.append(f"ERROR: {exc}")
    finally:
        job._proc = None
        job.finished_at = time.time()
        if remove_config:
            try:
                config.unlink()
            except OSError:
                pass
