"""UTF WiFi test runner — launch_utf_tests script with live log capture."""

from __future__ import annotations

import os
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from config import DEFAULT_UTF_HARNESS, DEFAULT_UTF_TARGET

# Windows ships the .bat launcher; POSIX checkouts use the shell script.
LAUNCHER_NAMES = ("launch_utf_tests.bat", "launch_utf_tests.sh", "run_tests.sh")


@dataclass
class UtfJob:
    id: str
    status: str = "queued"
    logs: List[str] = field(default_factory=list)
    error: Optional[str] = None
    started_at: float = field(default_factory=time.time)
    finished_at: Optional[float] = None
    config: dict = field(default_factory=dict)
    _proc: Optional[subprocess.Popen] = field(default=None, repr=False)

    def append(self, line: str) -> None:
        self.logs.append(line)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "status": self.status,
            "logs": self.logs,
            "error": self.error,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "config": self.config,
        }


_jobs: Dict[str, UtfJob] = {}
_lock = threading.Lock()


def get_utf_job(job_id: str) -> Optional[UtfJob]:
    return _jobs.get(job_id)


def list_utf_jobs() -> list:
    return [j.to_dict() for j in sorted(_jobs.values(), key=lambda x: x.started_at, reverse=True)]


def _find_launcher(folder: Path) -> Path:
    """First available launcher script in the executor folder."""
    for name in LAUNCHER_NAMES:
        candidate = folder / name
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(
        f"No test launcher found in {folder} (looked for {', '.join(LAUNCHER_NAMES)})"
    )


def _launch_command(
    launcher: Path,
    target: str,
    harness: str,
    pytest_command: Optional[str] = None,
    docker_flags: Optional[str] = None,
) -> List[str]:
    """Command to run a launcher script on the current platform."""
    args = [f"--target={target}", f"--harness={harness}"]
    if pytest_command:
        args.append(f"--pytest_command={pytest_command}")
    if docker_flags:
        args.append(f"--docker_flags={docker_flags}")
    if launcher.suffix.lower() == ".bat":
        if os.name != "nt":
            raise RuntimeError(
                f"{launcher.name} can only run on Windows. Provide a .sh launcher instead."
            )
        return ["cmd.exe", "/c", launcher.name, *args]
    return ["bash", launcher.name, *args]


def _validate_executor(executor_dir: Path) -> Path:
    folder = executor_dir.expanduser().resolve()
    if not folder.is_dir():
        raise FileNotFoundError(f"Executor folder not found: {folder}")
    _find_launcher(folder)
    return folder


def run_utf_tests(
    executor_dir: str,
    target: str,
    harness: str,
    pytest_command: Optional[str] = None,
    docker_flags: Optional[str] = None,
) -> str:
    folder = _validate_executor(Path(executor_dir))
    launcher = _find_launcher(folder)
    target = (target or DEFAULT_UTF_TARGET).strip()
    harness = (harness or DEFAULT_UTF_HARNESS).strip()
    if not target:
        raise ValueError("target is required")
    if not harness:
        raise ValueError("harness is required")

    cmd = _launch_command(launcher, target, harness, pytest_command, docker_flags)
    job_id = str(uuid.uuid4())[:8]
    job = UtfJob(
        id=job_id,
        config={
            "executor_dir": str(folder),
            "target": target,
            "harness": harness,
            "pytest_command": pytest_command,
            "docker_flags": docker_flags,
            "command": " ".join(cmd),
        },
    )
    with _lock:
        _jobs[job_id] = job

    thread = threading.Thread(target=_utf_worker, args=(job, folder, cmd), daemon=True)
    thread.start()
    return job_id


def stop_utf_job(job_id: str) -> dict:
    job = get_utf_job(job_id)
    if not job:
        raise FileNotFoundError("UTF job not found")
    if job.status != "running":
        return {"stopped": False, "status": job.status}
    proc = job._proc
    if proc and proc.poll() is None:
        proc.terminate()
        job.append("=== Stopped by user ===")
        job.status = "stopped"
        job.finished_at = time.time()
        return {"stopped": True, "status": job.status}
    return {"stopped": False, "status": job.status}


def _utf_worker(job: UtfJob, folder: Path, cmd: List[str]) -> None:
    try:
        job.status = "running"
        job.append(f"$ {' '.join(cmd)}")
        job.append(f"  (cwd: {folder})")
        job.append("")

        proc = subprocess.Popen(
            cmd,
            cwd=str(folder),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            shell=False,
        )
        job._proc = proc
        assert proc.stdout is not None
        for line in proc.stdout:
            job.append(line.rstrip("\r\n"))
        code = proc.wait()
        job._proc = None
        if code != 0:
            job.status = "failed"
            job.error = f"UTF tests exited with code {code}"
            job.append(f"ERROR: {job.error}")
        else:
            job.status = "success"
            job.append("=== UTF tests finished successfully ===")
    except Exception as exc:
        job.status = "failed"
        job.error = str(exc)
        job.append(f"ERROR: {exc}")
    finally:
        job.finished_at = time.time()
        job._proc = None
