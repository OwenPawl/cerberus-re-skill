"""Restart-safe background command jobs for the local Cerberus MCP server."""

from __future__ import annotations

import base64
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .mcp_runtime import (
    FAILED,
    CommandRunner,
    MCPSettings,
    append_audit,
    envelope,
    make_run_result,
)


def _timestamp() -> str:
    return datetime.now(UTC).isoformat()


def _atomic_write(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True, default=str)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    temporary.replace(path)


def _pid_alive(pid: int | None) -> bool:
    if not pid:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _worker_environment() -> dict[str, str]:
    return {
        **os.environ,
        "PYTHONPATH": os.pathsep.join(
            entry for entry in sys.path if isinstance(entry, str) and entry
        ),
    }


def _spawn_windows_cim_worker(command: list[str], workspace: Path) -> int:
    """Ask the local CIM provider to create a worker outside the MCP Job Object."""
    powershell = shutil.which("pwsh.exe") or shutil.which("powershell.exe")
    if not powershell:
        raise OSError("PowerShell is required for restart-safe Windows MCP jobs")
    command_line = subprocess.list2cmdline(command).replace("'", "''")
    current_directory = str(workspace).replace("'", "''")
    script = (
        "$ErrorActionPreference='Stop';"
        "$result=Invoke-CimMethod -ClassName Win32_Process -MethodName Create "
        f"-Arguments @{{CommandLine='{command_line}';CurrentDirectory='{current_directory}'}};"
        "if($result.ReturnValue -ne 0){throw ('Win32_Process.Create failed: '+$result.ReturnValue)};"
        "Write-Output ('CERBERUS_PID='+$result.ProcessId)"
    )
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    broker = subprocess.run(
        [powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
        cwd=workspace,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        shell=False,
        check=False,
    )
    matches = re.findall(rb"CERBERUS_PID=(\d+)", broker.stdout)
    if broker.returncode != 0 or not matches:
        detail = broker.stderr.decode(errors="replace").strip()
        raise OSError(detail or "CIM did not return a worker process id")
    return int(matches[-1])


def _spawn_detached_worker(
    command: list[str],
    workspace: Path,
) -> tuple[int, subprocess.Popen[bytes] | None]:
    common: dict[str, Any] = {
        "cwd": str(workspace),
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "close_fds": True,
        "env": _worker_environment(),
    }
    if os.name != "nt":
        worker = subprocess.Popen(command, start_new_session=True, **common)
        return worker.pid, worker

    flags = (
        subprocess.CREATE_NEW_PROCESS_GROUP
        | subprocess.DETACHED_PROCESS
        | getattr(subprocess, "CREATE_BREAKAWAY_FROM_JOB", 0)
    )
    try:
        worker = subprocess.Popen(command, creationflags=flags, **common)
    except OSError:
        return _spawn_windows_cim_worker(command, workspace), None
    return worker.pid, worker


class JobStore:
    def __init__(self, settings: MCPSettings):
        self.settings = settings
        self.settings.ensure_state()

    def path(self, job_id: str, *, archived: bool = False) -> Path:
        if not job_id or any(char not in "0123456789abcdef" for char in job_id.lower()):
            raise ValueError("job_id must be hexadecimal")
        directory = self.settings.job_archive_dir if archived else self.settings.jobs_dir
        return directory / f"{job_id}.json"

    def read(self, job_id: str) -> dict[str, Any] | None:
        active = self.path(job_id)
        archived = self.path(job_id, archived=True)
        path = active if active.is_file() else archived
        if not path.is_file():
            return None
        record = json.loads(path.read_text(encoding="utf-8"))
        if record.get("status") in {"queued", "running"}:
            pid = record.get("worker_pid")
            age = time.time() - float(record.get("started_epoch", time.time()))
            if (pid and not _pid_alive(pid)) or (not pid and age > 30):
                record.update(
                    status="orphaned",
                    finished_at=_timestamp(),
                    note="detached worker exited without recording a terminal result",
                )
                _atomic_write(active, record)
        return record

    def start(
        self,
        args: list[str],
        *,
        kind: str,
        label: str,
        artifact_hint: tuple[str, str] | None = None,
    ) -> str:
        job_id = uuid.uuid4().hex[:12]
        record_path = self.path(job_id)
        stdout_log = self.settings.jobs_dir / f"{job_id}.stdout.log"
        stderr_log = self.settings.jobs_dir / f"{job_id}.stderr.log"
        record: dict[str, Any] = {
            "id": job_id,
            "label": label,
            "kind": kind,
            "status": "queued",
            "command": [*self.settings.cli_command, *args],
            "workspace": str(self.settings.workspace),
            "artifact_hint": list(artifact_hint) if artifact_hint else None,
            "stdout_log": str(stdout_log),
            "stderr_log": str(stderr_log),
            "started_at": _timestamp(),
            "started_epoch": time.time(),
            "worker_pid": None,
            "result": None,
        }
        _atomic_write(record_path, record)
        command = [
            sys.executable,
            "-m",
            "cerberus_re_skill.mcp_jobs",
            "--worker",
            str(record_path),
        ]
        try:
            worker_pid, worker = _spawn_detached_worker(command, self.settings.workspace)
        except OSError as exc:
            record.update(
                status="error",
                finished_at=_timestamp(),
                result=envelope(FAILED, command=record["command"], stderr=str(exc)),
            )
            _atomic_write(record_path, record)
        else:
            if worker is not None:
                # Reap a direct child while this server is alive. A CIM-created
                # Windows worker is independent and is not waitable here.
                threading.Thread(target=worker.wait, daemon=True).start()
            # The detached worker may finish before this process regains the CPU.
            # Never overwrite a terminal record with the parent's stale queued copy.
            current = json.loads(record_path.read_text(encoding="utf-8"))
            if current.get("status") == "queued":
                current["worker_pid"] = worker_pid
                current["status"] = "running"
                _atomic_write(record_path, current)
        append_audit(
            self.settings,
            {
                "tier": "job",
                "action": "start",
                "job_id": job_id,
                "label": label,
                "command": record["command"],
            },
        )
        return job_id

    def list(self, *, include_archived: bool = False) -> list[dict[str, Any]]:
        paths = list(self.settings.jobs_dir.glob("*.json"))
        if include_archived:
            paths.extend(self.settings.job_archive_dir.glob("*.json"))
        records = []
        for path in sorted(paths):
            try:
                record = self.read(path.stem)
            except (OSError, ValueError, json.JSONDecodeError):
                continue
            if record:
                records.append(record)
        return records

    def archive(self, job_id: str) -> dict[str, Any]:
        record = self.read(job_id)
        if record is None:
            return envelope(FAILED, note=f"unknown job_id {job_id}")
        if record.get("status") in {"queued", "running"}:
            return envelope("blocked", note="job is still running")
        active = self.path(job_id)
        archived = self.path(job_id, archived=True)
        if active.is_file():
            record["archived_at"] = _timestamp()
            record["archived"] = True
            _atomic_write(active, record)
            active.replace(archived)
        return envelope(
            "success",
            artifacts=[str(archived)],
            data=record,
            note=f"archived job {job_id}; evidence was not deleted",
        )


def run_worker(record_path: Path) -> int:
    record = json.loads(record_path.read_text(encoding="utf-8"))
    record.update(status="running", worker_pid=os.getpid())
    _atomic_write(record_path, record)
    command = list(record["command"])
    stdout_path = Path(record["stdout_log"])
    stderr_path = Path(record["stderr_log"])
    try:
        with stdout_path.open("w", encoding="utf-8") as stdout_handle, stderr_path.open(
            "w", encoding="utf-8"
        ) as stderr_handle:
            result = subprocess.run(
                command,
                cwd=record["workspace"],
                stdin=subprocess.DEVNULL,
                stdout=stdout_handle,
                stderr=stderr_handle,
                text=True,
                shell=False,
                check=False,
            )
        stdout = stdout_path.read_text(encoding="utf-8", errors="replace")
        stderr = stderr_path.read_text(encoding="utf-8", errors="replace")
        run = make_run_result(
            command,
            returncode=result.returncode,
            stdout=stdout,
            stderr=stderr,
        )
        jobs_dir = record_path.parent
        state_dir = jobs_dir.parent
        settings = MCPSettings(
            cli_command=tuple(command),
            workspace=Path(record["workspace"]),
            state_dir=state_dir,
            jobs_dir=jobs_dir,
            job_archive_dir=jobs_dir / "archive",
            audit_log=state_dir / "audit.jsonl",
            elicit_timeout=120,
        )
        runner = CommandRunner(settings)
        hint = record.get("artifact_hint")
        artifacts = runner.artifacts_for(*hint) if hint else []
        artifacts.extend([str(stdout_path), str(stderr_path)])
        wrapped = runner.wrap(run, kind=record["kind"], artifacts=artifacts)
        record.update(
            status="done" if result.returncode == 0 else "error",
            finished_at=_timestamp(),
            result=wrapped,
        )
    except Exception as exc:  # noqa: BLE001 - worker must persist every terminal failure.
        record.update(
            status="error",
            finished_at=_timestamp(),
            result=envelope(FAILED, command=command, stderr=str(exc)),
        )
    _atomic_write(record_path, record)
    return 0 if record["status"] == "done" else 1


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) == 2 and args[0] == "--worker":
        return run_worker(Path(args[1]))
    print("mcp_jobs is an internal detached worker", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
