"""Per-project lock coordination for Ghidra headless operations."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from cerberus_re_skill.core.config import cfg
from cerberus_re_skill.core.subprocess_utils import check_pid_alive
from cerberus_re_skill.core.utils import sanitize_name, utc_now


DEFAULT_TIMEOUT_SECONDS = 600
DEFAULT_STALE_SECONDS = 1800


def lock_path(project_name: str, project_location: str | Path | None = None) -> Path:
    key_source = str(project_location or project_name)
    key = sanitize_name(key_source)
    return cfg.config_home / "headless-locks" / f"{key}.lockdir"


@contextmanager
def project_headless_lock(
    project_name: str,
    project_location: str | Path | None = None,
    *,
    operation: str = "headless",
    timeout_seconds: int | None = None,
    stale_seconds: int | None = None,
) -> Iterator[Path]:
    path = acquire_project_headless_lock(
        project_name,
        project_location,
        operation=operation,
        timeout_seconds=timeout_seconds,
        stale_seconds=stale_seconds,
    )
    try:
        yield path
    finally:
        release_project_headless_lock(path)


def acquire_project_headless_lock(
    project_name: str,
    project_location: str | Path | None = None,
    *,
    operation: str = "headless",
    timeout_seconds: int | None = None,
    stale_seconds: int | None = None,
    owner_pid: int | None = None,
) -> Path:
    timeout = _int_env("GHIDRA_HEADLESS_LOCK_TIMEOUT", timeout_seconds, DEFAULT_TIMEOUT_SECONDS)
    stale_after = _int_env("GHIDRA_HEADLESS_LOCK_STALE_SECONDS", stale_seconds, DEFAULT_STALE_SECONDS)
    path = lock_path(project_name, project_location)
    path.parent.mkdir(parents=True, exist_ok=True)
    started = time.time()
    pid = int(owner_pid or os.getpid())
    while True:
        try:
            path.mkdir()
            _write_metadata(path, project_name, project_location, operation, pid)
            return path
        except FileExistsError:
            if _is_stale(path, stale_after):
                _reclaim(path)
                continue
            if time.time() - started >= timeout:
                raise RuntimeError(
                    f"timed out waiting for Ghidra headless project lock at {path}; "
                    f"current owner: {_owner_summary(path)}"
                )
            time.sleep(1)


def release_project_headless_lock(path: str | Path, *, owner_pid: int | None = None) -> bool:
    lock = Path(path)
    metadata = _read_metadata(lock)
    pid = int(owner_pid or os.getpid())
    if not _metadata_matches_owner(metadata, pid):
        return False
    quarantine = lock.with_name(f".{lock.name}.release-{uuid.uuid4().hex}")
    try:
        lock.rename(quarantine)
    except FileNotFoundError:
        return False
    shutil.rmtree(quarantine, ignore_errors=True)
    return True


def _write_metadata(
    path: Path,
    project_name: str,
    project_location: str | Path | None,
    operation: str,
    owner_pid: int,
) -> None:
    now = utc_now()
    payload = {
        "version": 2,
        "lease_id": str(uuid.uuid4()),
        "project_name": project_name,
        "project_location": str(project_location or ""),
        "operation": operation,
        "pid": owner_pid,
        "process_start": _process_start_identity(owner_pid),
        "created_at": now,
        "heartbeat_at": now,
    }
    output = path / "owner.json"
    temporary = path / f"owner.{uuid.uuid4().hex}.tmp"
    temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    temporary.replace(output)


def _is_stale(path: Path, stale_seconds: int) -> bool:
    metadata = _read_metadata(path)
    pid = _metadata_pid(metadata)
    age = _heartbeat_age(path, metadata)
    if pid is None:
        return age >= stale_seconds
    if not check_pid_alive(pid):
        return age >= stale_seconds
    expected_start = str(metadata.get("process_start") or "")
    actual_start = _process_start_identity(pid)
    if expected_start and actual_start and expected_start != actual_start:
        return age >= stale_seconds
    return False


def _read_metadata(path: Path) -> dict:
    try:
        payload = json.loads((path / "owner.json").read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else {}
    except (FileNotFoundError, OSError, ValueError):
        return {}


def _metadata_pid(metadata: dict) -> int | None:
    try:
        pid = int(metadata.get("pid", 0))
    except (TypeError, ValueError):
        return None
    return pid if pid > 0 else None


def _metadata_matches_owner(metadata: dict, owner_pid: int) -> bool:
    if _metadata_pid(metadata) != owner_pid:
        return False
    expected_start = str(metadata.get("process_start") or "")
    actual_start = _process_start_identity(owner_pid)
    return not expected_start or not actual_start or expected_start == actual_start


def _heartbeat_age(path: Path, metadata: dict) -> float:
    heartbeat = str(metadata.get("heartbeat_at") or metadata.get("created_at") or "")
    if heartbeat:
        try:
            parsed = datetime.fromisoformat(heartbeat.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return max(0.0, time.time() - parsed.timestamp())
        except ValueError:
            pass
    try:
        return max(0.0, time.time() - path.stat().st_mtime)
    except FileNotFoundError:
        return 0.0


def _reclaim(path: Path) -> bool:
    quarantine = path.with_name(f".{path.name}.stale-{uuid.uuid4().hex}")
    try:
        path.rename(quarantine)
    except FileNotFoundError:
        return False
    shutil.rmtree(quarantine, ignore_errors=True)
    return True


def _owner_summary(path: Path) -> str:
    metadata = _read_metadata(path)
    if not metadata:
        return "unreadable owner metadata"
    pid = _metadata_pid(metadata)
    alive = check_pid_alive(pid) if pid is not None else False
    return (
        f"pid={pid or 'unknown'} alive={str(alive).lower()} "
        f"operation={metadata.get('operation') or 'unknown'} "
        f"heartbeat={metadata.get('heartbeat_at') or metadata.get('created_at') or 'unknown'}"
    )


def _process_start_identity(pid: int) -> str:
    if pid <= 0:
        return ""
    if sys.platform == "win32":
        return _windows_process_start_identity(pid)
    proc_stat = Path(f"/proc/{pid}/stat")
    try:
        suffix = proc_stat.read_text(encoding="utf-8").rsplit(")", 1)[1].split()
        if len(suffix) > 19:
            return f"proc-start-ticks:{suffix[19]}"
    except (FileNotFoundError, OSError, IndexError):
        pass
    try:
        result = subprocess.run(
            ["ps", "-o", "lstart=", "-p", str(pid)],
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
        )
        value = result.stdout.strip()
        return f"ps-lstart:{value}" if result.returncode == 0 and value else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def _windows_process_start_identity(pid: int) -> str:
    try:
        import ctypes
        import ctypes.wintypes

        handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)
        if not handle:
            return ""
        try:
            created = ctypes.wintypes.FILETIME()
            exited = ctypes.wintypes.FILETIME()
            kernel = ctypes.wintypes.FILETIME()
            user = ctypes.wintypes.FILETIME()
            if not ctypes.windll.kernel32.GetProcessTimes(
                handle,
                ctypes.byref(created),
                ctypes.byref(exited),
                ctypes.byref(kernel),
                ctypes.byref(user),
            ):
                return ""
            ticks = (created.dwHighDateTime << 32) | created.dwLowDateTime
            return f"win-filetime:{ticks}"
        finally:
            ctypes.windll.kernel32.CloseHandle(handle)
    except Exception:
        return ""


def _int_env(name: str, value: int | None, default: int) -> int:
    if value is not None:
        return int(value)
    raw = os.environ.get(name)
    if raw:
        try:
            return int(raw)
        except ValueError:
            return default
    return default
