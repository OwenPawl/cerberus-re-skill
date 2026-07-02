"""Bridge session management: arm, disarm, build, install, call, sessions, status."""

from __future__ import annotations

import json
import os
import signal
import shutil
import sys
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

from cerberus_re_skill.core.config import cfg
from cerberus_re_skill.core.ghidra_locator import (
    bridge_settings_dir,
    can_start_jdk,
    detect_ghidra_dir,
    detect_jdk_dir,
    gradle_wrapper_path,
    is_valid_ghidra_dir,
    is_valid_jdk_dir,
    resolve_ghidra_dir,
)
from cerberus_re_skill.core.subprocess_utils import (
    check_pid_alive,
    is_ghidra_running,
    run,
)
from cerberus_re_skill.core.utils import (
    extract_selectors_from_json,
    new_uuid,
    timestamp,
    utc_now,
    write_json,
)


# ---------------------------------------------------------------------------
# Auto-configure helpers
# ---------------------------------------------------------------------------

def auto_configure() -> None:
    """Detect Ghidra/JDK and update cfg in-place if needed."""
    if not is_valid_ghidra_dir(cfg.ghidra_install_dir):
        detected = detect_ghidra_dir()
        if detected:
            cfg.ghidra_install_dir = detected
            cfg._refresh_script_dirs()

    if not can_start_jdk(cfg.ghidra_jdk):
        detected_jdk = detect_jdk_dir()
        if detected_jdk:
            cfg.ghidra_jdk = detected_jdk


def require_tools() -> None:
    """Raise RuntimeError if Ghidra or JDK are missing."""
    auto_configure()
    if not is_valid_ghidra_dir(cfg.ghidra_install_dir):
        raise RuntimeError(f"missing Ghidra install at {cfg.ghidra_install_dir}")
    if not is_valid_jdk_dir(cfg.ghidra_jdk):
        raise RuntimeError(f"missing JDK at {cfg.ghidra_jdk}")
    if not can_start_jdk(cfg.ghidra_jdk):
        raise RuntimeError(
            f"JDK cannot start at {cfg.ghidra_jdk}; on Apple Silicon with "
            "amfi_get_out_of_my_way=1, install an x64 Java 21 JDK and run under Rosetta"
        )


def export_env() -> dict[str, str]:
    """Return environment additions for subprocesses (JAVA_HOME, PATH)."""
    auto_configure()
    java_home = str(cfg.ghidra_jdk)
    path_sep = ";" if sys.platform == "win32" else ":"
    new_path = str(Path(java_home) / "bin") + path_sep + os.environ.get("PATH", "")
    return {
        "GHIDRA_JDK": java_home,
        "JAVA_HOME": java_home,
        "JAVA_HOME_OVERRIDE": java_home,
        "PATH": new_path,
        "GHIDRA_INSTALL_DIR": str(cfg.ghidra_install_dir),
    }


# ---------------------------------------------------------------------------
# Workspace / dir helpers
# ---------------------------------------------------------------------------

def ensure_workspace() -> None:
    for d in [
        cfg.projects_dir,
        cfg.exports_dir,
        cfg.logs_dir,
        cfg.sources_cache_dir,
    ]:
        d.mkdir(parents=True, exist_ok=True)


def ensure_bridge_dirs() -> None:
    for d in [cfg.bridge_config_dir, cfg.bridge_sessions_dir, cfg.bridge_requests_dir]:
        d.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Session JSON helpers
# ---------------------------------------------------------------------------

def _read_session_value(path: Path, key: str) -> str:
    if not path.exists():
        return ""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        value = payload.get(key, "")
        if isinstance(value, bool):
            return "true" if value else "false"
        return str(value) if value is not None else ""
    except Exception:
        return ""


def session_files() -> list[Path]:
    ensure_bridge_dirs()
    return sorted(cfg.bridge_sessions_dir.glob("*.json"))


def _read_session_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else {}
    except Exception:
        return {}


def _session_pid(session_file: Path) -> int | None:
    pid_str = _read_session_value(session_file, "pid")
    if not pid_str:
        return None
    try:
        pid = int(pid_str)
    except (TypeError, ValueError):
        return None
    return pid if pid > 0 else None


# ---------------------------------------------------------------------------
# Session health checks
# ---------------------------------------------------------------------------

def _bridge_request(session_file: Path, endpoint: str, body: dict | None = None) -> dict | None:
    """Make a POST request to the bridge and return the parsed response, or None."""
    body = body or {}
    url = _read_session_value(session_file, "bridge_url")
    token = _read_session_value(session_file, "token")
    if not url or not token:
        return None
    try:
        resp = requests.post(
            url.rstrip("/") + endpoint,
            json=body,
            headers={"Authorization": f"Bearer {token}"},
            timeout=3,
        )
        resp.raise_for_status()
        payload = resp.json()
        if not payload.get("ok"):
            return None
        return payload
    except Exception:
        return None


def session_pid_alive(session_file: Path) -> bool:
    if not session_file.exists():
        return False
    pid = _session_pid(session_file)
    if pid is None:
        return False
    return check_pid_alive(pid)


def _session_is_post_install(session_file: Path) -> bool:
    install_ts = _read_session_value(cfg.bridge_install_state_file, "installed_at")
    if not install_ts:
        return True
    session_ts = _read_session_value(session_file, "started_at")
    if not session_ts:
        return False
    try:
        def _parse(s: str) -> datetime:
            s = s.strip()
            if s.endswith("Z"):
                s = s[:-1] + "+00:00"
            dt = datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt

        return _parse(session_ts) >= _parse(install_ts)
    except Exception:
        return False


def session_healthy(session_file: Path) -> bool:
    if not session_file.exists():
        return False
    if not session_pid_alive(session_file):
        return False
    if not _session_is_post_install(session_file):
        return False
    url = _read_session_value(session_file, "bridge_url")
    token = _read_session_value(session_file, "token")
    if not url or not token:
        return False
    if _bridge_request(session_file, "/health") is None:
        return False
    if _bridge_request(session_file, "/session") is None:
        return False
    return True


# ---------------------------------------------------------------------------
# Current session pointer management
# ---------------------------------------------------------------------------

_LOCK_SUFFIX = "bridge-current.lock"
_LOCK_STALE_SECONDS = 30


def _acquire_lock(stale_timeout: float = _LOCK_STALE_SECONDS) -> Path:
    """Acquire the bridge-current directory lock.

    Retries up to ~10 s (200 × 50 ms).  If the lock directory is older
    than *stale_timeout* seconds it is removed and acquisition retried
    immediately — this handles the case where a previous process crashed
    without releasing the lock.
    """
    lock = cfg.bridge_config_dir / _LOCK_SUFFIX
    ensure_bridge_dirs()
    for _ in range(200):
        try:
            lock.mkdir()
            return lock
        except FileExistsError:
            # Check for a stale lock (process crashed without releasing).
            try:
                age = time.time() - lock.stat().st_mtime
                if age > stale_timeout:
                    try:
                        lock.rmdir()
                    except Exception:
                        pass
            except FileNotFoundError:
                pass  # Lock was just released; retry immediately.
            time.sleep(0.05)
    raise RuntimeError(f"timed out waiting for bridge-current lock at {lock}")


def _release_lock(lock: Path) -> None:
    try:
        lock.rmdir()
    except Exception:
        pass


def write_current_from_session_file(session_file: Path) -> None:
    if not session_file.exists():
        raise RuntimeError(f"session file not found: {session_file}")
    ensure_bridge_dirs()
    session_id = _read_session_value(session_file, "session_id")
    if not session_id:
        raise RuntimeError(f"session file is missing session_id: {session_file}")
    payload = {
        "version": 1,
        "session_id": session_id,
        "session_file": str(session_file),
        "selected_at": utc_now(),
    }
    lock = _acquire_lock()
    try:
        tmp = cfg.bridge_config_dir / f"bridge-current.{new_uuid()}.tmp"
        write_json(tmp, payload)
        tmp.rename(cfg.bridge_current_file)
    finally:
        _release_lock(lock)


def _remove_current_if_matches(session_file: Path) -> None:
    if not cfg.bridge_current_file.exists():
        return
    current_sf = _read_session_value(cfg.bridge_current_file, "session_file")
    if current_sf and current_sf == str(session_file):
        lock = _acquire_lock()
        try:
            cfg.bridge_current_file.unlink(missing_ok=True)
        finally:
            _release_lock(lock)


# ---------------------------------------------------------------------------
# Stale-session pruning
# ---------------------------------------------------------------------------

def prune_stale_sessions() -> None:
    ensure_bridge_dirs()
    for sf in list(session_files()):
        if not session_healthy(sf):
            _remove_current_if_matches(sf)
            sf.unlink(missing_ok=True)
    if cfg.bridge_current_file.exists():
        sf_path = _read_session_value(cfg.bridge_current_file, "session_file")
        if not sf_path or not Path(sf_path).exists():
            cfg.bridge_current_file.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Session resolution
# ---------------------------------------------------------------------------

def _current_pointer_session_file() -> Path | None:
    prune_stale_sessions()
    if cfg.bridge_current_file.exists():
        sf_path = _read_session_value(cfg.bridge_current_file, "session_file")
        if sf_path:
            p = Path(sf_path)
            if p.exists():
                return p
    return None


def current_session_file() -> Path | None:
    current = _current_pointer_session_file()
    if current:
        return current
    prune_stale_sessions()
    files = session_files()
    if len(files) == 1:
        return files[0]
    return None


def _session_matches(
    session_file: Path,
    requested_session: str,
    requested_project: str,
    requested_program: str,
) -> bool:
    if not session_file.exists():
        return False
    if requested_session:
        sid = _read_session_value(session_file, "session_id")
        if not sid or not (sid == requested_session or sid.startswith(requested_session)):
            return False
    if requested_project:
        proj_name = _read_session_value(session_file, "project_name")
        proj_path = _read_session_value(session_file, "project_path")
        expected_path = str(cfg.project_file(requested_project))
        if not (
            proj_name == requested_project
            or proj_path == expected_path
            or proj_path.endswith(f"/{requested_project}.gpr")
        ):
            return False
    if requested_program:
        prog_name = _read_session_value(session_file, "program_name")
        prog_path = _read_session_value(session_file, "program_path")
        if not (
            prog_name == requested_program
            or prog_path == requested_program
            or prog_path.endswith(f"/{requested_program}")
        ):
            return False
    return True


def find_matching_sessions(
    requested_session: str = "",
    requested_project: str = "",
    requested_program: str = "",
) -> list[Path]:
    prune_stale_sessions()
    return [
        sf
        for sf in session_files()
        if _session_matches(sf, requested_session, requested_project, requested_program)
    ]


def resolve_session_file(
    requested_session: str = "",
    requested_project: str = "",
    requested_program: str = "",
) -> Path:
    if not requested_session and not requested_project and not requested_program:
        sf = current_session_file()
        if sf:
            return sf
        raise RuntimeError("bridge session not found; arm or select a bridge session first")

    matches = find_matching_sessions(requested_session, requested_project, requested_program)
    if not matches:
        raise RuntimeError(
            f"no bridge session found for session={requested_session!r} "
            f"project={requested_project!r} program={requested_program!r}"
        )
    if len(matches) == 1:
        return matches[0]
    current = _current_pointer_session_file()
    if current and current in matches:
        return current
    raise RuntimeError(
        "multiple matching bridge sessions found; use session=<id> to disambiguate"
    )


# ---------------------------------------------------------------------------
# Bridge request files (arm/disarm signals to Ghidra)
# ---------------------------------------------------------------------------

def write_request_file(
    command: str,
    requested_session: str = "",
    project_name: str = "",
    program_name: str = "",
) -> Path:
    ensure_bridge_dirs()
    request_id = new_uuid()
    payload = {
        "version": 1,
        "request_id": request_id,
        "command": command,
        "session_id": requested_session,
        "project_name": project_name,
        "program_name": program_name,
        "requested_at": utc_now(),
    }
    request_file = cfg.bridge_requests_dir / f"{request_id}.json"
    tmp = cfg.bridge_requests_dir / f"{request_id}.tmp"
    write_json(tmp, payload)
    tmp.rename(request_file)
    return request_file


def wait_for_disarm(
    timeout_seconds: int = 15,
    requested_session: str = "",
    requested_project: str = "",
    requested_program: str = "",
) -> bool:
    started = time.time()
    while True:
        prune_stale_sessions()
        matches = find_matching_sessions(requested_session, requested_project, requested_program)
        if not matches:
            return True
        if time.time() - started >= timeout_seconds:
            return False
        time.sleep(1)


__all__ = [name for name in globals() if not name.startswith('__')]
__all__ = [name for name in globals() if not name.startswith('__')]
