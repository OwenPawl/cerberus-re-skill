"""Bridge implementation shard."""

from __future__ import annotations

from cerberus_re_skill.modules.bridge_sessions import *  # noqa: F403

def call_bridge(
    endpoint: str,
    body: str | dict | None = None,
    requested_session: str = "",
    requested_project: str = "",
    requested_program: str = "",
) -> Any:
    """POST *body* to *endpoint* on the current bridge session and return the JSON response."""
    if not endpoint.startswith("/"):
        endpoint = "/" + endpoint

    if body is None:
        body_dict: dict = {}
    elif isinstance(body, str):
        body_dict = json.loads(body) if body.strip() else {}
    else:
        body_dict = body

    # Extract selectors from body if not provided explicitly
    if not requested_session and not requested_project and not requested_program:
        requested_session, requested_project, requested_program = extract_selectors_from_json(
            body_dict
        )

    session_file = resolve_session_file(requested_session, requested_project, requested_program)
    if not session_healthy(session_file):
        raise RuntimeError(
            f"bridge session at {session_file} is stale or unreachable; arm or reopen that target"
        )

    url = _read_session_value(session_file, "bridge_url")
    token = _read_session_value(session_file, "token")
    if not url or not token:
        raise RuntimeError("bridge session is missing bridge_url or token")

    resp = requests.post(
        url.rstrip("/") + endpoint,
        json=body_dict,
        headers={"Authorization": f"Bearer {token}"},
        timeout=30,
    )
    if not resp.ok:
        detail = resp.text.strip()
        try:
            payload = resp.json()
            if isinstance(payload, dict):
                detail = str(payload.get("error") or payload.get("message") or detail)
        except Exception:
            pass
        if len(detail) > 1000:
            detail = detail[:1000] + "...[truncated]"
        raise RuntimeError(f"bridge HTTP {resp.status_code} for {endpoint}: {detail}")
    return resp.json()


# ---------------------------------------------------------------------------
# Bridge status / sessions listing
# ---------------------------------------------------------------------------

def bridge_status(body: str | dict = "{}") -> dict:
    """Return bridge /session response or a disarmed status dict."""
    if isinstance(body, str):
        try:
            body_dict = json.loads(body) if body.strip() else {}
        except Exception:
            body_dict = {}
    else:
        body_dict = body

    requested_session, requested_project, requested_program = extract_selectors_from_json(body_dict)
    prune_stale_sessions()

    try:
        sf = resolve_session_file(requested_session, requested_project, requested_program)
        if session_healthy(sf):
            return call_bridge("/session", body_dict)
        return {"ok": False, "status": "stale", "session_file": str(sf)}
    except RuntimeError:
        return {"ok": False, "status": "disarmed"}


def list_sessions() -> list[dict]:
    """Return a list of session info dicts."""
    prune_stale_sessions()
    current = _current_pointer_session_file()
    sessions = []
    for sf in session_files():
        try:
            data = json.loads(sf.read_text(encoding="utf-8"))
        except Exception:
            continue
        data["session_file"] = str(sf)
        data["current"] = current is not None and str(sf) == str(current)
        sessions.append(data)
    sessions.sort(
        key=lambda x: (x.get("last_heartbeat", ""), x.get("project_name", "")),
        reverse=True,
    )
    return sessions


def _pid_command_line(pid: int) -> str:
    if pid <= 0:
        return ""
    if sys.platform == "win32":
        try:
            result = run(
                [
                    "wmic",
                    "process",
                    "where",
                    f"ProcessId={pid}",
                    "get",
                    "CommandLine",
                    "/value",
                ],
                check=False,
                capture_output=True,
            )
            output = result.stdout.decode(errors="replace")
            for line in output.splitlines():
                if line.startswith("CommandLine="):
                    return line.split("=", 1)[1].strip()
        except Exception:
            return ""
        return ""

    try:
        result = run(["ps", "-p", str(pid), "-o", "command="], check=False, capture_output=True)
        if result.returncode != 0:
            return ""
        return result.stdout.decode(errors="replace").strip()
    except Exception:
        return ""


def _is_safe_ghidra_pid(pid: int) -> tuple[bool, str]:
    command_line = _pid_command_line(pid)
    if not command_line:
        return False, "could not inspect process command line"
    lowered = command_line.lower()
    markers = ("ghidra.ghidrarun", "ghidrarun", "ghidra.app")
    if any(marker in lowered for marker in markers):
        return True, command_line
    return False, command_line


def _terminate_pid(
    pid: int,
    *,
    timeout_seconds: float = 10.0,
    kill_after_timeout: bool = True,
) -> dict[str, Any]:
    if pid <= 0:
        raise RuntimeError(f"invalid pid: {pid}")
    if pid == os.getpid():
        raise RuntimeError("refusing to terminate the current ghidra-re process")
    if not check_pid_alive(pid):
        return {"terminated": True, "method": "already-exited"}

    deadline = time.time() + max(0.0, timeout_seconds)

    if sys.platform == "win32":
        result = run(["taskkill", "/PID", str(pid), "/T"], check=False, capture_output=True)
        while time.time() < deadline:
            if not check_pid_alive(pid):
                return {"terminated": True, "method": "taskkill"}
            time.sleep(0.25)
        if kill_after_timeout and check_pid_alive(pid):
            run(["taskkill", "/PID", str(pid), "/T", "/F"], check=False, capture_output=True)
            while time.time() < deadline + max(1.0, timeout_seconds):
                if not check_pid_alive(pid):
                    return {"terminated": True, "method": "taskkill-force"}
                time.sleep(0.25)
        stderr = result.stderr.decode(errors="replace").strip() if result.stderr else ""
        return {"terminated": False, "method": "taskkill", "error": stderr}

    os.kill(pid, signal.SIGTERM)
    while time.time() < deadline:
        if not check_pid_alive(pid):
            return {"terminated": True, "method": "sigterm"}
        time.sleep(0.25)
    if kill_after_timeout and check_pid_alive(pid):
        os.kill(pid, signal.SIGKILL)
        while time.time() < deadline + max(1.0, timeout_seconds):
            if not check_pid_alive(pid):
                return {"terminated": True, "method": "sigkill"}
            time.sleep(0.25)
    return {"terminated": False, "method": "sigterm"}


def _matching_session_summary(session_file: Path) -> dict[str, Any]:
    data = _read_session_json(session_file)
    return {
        "session_id": data.get("session_id", ""),
        "project_name": data.get("project_name", ""),
        "program_name": data.get("program_name", ""),
        "pid": data.get("pid", ""),
        "session_file": str(session_file),
    }


def close_bridge(
    requested_session: str = "",
    requested_project: str = "",
    requested_program: str = "",
    *,
    disarm_timeout_seconds: int = 15,
    terminate_timeout_seconds: float = 10.0,
    kill_after_timeout: bool = True,
) -> dict[str, Any]:
    """Disarm a selected bridge session and terminate its owning Ghidra process."""
    if not requested_session and not requested_project and not requested_program:
        raise RuntimeError("bridge close requires --session, --project, or --program")

    # Resolve from raw session files first.  A close command is often used
    # specifically when the HTTP bridge is stale but the owning JVM still exists.
    matches = [
        session_file
        for session_file in session_files()
        if _session_matches(session_file, requested_session, requested_project, requested_program)
    ]
    if not matches:
        return {"ok": True, "message": "Bridge already closed"}
    current = None
    if cfg.bridge_current_file.exists():
        current_path = _read_session_value(cfg.bridge_current_file, "session_file")
        current = Path(current_path) if current_path else None
    if len(matches) == 1:
        sf = matches[0]
    elif current and current in matches:
        sf = current
    else:
        raise RuntimeError("multiple matching bridge sessions found; use --session to disambiguate")

    pid = _session_pid(sf)
    if pid is None:
        _remove_current_if_matches(sf)
        sf.unlink(missing_ok=True)
        return {"ok": True, "message": "Bridge state cleared; session file had no valid pid"}

    shared_sessions = [
        other
        for other in session_files()
        if other != sf and _session_pid(other) == pid and session_pid_alive(other)
    ]
    if shared_sessions:
        return {
            "ok": False,
            "message": "Refusing to terminate Ghidra because the selected PID is shared by other bridge sessions",
            "pid": pid,
            "session_file": str(sf),
            "shared_sessions": [_matching_session_summary(other) for other in shared_sessions],
        }

    safe, command_line = _is_safe_ghidra_pid(pid)
    if not safe:
        return {
            "ok": False,
            "message": "Refusing to terminate process because it does not look like a Ghidra JVM",
            "pid": pid,
            "process_command": command_line,
            "session_file": str(sf),
        }

    session_id = _read_session_value(sf, "session_id")
    proj = _read_session_value(sf, "project_name")
    prog = _read_session_value(sf, "program_name")
    if session_id:
        write_request_file("disarm", session_id, proj, prog)
    disarmed = wait_for_disarm(disarm_timeout_seconds, session_id, proj, prog) if session_id else False

    termination = _terminate_pid(
        pid,
        timeout_seconds=terminate_timeout_seconds,
        kill_after_timeout=kill_after_timeout,
    )
    _remove_current_if_matches(sf)
    sf.unlink(missing_ok=True)
    prune_stale_sessions()

    ok = bool(termination.get("terminated"))
    return {
        "ok": ok,
        "message": "Bridge closed" if ok else "Bridge disarmed but owning Ghidra process is still running",
        "session_id": session_id,
        "project_name": proj,
        "program_name": prog,
        "pid": pid,
        "session_file": str(sf),
        "disarmed": disarmed,
        "termination": termination,
    }


def _ghidra_processes() -> list[dict[str, Any]]:
    if sys.platform == "win32":
        try:
            result = run(
                [
                    "wmic",
                    "process",
                    "where",
                    "CommandLine like '%ghidra.GhidraRun%'",
                    "get",
                    "ProcessId,CommandLine",
                    "/format:csv",
                ],
                check=False,
                capture_output=True,
            )
            processes = []
            for line in result.stdout.decode(errors="replace").splitlines():
                if not line.strip() or line.startswith("Node,"):
                    continue
                parts = line.split(",", 2)
                if len(parts) == 3:
                    processes.append({"pid": parts[2].strip(), "command": parts[1].strip()})
            return processes
        except Exception:
            return []

    try:
        result = run(["pgrep", "-fl", "java.*ghidra.GhidraRun"], check=False, capture_output=True)
    except Exception:
        return []
    processes = []
    for line in result.stdout.decode(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        pid_text, _, command = line.partition(" ")
        try:
            pid: int | str = int(pid_text)
        except ValueError:
            pid = pid_text
        processes.append({"pid": pid, "command": command})
    return processes


def audit_bridge_state() -> dict[str, Any]:
    """Return raw bridge session/JVM diagnostics without pruning files first."""
    ensure_bridge_dirs()
    current_session_file_path = _read_session_value(cfg.bridge_current_file, "session_file")
    sessions = []
    live_session_pids: set[int] = set()
    stale_session_files = []

    for sf in session_files():
        data = _read_session_json(sf)
        pid = _session_pid(sf)
        pid_alive = check_pid_alive(pid) if pid is not None else False
        has_bridge_auth = bool(data.get("bridge_url")) and bool(data.get("token"))
        post_install = _session_is_post_install(sf)
        healthy = False
        if pid_alive and has_bridge_auth and post_install:
            healthy = session_healthy(sf)
        if pid is not None and pid_alive:
            live_session_pids.add(pid)
        if not healthy:
            stale_session_files.append(str(sf))
        sessions.append(
            {
                **data,
                "session_file": str(sf),
                "current": current_session_file_path == str(sf),
                "pid_alive": pid_alive,
                "post_install": post_install,
                "has_bridge_auth": has_bridge_auth,
                "healthy": healthy,
            }
        )

    ghidra_processes = _ghidra_processes()
    orphan_ghidra_processes = [
        proc
        for proc in ghidra_processes
        if isinstance(proc.get("pid"), int) and proc.get("pid") not in live_session_pids
    ]
    return {
        "ok": not stale_session_files,
        "bridge_config_dir": str(cfg.bridge_config_dir),
        "current_file": str(cfg.bridge_current_file),
        "current_session_file": current_session_file_path,
        "sessions": sessions,
        "stale_session_files": stale_session_files,
        "ghidra_processes": ghidra_processes,
        "orphan_ghidra_processes": orphan_ghidra_processes,
    }


# ---------------------------------------------------------------------------
# Bridge request files (arm/disarm signals to Ghidra)
# ---------------------------------------------------------------------------

__all__ = [name for name in globals() if not name.startswith('__')]
