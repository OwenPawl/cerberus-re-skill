"""Bridge session management: arm, disarm, build, install, call, sessions, status."""

from __future__ import annotations

import json
import os
import shutil
import sys
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

from ghidra_re_skill.core.config import cfg
from ghidra_re_skill.core.ghidra_locator import (
    bridge_settings_dir,
    detect_ghidra_dir,
    detect_jdk_dir,
    gradle_wrapper_path,
    is_valid_ghidra_dir,
    is_valid_jdk_dir,
    resolve_ghidra_dir,
)
from ghidra_re_skill.core.subprocess_utils import (
    check_pid_alive,
    is_ghidra_running,
    run,
)
from ghidra_re_skill.core.utils import (
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

    if not is_valid_jdk_dir(cfg.ghidra_jdk):
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
        cfg.investigations_dir,
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
    pid_str = _read_session_value(session_file, "pid")
    if not pid_str:
        return False
    try:
        return check_pid_alive(int(pid_str))
    except (ValueError, TypeError):
        return False


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
# Bridge call
# ---------------------------------------------------------------------------

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
    resp.raise_for_status()
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


# ---------------------------------------------------------------------------
# Bridge arm
# ---------------------------------------------------------------------------

def _launch_gui_project(project_file: Path, new_instance: bool = False) -> None:
    """Launch Ghidra GUI with the given project file (detached)."""
    ghidra_run = None
    from ghidra_re_skill.core.ghidra_locator import ghidra_run_path

    ghidra_run = ghidra_run_path(cfg.ghidra_install_dir)
    if not ghidra_run:
        raise RuntimeError(f"ghidraRun not found in {cfg.ghidra_install_dir}")

    env = export_env()

    if sys.platform == "win32":
        import subprocess

        subprocess.Popen(
            [str(ghidra_run), str(project_file)],
            shell=False,
            env={**os.environ, **env},
            creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP,
            close_fds=True,
        )
    else:
        import subprocess

        log_dir = cfg.log_dir(project_file.stem) / "bridge-launch"
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / f"launch-{timestamp()}.log"

        with open(log_file, "wb") as lf:
            subprocess.Popen(
                [str(ghidra_run), str(project_file)],
                shell=False,
                env={**os.environ, **env},
                stdin=subprocess.DEVNULL,
                stdout=lf,
                stderr=lf,
                start_new_session=True,
                close_fds=True,
            )


def wait_for_session(
    timeout_seconds: int = 60,
    expected_project: str = "",
    expected_program: str = "",
) -> Path | None:
    started = time.time()
    while True:
        try:
            sf = resolve_session_file("", expected_project, expected_program)
            if session_healthy(sf):
                return sf
        except RuntimeError:
            pass
        if time.time() - started >= timeout_seconds:
            return None
        time.sleep(1)


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


def _bridge_installed_dir() -> Path | None:
    ghidra_dir = cfg.ghidra_install_dir
    settings = bridge_settings_dir(ghidra_dir)
    if not settings:
        return None
    return settings / "Extensions" / "Ghidra" / "CodexGhidraBridge"


def arm(project_name: str, program_name: str = "") -> dict:
    """Arm the bridge for *project_name* (and optionally *program_name*)."""
    require_tools()
    ensure_workspace()
    ensure_bridge_dirs()
    prune_stale_sessions()

    project_file = cfg.project_file(project_name)
    if not project_file.exists():
        raise RuntimeError(f"project {project_name} not found at {project_file}")

    # Install bridge extension if needed
    installed = _bridge_installed_dir()
    if installed is None or not installed.exists():
        install()

    # Check for an existing healthy session
    try:
        existing = resolve_session_file("", project_name, program_name)
        if session_healthy(existing):
            write_current_from_session_file(existing)
            url = _read_session_value(existing, "bridge_url")
            return {"ok": True, "bridge_url": url, "session_file": str(existing), "reused": True}
    except RuntimeError:
        pass

    # Write arm request
    write_request_file("arm", "", project_name, program_name)

    # Wait if Ghidra is already running
    if is_ghidra_running():
        sf = wait_for_session(8, project_name, program_name)
        if sf:
            write_current_from_session_file(sf)
            url = _read_session_value(sf, "bridge_url")
            return {"ok": True, "bridge_url": url, "session_file": str(sf)}

    # Launch Ghidra
    _launch_gui_project(project_file)
    sf = wait_for_session(60, project_name, program_name)
    if not sf:
        raise RuntimeError(
            "timed out waiting for bridge session; open the project in Ghidra and "
            "run EnableCodexBridge.java once if needed"
        )
    write_current_from_session_file(sf)
    url = _read_session_value(sf, "bridge_url")
    return {"ok": True, "bridge_url": url, "session_file": str(sf)}


# ---------------------------------------------------------------------------
# Bridge disarm
# ---------------------------------------------------------------------------

def disarm(
    requested_session: str = "",
    requested_project: str = "",
    requested_program: str = "",
) -> dict:
    """Disarm a bridge session."""
    prune_stale_sessions()
    try:
        sf = resolve_session_file(requested_session, requested_project, requested_program)
    except RuntimeError:
        return {"ok": True, "message": "Bridge already disarmed"}

    session_id = _read_session_value(sf, "session_id")
    proj = _read_session_value(sf, "project_name")
    prog = _read_session_value(sf, "program_name")
    write_request_file("disarm", session_id, proj, prog)

    if wait_for_disarm(15, session_id, proj, prog):
        return {"ok": True, "message": "Bridge disarmed"}

    if not session_healthy(sf):
        sf.unlink(missing_ok=True)
        prune_stale_sessions()
        return {"ok": True, "message": "Bridge disarmed (cleared stale session state)"}

    raise RuntimeError("timed out waiting for bridge to disarm")


# ---------------------------------------------------------------------------
# Bridge build / install
# ---------------------------------------------------------------------------

def build() -> Path:
    """Build the bridge extension using the bundled Gradle wrapper."""
    require_tools()
    env = export_env()

    if not cfg.bridge_extension_dir.exists():
        raise RuntimeError(f"bridge extension directory not found at {cfg.bridge_extension_dir}")

    gradle_cmd: list[str | Path]
    gradle_cwd: Path | None = None
    if sys.platform == "win32":
        java = Path(cfg.ghidra_jdk) / "bin" / "java.exe"
        wrapper_jar = cfg.ghidra_install_dir / "support" / "gradle" / "gradle-wrapper.jar"
        wrapper_dir = wrapper_jar.parent
        if not java.exists():
            raise RuntimeError(f"Java not found at {java}")
        if not wrapper_jar.exists():
            raise RuntimeError(f"Gradle wrapper jar not found at {wrapper_jar}")
        gradle_cmd = [
            java,
            "-classpath",
            wrapper_jar,
            "org.gradle.wrapper.GradleWrapperMain",
        ]
        gradle_cwd = wrapper_dir
    else:
        gradle = gradle_wrapper_path(cfg.ghidra_install_dir)
        if not gradle:
            raise RuntimeError(f"Gradle wrapper not found in {cfg.ghidra_install_dir}")
        gradle_cmd = [gradle]

    run(
        gradle_cmd
        + [
            "-p",
            str(cfg.bridge_extension_dir),
            f"-PGHIDRA_INSTALL_DIR={cfg.ghidra_install_dir}",
            "clean",
            "distributeExtension",
        ],
        env=env,
        cwd=gradle_cwd,
    )

    zips = sorted(cfg.bridge_dist_dir.glob("ghidra_*_CodexGhidraBridge.zip"))
    if not zips:
        raise RuntimeError(f"bridge zip not found in {cfg.bridge_dist_dir}")
    return zips[-1]


def install() -> dict:
    """Build and install the bridge extension into the user's Ghidra settings."""
    require_tools()

    zip_path = build()
    installed_at = utc_now()

    ghidra_dir = cfg.ghidra_install_dir
    settings = bridge_settings_dir(ghidra_dir)
    if not settings:
        raise RuntimeError("could not determine Ghidra settings directory")

    extensions_dir = settings / "Extensions" / "Ghidra"
    installed_dir = extensions_dir / "CodexGhidraBridge"
    legacy_installed_dir = settings / "Extensions" / "Ghidra" / "CodexGhidraBridge"
    tools_dir = settings / "tools"
    frontend_tool_file = settings / "FrontEndTool.xml"

    extensions_dir.mkdir(parents=True, exist_ok=True)

    # Extract zip to a temp dir inside our config area
    tmp_root = cfg.bridge_config_dir / f"bridge-install-{new_uuid()}"
    tmp_root.mkdir(parents=True, exist_ok=True)
    try:
        with zipfile.ZipFile(zip_path) as archive:
            archive.extractall(tmp_root)

        if installed_dir.exists():
            shutil.rmtree(installed_dir)
        shutil.copytree(tmp_root / "CodexGhidraBridge", installed_dir)
        _verify_bridge_install(installed_dir)

        if legacy_installed_dir != installed_dir and legacy_installed_dir.exists():
            shutil.rmtree(legacy_installed_dir)

        # Patch tool config files
        if tools_dir.exists():
            for tool_file in sorted(tools_dir.glob("*.tcd")):
                _patch_tool_xml(tool_file)

        if frontend_tool_file.exists():
            _patch_frontend_xml(frontend_tool_file)

    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)

    # Write install state
    write_json(
        cfg.bridge_install_state_file,
        {"version": 1, "installed_at": installed_at, "zip_path": str(zip_path)},
    )
    _clear_state_files()

    return {
        "ok": True,
        "installed_dir": str(installed_dir),
        "settings_dir": str(settings),
        "installed_at": installed_at,
    }


def _verify_bridge_install(installed_dir: Path) -> None:
    """Verify the user-level bridge extension directory is complete."""
    required = [
        installed_dir / "extension.properties",
        installed_dir / "Module.manifest",
        installed_dir / "ghidra_scripts" / "EnableCodexBridge.java",
    ]
    missing = [str(path) for path in required if not path.exists()]
    jars = list((installed_dir / "lib").glob("CodexGhidraBridge*.jar"))
    if not jars:
        missing.append(str(installed_dir / "lib" / "CodexGhidraBridge*.jar"))
    if missing:
        raise RuntimeError("bridge extension install incomplete; missing: " + ", ".join(missing))


def _patch_tool_xml(path: Path) -> None:
    """Patch a Ghidra tool config (.tcd) file using ElementTree.

    - Removes any PACKAGE named "Codex Bridge".
    - Removes stray top-level INCLUDE elements for codexghidrabridge.CodexBridgePlugin.
    - For _code_browser.tcd: ensures codexghidrabridge.CodexBridgePlugin is
      present as an INCLUDE inside the "Ghidra Core" PACKAGE (creating the
      PACKAGE if it only existed as a self-closing tag).
    """
    import xml.etree.ElementTree as ET

    raw = path.read_text(encoding="utf-8")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        # Log and skip malformed XML rather than corrupting the file.
        import sys
        print(f"WARNING: skipping malformed XML in {path}: {exc}", file=sys.stderr)
        return

    _BRIDGE_PKG = "Codex Bridge"
    _PLUGIN_CLASS = "codexghidrabridge.CodexBridgePlugin"
    changed = False

    # Walk every PLUGIN_PACKAGE element (or TOOL element that contains them).
    # Ghidra .tcd files use TOOL > PACKAGE structure.
    for parent in list(root.iter()):
        # Remove "Codex Bridge" PACKAGE children
        for pkg in list(parent):
            if pkg.tag == "PACKAGE" and pkg.get("NAME") == _BRIDGE_PKG:
                parent.remove(pkg)
                changed = True
            # Remove stray INCLUDE for the plugin at any level
            if pkg.tag == "INCLUDE" and pkg.get("CLASS") == _PLUGIN_CLASS:
                parent.remove(pkg)
                changed = True

    # For _code_browser.tcd only: ensure plugin is inside "Ghidra Core" PACKAGE.
    if path.name == "_code_browser.tcd":
        # Check whether the plugin is already present anywhere after cleanup.
        already_present = any(
            el.get("CLASS") == _PLUGIN_CLASS
            for el in root.iter("INCLUDE")
        )
        if not already_present:
            # Find or create the "Ghidra Core" PACKAGE.
            ghidra_core_pkg: ET.Element | None = None
            for pkg in root.iter("PACKAGE"):
                if pkg.get("NAME") == "Ghidra Core":
                    ghidra_core_pkg = pkg
                    break

            if ghidra_core_pkg is None:
                # Append a new PACKAGE element to root.
                ghidra_core_pkg = ET.SubElement(root, "PACKAGE")
                ghidra_core_pkg.set("NAME", "Ghidra Core")

            include_el = ET.SubElement(ghidra_core_pkg, "INCLUDE")
            include_el.set("CLASS", _PLUGIN_CLASS)
            changed = True

    if changed:
        ET.indent(root, space="    ")
        path.write_text(
            '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode"),
            encoding="utf-8",
        )


def _patch_frontend_xml(path: Path) -> None:
    """Patch FrontEndTool.xml using ElementTree.

    - Removes any PACKAGE named "Codex Bridge".
    - Ensures codexghidrabridge.CodexBridgeFrontEndPlugin is present inside
      the "Ghidra Core" PACKAGE.
    """
    import xml.etree.ElementTree as ET

    raw = path.read_text(encoding="utf-8")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        import sys
        print(f"WARNING: skipping malformed XML in {path}: {exc}", file=sys.stderr)
        return

    _BRIDGE_PKG = "Codex Bridge"
    _FRONTEND_CLASS = "codexghidrabridge.CodexBridgeFrontEndPlugin"
    changed = False

    for parent in list(root.iter()):
        for pkg in list(parent):
            if pkg.tag == "PACKAGE" and pkg.get("NAME") == _BRIDGE_PKG:
                parent.remove(pkg)
                changed = True
            if pkg.tag == "INCLUDE" and pkg.get("CLASS") == _FRONTEND_CLASS:
                parent.remove(pkg)
                changed = True

    already_present = any(
        el.get("CLASS") == _FRONTEND_CLASS
        for el in root.iter("INCLUDE")
    )
    if not already_present:
        ghidra_core_pkg: ET.Element | None = None
        for pkg in root.iter("PACKAGE"):
            if pkg.get("NAME") == "Ghidra Core":
                ghidra_core_pkg = pkg
                break

        if ghidra_core_pkg is None:
            ghidra_core_pkg = ET.SubElement(root, "PACKAGE")
            ghidra_core_pkg.set("NAME", "Ghidra Core")

        include_el = ET.SubElement(ghidra_core_pkg, "INCLUDE")
        include_el.set("CLASS", _FRONTEND_CLASS)
        changed = True

    if changed:
        ET.indent(root, space="    ")
        path.write_text(
            '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode"),
            encoding="utf-8",
        )


def _clear_state_files() -> None:
    for f in [
        cfg.bridge_current_file,
        cfg.bridge_legacy_control_file,
        cfg.bridge_legacy_session_file,
    ]:
        f.unlink(missing_ok=True)
    if cfg.bridge_requests_dir.exists():
        for f in cfg.bridge_requests_dir.glob("*.json"):
            f.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

def health_check(
    requested_session: str = "",
    requested_project: str = "",
    requested_program: str = "",
) -> dict:
    try:
        sf = resolve_session_file(requested_session, requested_project, requested_program)
    except RuntimeError as e:
        return {"ok": False, "healthy": False, "error": str(e)}
    healthy = session_healthy(sf)
    return {
        "ok": healthy,
        "healthy": healthy,
        "session_file": str(sf),
        "bridge_url": _read_session_value(sf, "bridge_url"),
    }
