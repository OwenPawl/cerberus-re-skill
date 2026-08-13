"""Bridge implementation shard."""

from __future__ import annotations

from cerberus_re_skill.modules.bridge_sessions import *  # noqa: F403
from cerberus_re_skill.modules.bridge_runtime import *  # noqa: F403


# ---------------------------------------------------------------------------
# Bridge arm
# ---------------------------------------------------------------------------

def _launch_gui_project(project_file: Path, new_instance: bool = False) -> None:
    """Launch Ghidra GUI with the given project file (detached)."""
    ghidra_run = None
    from cerberus_re_skill.core.ghidra_locator import ghidra_run_path

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


def _bridge_installed_dir() -> Path | None:
    ghidra_dir = cfg.ghidra_install_dir
    settings = bridge_settings_dir(ghidra_dir)
    if not settings:
        return None
    return settings / "Extensions" / "Ghidra" / "CodexGhidraBridge"


def _xml_includes_plugin(path: Path, plugin_class: str) -> bool:
    """Return whether a Ghidra tool configuration enables *plugin_class*."""
    import xml.etree.ElementTree as ET

    if not path.is_file():
        return False
    try:
        root = ET.fromstring(path.read_text(encoding="utf-8"))
    except (OSError, ET.ParseError):
        return False
    return any(
        element.get("CLASS") == plugin_class
        for element in root.iter("INCLUDE")
    )


def bridge_enablement_status() -> dict:
    """Inspect installation and persistent Ghidra plugin enablement state."""
    settings = bridge_settings_dir(cfg.ghidra_install_dir)
    installed_dir = _bridge_installed_dir()
    if settings is None:
        return {
            "installed": False,
            "enabled": False,
            "settings_dir": "",
            "installed_dir": "",
            "code_browser_enabled": False,
            "frontend_enabled": False,
            "code_browser_configs": [],
            "frontend_config": "",
        }

    tools_dir = settings / "tools"
    code_browser_configs = sorted(tools_dir.glob("_code_browser.tcd")) if tools_dir.exists() else []
    frontend_config = settings / "FrontEndTool.xml"
    code_browser_enabled = any(
        _xml_includes_plugin(path, "codexghidrabridge.CodexBridgePlugin")
        for path in code_browser_configs
    )
    frontend_enabled = _xml_includes_plugin(
        frontend_config, "codexghidrabridge.CodexBridgeFrontEndPlugin"
    )
    installed = bool(installed_dir and installed_dir.is_dir())
    return {
        "installed": installed,
        "enabled": installed and code_browser_enabled and frontend_enabled,
        "settings_dir": str(settings),
        "installed_dir": str(installed_dir or ""),
        "code_browser_enabled": code_browser_enabled,
        "frontend_enabled": frontend_enabled,
        "code_browser_configs": [str(path) for path in code_browser_configs],
        "frontend_config": str(frontend_config),
    }


def ensure_bridge_installed_and_enabled() -> dict:
    """Install when absent and repair persistent plugin enablement when present."""
    status = bridge_enablement_status()
    if not status["installed"]:
        install()
        status = bridge_enablement_status()
        status["action"] = "installed"
        return status

    settings = Path(status["settings_dir"])
    tools_dir = settings / "tools"
    if tools_dir.exists():
        for tool_file in sorted(tools_dir.glob("*.tcd")):
            _patch_tool_xml(tool_file)
    frontend_config = settings / "FrontEndTool.xml"
    if frontend_config.exists():
        _patch_frontend_xml(frontend_config)

    repaired = bridge_enablement_status()
    repaired["action"] = "repaired" if not status["enabled"] else "unchanged"
    return repaired


def _clear_state_files() -> None:
    cfg.bridge_current_file.unlink(missing_ok=True)
    if cfg.bridge_requests_dir.exists():
        for f in cfg.bridge_requests_dir.glob("*.json"):
            f.unlink(missing_ok=True)


def arm(project_name: str, program_name: str = "") -> dict:
    """Arm the bridge for *project_name* (and optionally *program_name*)."""
    require_tools()
    ensure_workspace()
    ensure_bridge_dirs()
    prune_stale_sessions()

    project_file = cfg.project_file(project_name)
    if not project_file.exists():
        raise RuntimeError(f"project {project_name} not found at {project_file}")

    # Install the extension and repair persistent plugin enablement before launch.
    enablement = ensure_bridge_installed_and_enabled()
    ghidra_was_running = is_ghidra_running()

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
    if ghidra_was_running:
        sf = wait_for_session(8, project_name, program_name)
        if sf:
            write_current_from_session_file(sf)
            url = _read_session_value(sf, "bridge_url")
            return {"ok": True, "bridge_url": url, "session_file": str(sf)}

    # Launch Ghidra
    _launch_gui_project(project_file)
    sf = wait_for_session(60, project_name, program_name)
    if not sf:
        raise RuntimeError(_bridge_arm_timeout_diagnostic(enablement, ghidra_was_running))
    write_current_from_session_file(sf)
    url = _read_session_value(sf, "bridge_url")
    return {"ok": True, "bridge_url": url, "session_file": str(sf)}


def _bridge_arm_timeout_diagnostic(enablement: dict, ghidra_was_running: bool) -> str:
    """Explain an arm timeout without conflating installation and enablement."""
    problems: list[str] = []
    if not enablement.get("installed"):
        problems.append("extension installation was not detected")
    if not enablement.get("code_browser_enabled"):
        problems.append("CodexBridgePlugin is not enabled in the Code Browser configuration")
    if not enablement.get("frontend_enabled"):
        problems.append("CodexBridgeFrontEndPlugin is not enabled in FrontEndTool.xml")

    if problems:
        return (
            "timed out waiting for bridge session; CodexGhidraBridge enablement diagnostic: "
            f"{'; '.join(problems)}. Run 'cerberus-re bridge install', then restart Ghidra."
        )
    if ghidra_was_running and enablement.get("action") == "repaired":
        return (
            "timed out waiting for bridge session; CodexGhidraBridge configuration was "
            "auto-enabled, but Ghidra was already running and must be restarted to load it"
        )
    return (
        "timed out waiting for bridge session; CodexGhidraBridge is installed and enabled "
        "in persistent Ghidra configuration, but no live plugin session appeared. Restart "
        "Ghidra and inspect the bridge launch log; run EnableCodexBridge.java once only as "
        "a compatibility fallback"
    )


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

    gradle = gradle_wrapper_path(cfg.ghidra_install_dir)
    if not gradle:
        raise RuntimeError(f"Gradle wrapper not found in {cfg.ghidra_install_dir}")
    if not cfg.bridge_extension_dir.exists():
        raise RuntimeError(f"bridge extension directory not found at {cfg.bridge_extension_dir}")

    run(
        [
            str(gradle),
            "-p",
            str(cfg.bridge_extension_dir),
            f"-PGHIDRA_INSTALL_DIR={cfg.ghidra_install_dir}",
            "clean",
            "distributeExtension",
        ],
        env=env,
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
    app_installed_dir = ghidra_dir / "Ghidra" / "Extensions" / "CodexGhidraBridge"
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

        if legacy_installed_dir != installed_dir and legacy_installed_dir.exists():
            shutil.rmtree(legacy_installed_dir)

        # Also install into app Extensions if writable
        app_parent = app_installed_dir.parent
        if app_parent.exists() and os.access(app_parent, os.W_OK):
            if app_installed_dir.exists():
                shutil.rmtree(app_installed_dir)
            shutil.copytree(tmp_root / "CodexGhidraBridge", app_installed_dir)

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

__all__ = [name for name in globals() if not name.startswith('__')]
