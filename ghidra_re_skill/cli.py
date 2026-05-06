"""Main CLI for ghidra-re-skill using typer + rich.

Commands:
  bootstrap   - detect Ghidra, create workspace, write config
  doctor      - check environment
  bridge      - bridge session management subcommands
  mission     - mission management subcommands
  notes       - shared notes subcommands
  import      - import/analyze subcommands
  export      - export Apple binary analysis artifacts
  diff        - compare two exported function inventories
  generate-harness - create source harnesses from enriched traces
  plugins     - community plugin management (GhidraApple, etc.)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

app = typer.Typer(
    name="ghidra-re",
    help="Cross-platform Ghidra reverse-engineering orchestration.",
    no_args_is_help=True,
)
bridge_app = typer.Typer(help="Bridge session management.", no_args_is_help=True)
mission_app = typer.Typer(help="Mission management.", no_args_is_help=True)
notes_app = typer.Typer(help="Shared notes management.", no_args_is_help=True)
import_app = typer.Typer(help="Import and analysis.", no_args_is_help=True)
export_app = typer.Typer(help="Export Apple binary analysis artifacts.", no_args_is_help=True)
publish_app = typer.Typer(help="Build share/install packages.", no_args_is_help=True)
plugins_app = typer.Typer(help="Community Ghidra plugin management.", no_args_is_help=True)

app.add_typer(bridge_app, name="bridge")
app.add_typer(mission_app, name="mission")
app.add_typer(notes_app, name="notes")
app.add_typer(import_app, name="import")
app.add_typer(export_app, name="export")
app.add_typer(plugins_app, name="plugins")
app.add_typer(publish_app, name="publish")

console = Console()
err_console = Console(stderr=True)


def _die(msg: str) -> None:
    err_console.print(f"[bold red]Error:[/bold red] {msg}")
    raise typer.Exit(code=1)


def _print_json(data: object) -> None:
    console.print_json(json.dumps(data, indent=2, default=str))


@app.command("diff")
def diff_cmd(
    project_a: str = typer.Argument(..., help="Left Ghidra project name."),
    program_a: str = typer.Argument(..., help="Left program name."),
    project_b: str = typer.Argument(..., help="Right Ghidra project name."),
    program_b: str = typer.Argument(..., help="Right program name."),
    function_inventory_a: Optional[str] = typer.Option(None, "--function-inventory-a", help="Override left function_inventory.json."),
    function_inventory_b: Optional[str] = typer.Option(None, "--function-inventory-b", help="Override right function_inventory.json."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Destination diff JSON."),
) -> None:
    """Compare two Ghidra export bundles."""
    from ghidra_re_skill.modules.diffing import diff_exports

    try:
        result = diff_exports(
            project_a=project_a,
            program_a=program_a,
            project_b=project_b,
            program_b=program_b,
            function_inventory_a=function_inventory_a,
            function_inventory_b=function_inventory_b,
            output=output,
        )
        _print_json(result)
        if result.get("ok"):
            console.print(
                f"[green]Wrote[/green] {result['output']} "
                f"({result['added_count']} added, {result['removed_count']} removed, "
                f"{result['modified_count']} modified)"
            )
    except Exception as e:
        _die(str(e))


@app.command("generate-harness")
def generate_harness_cmd(
    trace_json: str = typer.Argument(..., help="Enriched LLDB trace JSON."),
    target: Optional[str] = typer.Argument(None, help="Function name, symbol, runtime PC, or Ghidra address to target."),
    language: str = typer.Option("auto", "--language", "-l", help="Harness language: auto, objc, or swift."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Destination .m or .swift file."),
    framework: Optional[str] = typer.Option(None, "--framework", help="Framework name to load (default: trace program)."),
    bundle_path: Optional[str] = typer.Option(None, "--bundle-path", help="Framework bundle path to load."),
) -> None:
    """Generate a source harness from an enriched LLDB trace."""
    from ghidra_re_skill.modules.harness import generate_harness

    try:
        result = generate_harness(
            trace_path=trace_json,
            target=target,
            language=language,
            output=output,
            framework=framework,
            bundle_path=bundle_path,
        )
        _print_json(result)
        if result.get("ok"):
            console.print(
                f"[green]Wrote[/green] {result['output']} "
                f"({result['language']} harness for {result['target']})"
            )
    except Exception as e:
        _die(str(e))


@app.command("generate-xpc-harness")
def generate_xpc_harness_cmd(
    project: str = typer.Argument(..., help="Ghidra project name."),
    program: str = typer.Argument(..., help="Program name within the project."),
    service: Optional[str] = typer.Option(None, "--service", help="Mach service name (default: first XPC surface candidate)."),
    protocol: Optional[str] = typer.Option(None, "--protocol", help="ObjC protocol name for remoteObjectInterface."),
    xpc_surface: Optional[str] = typer.Option(None, "--xpc-surface", help="Path to xpc_surface.json."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Destination Objective-C harness."),
) -> None:
    """Generate an Objective-C NSXPCConnection harness skeleton."""
    from ghidra_re_skill.modules.xpc_harness import generate_xpc_harness

    try:
        result = generate_xpc_harness(
            project=project,
            program=program,
            service=service,
            protocol=protocol,
            xpc_surface_path=xpc_surface,
            output=output,
        )
        _print_json(result)
        if result.get("ok"):
            console.print(f"[green]Wrote[/green] {result['output']} ({result['service']})")
    except Exception as e:
        _die(str(e))


# ---------------------------------------------------------------------------
# bootstrap
# ---------------------------------------------------------------------------


@app.command()
def bootstrap(
    skip_smoke_test: bool = typer.Option(False, "--skip-smoke-test", help="Skip analyzeHeadless smoke test."),
    skip_bridge_install: bool = typer.Option(False, "--skip-bridge-install", help="Skip bridge extension install."),
    skip_plugins_install: bool = typer.Option(False, "--skip-plugins-install", help="Skip community plugin install (GhidraApple)."),
    no_write_config: bool = typer.Option(False, "--no-write-config", help="Do not write config file."),
    config_file: Optional[str] = typer.Option(None, "--config-file", help="Path to config file."),
) -> None:
    """Detect Ghidra/JDK, create workspace, write config, install bridge + plugins."""
    from ghidra_re_skill.core.config import cfg
    from ghidra_re_skill.core.ghidra_locator import detect_ghidra_dir, detect_jdk_dir

    console.print("[bold]ghidra-re bootstrap[/bold]")

    detected_ghidra = detect_ghidra_dir()
    detected_jdk = detect_jdk_dir()

    if not detected_ghidra:
        _die("could not detect a Ghidra install; run 'ghidra-re doctor' for details")
    if not detected_jdk:
        _die("could not detect a Java 21 JDK; run 'ghidra-re doctor' for details")

    cfg.ghidra_install_dir = detected_ghidra
    cfg.ghidra_jdk = detected_jdk
    cfg._refresh_script_dirs()

    workspace = cfg.workspace
    for d in [
        workspace / "projects",
        workspace / "exports",
        workspace / "logs",
        workspace / "investigations",
        workspace / "sources",
    ]:
        d.mkdir(parents=True, exist_ok=True)

    if not no_write_config:
        import datetime

        target = Path(config_file) if config_file else cfg.config_home / "config.env"
        target.parent.mkdir(parents=True, exist_ok=True)
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        target.write_text(
            f"# Generated by ghidra-re bootstrap on {now}\n"
            f"GHIDRA_INSTALL_DIR={detected_ghidra}\n"
            f"GHIDRA_JDK={detected_jdk}\n"
            f"GHIDRA_WORKSPACE={workspace}\n",
            encoding="utf-8",
        )
        console.print(f"Config: {target}")

    if not skip_smoke_test:
        _run_smoke_test(detected_ghidra, detected_jdk)
        console.print("Smoke test: [green]passed[/green]")
    else:
        console.print("Smoke test: skipped")

    bridge_status = "skipped"
    if not skip_bridge_install:
        try:
            from ghidra_re_skill.modules.bridge import install
            install()
            bridge_status = "installed"
        except Exception as e:
            _die(f"bridge install failed: {e}")

    plugins_status_str = "skipped"
    if not skip_plugins_install:
        try:
            from ghidra_re_skill.modules.plugins import install_ghidra_apple
            result = install_ghidra_apple()
            plugins_status_str = result.get("status", "installed")
        except Exception as e:
            # Non-fatal: plugins are useful but not required for basic operation.
            plugins_status_str = f"failed ({e})"
            console.print(f"[yellow]Warning:[/yellow] GhidraApple install failed: {e}")
            console.print("[dim]Run 'ghidra-re plugins install' to retry.[/dim]")

    console.print(f"Skill root: {cfg.skill_root}")
    console.print(f"Ghidra: {detected_ghidra}")
    console.print(f"JDK: {detected_jdk}")
    console.print(f"Workspace: {workspace}")
    console.print(f"Bridge: {bridge_status}")
    console.print(f"Plugins (GhidraApple): {plugins_status_str}")
    if plugins_status_str in ("installed",):
        console.print(
            "[dim]Restart Ghidra and enable GhidraApple analyzers via "
            "Analysis > Analyze All Open Files.[/dim]"
        )
    console.print("[bold green]ghidra-re bootstrap complete[/bold green]")


def _run_smoke_test(ghidra_dir: Path, jdk_dir: Path) -> None:
    import subprocess
    import tempfile

    from ghidra_re_skill.core.ghidra_locator import analyze_headless_path
    from ghidra_re_skill.core.platform_helpers import is_windows

    headless = analyze_headless_path(ghidra_dir)
    if not headless:
        _die(f"analyzeHeadless not found in {ghidra_dir}")

    if is_windows():
        smoke_binary = Path("C:/Windows/System32/where.exe")
    else:
        smoke_binary = Path("/usr/bin/true")
        if not smoke_binary.exists():
            smoke_binary = Path("/bin/ls")

    if not smoke_binary.exists():
        _die("unable to find a small system binary for smoke testing")

    import os

    with tempfile.TemporaryDirectory(prefix="ghidra-re-bootstrap-") as tmp:
        project_root = Path(tmp) / "project"
        project_root.mkdir()
        java_home = str(jdk_dir)
        path_sep = ";" if sys.platform == "win32" else ":"
        env = {
            **os.environ,
            "JAVA_HOME": java_home,
            "PATH": str(jdk_dir / "bin") + path_sep + os.environ.get("PATH", ""),
        }
        result = subprocess.run(
            [
                str(headless),
                str(project_root),
                "bootstrap-smoke",
                "-import", str(smoke_binary),
                "-overwrite",
                "-noanalysis",
                "-max-cpu", "1",
                "-log", str(Path(tmp) / "bootstrap.log"),
                "-scriptlog", str(Path(tmp) / "bootstrap.script.log"),
            ],
            shell=False,
            env=env,
            capture_output=True,
        )
        if result.returncode != 0 or not (project_root / "bootstrap-smoke.gpr").exists():
            _die("analyzeHeadless smoke test failed; run 'ghidra-re doctor' for details")


# ---------------------------------------------------------------------------
# doctor
# ---------------------------------------------------------------------------


@app.command()
def doctor() -> None:
    """Check the ghidra-re environment and report issues."""
    from ghidra_re_skill.core.config import cfg
    from ghidra_re_skill.core.ghidra_locator import detect_ghidra_dir, detect_jdk_dir, is_valid_ghidra_dir, is_valid_jdk_dir
    from ghidra_re_skill.core.subprocess_utils import find_tool

    ok_count = 0
    warn_count = 0

    def record(level: str, label: str, value: str = "") -> None:
        nonlocal ok_count, warn_count
        color = "green" if level == "OK" else "yellow" if level == "WARN" else "blue"
        val_str = f": {value}" if value else ""
        console.print(f"[{color}]{level:<8}[/{color}] {label}{val_str}")
        if level == "OK":
            ok_count += 1
        elif level == "WARN":
            warn_count += 1

    console.print(f"[bold]ghidra-re doctor[/bold]")
    console.print(f"Skill root: {cfg.skill_root}")
    console.print(f"Platform: {cfg.platform}")
    console.print(f"Config home: {cfg.config_home}")
    console.print()

    if is_valid_ghidra_dir(cfg.ghidra_install_dir):
        record("OK", "Configured Ghidra", str(cfg.ghidra_install_dir))
    else:
        record("WARN", "Configured Ghidra", str(cfg.ghidra_install_dir) + " (not set or invalid)")

    if is_valid_jdk_dir(cfg.ghidra_jdk):
        record("OK", "Configured JDK", str(cfg.ghidra_jdk))
    else:
        record("WARN", "Configured JDK", str(cfg.ghidra_jdk) + " (not set or invalid)")

    detected_ghidra = detect_ghidra_dir()
    detected_jdk = detect_jdk_dir()
    if detected_ghidra:
        record("INFO", "Detected Ghidra candidate", str(detected_ghidra))
    if detected_jdk:
        record("INFO", "Detected JDK candidate", str(detected_jdk))

    python_cmd = find_tool("python3") or find_tool("python")
    if python_cmd:
        record("INFO", "Detected Python", python_cmd)
    else:
        record("WARN", "Python not found on PATH")

    gh_cmd = find_tool("gh")
    if gh_cmd:
        record("INFO", "GitHub CLI", gh_cmd)
    else:
        record("WARN", "GitHub CLI (gh) not found on PATH")

    for path in [
        cfg.workspace,
        cfg.projects_dir,
        cfg.exports_dir,
        cfg.logs_dir,
        cfg.investigations_dir,
        cfg.sources_cache_dir,
    ]:
        if path.is_dir():
            record("OK", "Directory exists", str(path))
        else:
            record("WARN", "Directory missing", str(path))

    for asset in [
        cfg.skill_root / "scripts" / "ghidra_notes_backend.py",
        cfg.skill_root / "scripts" / "ghidra_mission_backend.py",
        cfg.skill_root / "references" / "bug-hunt-patterns.json",
    ]:
        if asset.exists():
            record("OK", "Asset present", str(asset))
        else:
            record("WARN", "Asset missing", str(asset))

    for script in [
        cfg.custom_scripts_dir / "BugHuntSupport.java",
        cfg.custom_scripts_dir / "ExportAppleBundle.java",
        cfg.custom_scripts_dir / "ExportEntrypoints.java",
        cfg.custom_scripts_dir / "ExportSinks.java",
        cfg.custom_scripts_dir / "TriageBugPaths.java",
        cfg.custom_scripts_dir / "ExportFunctionDossier.java",
        cfg.custom_scripts_dir / "ExportMachOStructure.java",
        cfg.custom_scripts_dir / "ExportObjCTypeLayout.java",
        cfg.custom_scripts_dir / "ExportSwiftTypeLayout.java",
    ]:
        if script.exists():
            record("OK", "Ghidra script present", str(script))
        else:
            record("WARN", "Ghidra script missing", str(script))

    console.print()
    if warn_count == 0:
        console.print("[bold green]READY[/bold green]    ghidra-re looks ready to use")
    else:
        console.print("[bold yellow]ACTION[/bold yellow]   Run 'ghidra-re bootstrap' to auto-configure this machine")


# ---------------------------------------------------------------------------
# bridge subcommands
# ---------------------------------------------------------------------------


@bridge_app.command("arm")
def bridge_arm(
    project: str = typer.Argument(..., help="Ghidra project name."),
    program: str = typer.Argument("", help="Program name (optional)."),
) -> None:
    """Arm the bridge for a project."""
    from ghidra_re_skill.modules.bridge import arm

    try:
        result = arm(project, program)
        _print_json(result)
    except Exception as e:
        _die(str(e))


@bridge_app.command("disarm")
def bridge_disarm(
    session: str = typer.Option("", help="Session ID to disarm."),
    project: str = typer.Option("", help="Project name to disarm."),
    program: str = typer.Option("", help="Program name to disarm."),
) -> None:
    """Disarm the bridge session."""
    from ghidra_re_skill.modules.bridge import disarm

    try:
        result = disarm(session, project, program)
        _print_json(result)
    except Exception as e:
        _die(str(e))


@bridge_app.command("build")
def bridge_build() -> None:
    """Build the bridge Ghidra extension."""
    from ghidra_re_skill.modules.bridge import build

    try:
        zip_path = build()
        console.print(f"Built bridge extension: {zip_path}")
    except Exception as e:
        _die(str(e))


@bridge_app.command("install")
def bridge_install() -> None:
    """Build and install the bridge extension into Ghidra settings."""
    from ghidra_re_skill.modules.bridge import install

    try:
        result = install()
        _print_json(result)
    except Exception as e:
        _die(str(e))


@bridge_app.command("call")
def bridge_call(
    endpoint: str = typer.Argument(..., help="API endpoint (e.g. /session or /symbols/get)."),
    body: str = typer.Argument("{}", help="JSON body string, @file, or '-' for stdin."),
) -> None:
    """Call a bridge endpoint and print the JSON response."""
    from ghidra_re_skill.modules.bridge import call_bridge

    # Handle @file and stdin
    if body.startswith("@"):
        body_file = Path(body[1:])
        if not body_file.exists():
            _die(f"JSON body file not found: {body_file}")
        body = body_file.read_text(encoding="utf-8")
    elif body == "-":
        body = sys.stdin.read()

    try:
        result = call_bridge(endpoint, body)
        _print_json(result)
    except Exception as e:
        _die(str(e))


@bridge_app.command("status")
def bridge_status_cmd(
    body: str = typer.Argument("{}", help="Optional JSON body with session/project/program selectors."),
) -> None:
    """Show bridge status."""
    from ghidra_re_skill.modules.bridge import bridge_status

    result = bridge_status(body)
    _print_json(result)
    if not result.get("ok"):
        raise typer.Exit(code=1)


@bridge_app.command("sessions")
def bridge_sessions() -> None:
    """List all active bridge sessions."""
    from ghidra_re_skill.modules.bridge import list_sessions

    sessions = list_sessions()
    _print_json(sessions)


@bridge_app.command("health")
def bridge_health(
    session: str = typer.Option("", help="Session ID."),
    project: str = typer.Option("", help="Project name."),
    program: str = typer.Option("", help="Program name."),
) -> None:
    """Check bridge session health."""
    from ghidra_re_skill.modules.bridge import health_check

    result = health_check(session, project, program)
    _print_json(result)
    if not result.get("ok"):
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# mission subcommands
# ---------------------------------------------------------------------------


@mission_app.command("start")
def mission_start(
    name: str = typer.Argument(..., help="Mission name."),
    goal: str = typer.Option(..., help="Mission goal description."),
    target: list[str] = typer.Option([], help="Target binary/project:program (repeatable)."),
    seed: list[str] = typer.Option([], help="Seed (repeatable)."),
    mode: str = typer.Option("trace", help="Mission mode."),
) -> None:
    """Start a new mission."""
    from ghidra_re_skill.modules.mission import start

    try:
        result = start(name, goal, target, seed, mode)
        _print_json(result)
    except Exception as e:
        _die(str(e))


@mission_app.command("status")
def mission_status(
    name: str = typer.Argument(..., help="Mission name."),
) -> None:
    """Show mission status."""
    from ghidra_re_skill.modules.mission import status

    try:
        result = status(name)
        _print_json(result)
    except Exception as e:
        _die(str(e))


@mission_app.command("finish")
def mission_finish(
    name: str = typer.Argument(..., help="Mission name."),
) -> None:
    """Finish a mission."""
    from ghidra_re_skill.modules.mission import finish

    try:
        result = finish(name)
        _print_json(result)
    except Exception as e:
        _die(str(e))


@mission_app.command("report")
def mission_report(
    name: str = typer.Argument(..., help="Mission name."),
) -> None:
    """Render the mission report."""
    from ghidra_re_skill.modules.mission import report

    try:
        result = report(name)
        _print_json(result)
    except Exception as e:
        _die(str(e))


@mission_app.command("trace")
def mission_trace(
    name: str = typer.Argument(..., help="Mission name."),
    seed: str = typer.Argument(..., help="Seed to trace."),
) -> None:
    """Trace a seed in a mission."""
    from ghidra_re_skill.modules.mission import trace

    try:
        result = trace(name, seed)
        _print_json(result)
    except Exception as e:
        _die(str(e))


@mission_app.command("autopilot")
def mission_autopilot(
    name: str = typer.Argument(..., help="Mission name."),
) -> None:
    """Run mission autopilot."""
    from ghidra_re_skill.modules.mission import autopilot

    try:
        result = autopilot(name)
        _print_json(result)
    except Exception as e:
        _die(str(e))


# ---------------------------------------------------------------------------
# notes subcommands
# ---------------------------------------------------------------------------


@notes_app.command("add")
def notes_add(
    title: str = typer.Option(..., help="Note title."),
    body: str = typer.Option(..., help="Note body."),
    category: str = typer.Option("workflow", help="Note category."),
    target: str = typer.Option("", help="Target (project:program)."),
    mission: str = typer.Option("", help="Mission name."),
    project: str = typer.Option("", help="Project name."),
    program: str = typer.Option("", help="Program name."),
    program_path: str = typer.Option("", "--program-path", help="Program path."),
    context: str = typer.Option("", "--context", help="Context mode."),
    platform: str = typer.Option("", help="Observed platform."),
    status: str = typer.Option("open", help="Note status."),
) -> None:
    """Add a shared note."""
    from ghidra_re_skill.modules.notes import add

    try:
        result = add(
            title=title,
            body=body,
            category=category,
            target=target,
            mission_name=mission,
            project_name=project,
            program_name=program,
            program_path=program_path,
            context_mode=context,
            platform=platform,
            status=status,
        )
        _print_json(result)
    except Exception as e:
        _die(str(e))


@notes_app.command("sync")
def notes_sync() -> None:
    """Push queued notes to GitHub and pull the latest state."""
    from ghidra_re_skill.modules.notes import sync

    try:
        result = sync()
        _print_json(result)
    except Exception as e:
        _die(str(e))


@notes_app.command("pull")
def notes_pull() -> None:
    """Pull the latest shared notes from GitHub."""
    from ghidra_re_skill.modules.notes import pull

    try:
        result = pull()
        _print_json(result)
    except Exception as e:
        _die(str(e))


@notes_app.command("status")
def notes_status_cmd() -> None:
    """Show shared notes status."""
    from ghidra_re_skill.modules.notes import notes_status

    try:
        result = notes_status()
        _print_json(result)
    except Exception as e:
        _die(str(e))


@notes_app.command("remediate")
def notes_remediate(
    note_id: str = typer.Argument(..., help="Note ID to remediate."),
    resolution: str = typer.Option("", help="Resolution description."),
    comment: str = typer.Option("", help="Optional comment."),
) -> None:
    """Mark a note as remediated."""
    from ghidra_re_skill.modules.notes import remediate

    try:
        result = remediate(note_id, resolution, comment)
        _print_json(result)
    except Exception as e:
        _die(str(e))


@notes_app.command("open-shared")
def notes_open_shared(
    browse: bool = typer.Option(True, "--browse/--no-browse", help="Open the issue in the default browser."),
) -> None:
    """Open or print the shared notes issue URL."""
    from ghidra_re_skill.modules.notes import open_shared

    try:
        url = open_shared(browse=browse)
        if browse:
            console.print(f"Opened shared notes issue: {url}")
        else:
            console.print(url)
    except Exception as e:
        _die(str(e))


# ---------------------------------------------------------------------------
# import subcommands
# ---------------------------------------------------------------------------


@import_app.command("analyze")
def import_analyze(
    binary: str = typer.Argument(..., help="Binary path or source:name:/path/in/image."),
    project: str = typer.Argument("", help="Ghidra project name (auto-derived if omitted)."),
) -> None:
    """Import and analyze a binary with Ghidra."""
    from ghidra_re_skill.modules.importer import import_analyze

    try:
        result = import_analyze(binary, project or None)
        _print_json(result)
        if result.get("warnings"):
            w = result["warnings"]
            if any(v for v in w.values()):
                console.print("\n[yellow]Import warnings:[/yellow]")
                if w.get("unresolved_count"):
                    console.print(
                        f"  unresolved external programs: {w['unresolved_count']} "
                        f"(system={w['unresolved_system']} private={w['unresolved_private']} "
                        f"swift_runtime={w['unresolved_swift_runtime']} other={w['unresolved_other']})"
                    )
                if w.get("symbol_length_failures"):
                    console.print(f"  overlength symbol failures: {w['symbol_length_failures']}")
                if w.get("demangle_failures"):
                    console.print(f"  demangle failures: {w['demangle_failures']}")
    except Exception as e:
        _die(str(e))


@import_app.command("macos-framework")
def import_macos_framework(
    framework: str = typer.Argument(..., help="Path to macOS framework."),
    project: str = typer.Option("", help="Ghidra project name."),
) -> None:
    """Import a macOS framework."""
    from ghidra_re_skill.modules.importer import import_macos_framework

    try:
        result = import_macos_framework(framework, project or None)
        _print_json(result)
    except Exception as e:
        _die(str(e))


@import_app.command("run-script")
def import_run_script(
    script: str = typer.Argument(..., help="Ghidra script name (e.g. ExportAppleBundle.java)."),
    project: str = typer.Argument(..., help="Ghidra project name."),
    program: str = typer.Argument("", help="Program name within the project."),
) -> None:
    """Run a Ghidra headless script against a project."""
    from ghidra_re_skill.modules.importer import run_script

    try:
        result = run_script(script, project, program or None)
        _print_json(result)
    except Exception as e:
        _die(str(e))


# ---------------------------------------------------------------------------
# export subcommands
# ---------------------------------------------------------------------------


@export_app.command("macho-structure")
def export_macho_structure(
    project: str = typer.Argument(..., help="Ghidra project name."),
    program: str = typer.Argument("", help="Program name within the project (optional when --output given)."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Destination JSON file (default: exports/<project>/<program>/macho_structure.json)."),
) -> None:
    """Export Mach-O structural metadata to macho_structure.json.

    Runs ExportMachOStructure.java via Ghidra headless and writes a JSON file
    containing load commands, segments/sections, UUID, build/source versions,
    dylib ordinal table, rpaths, encryption info, and entitlements.
    """
    from ghidra_re_skill.modules.exporter import export_macho_structure as _export

    try:
        result = _export(project, program or None, output)
        _print_json(result)
        if result.get("ok"):
            console.print(f"[green]Wrote[/green] {result.get('output')}")
    except Exception as e:
        _die(str(e))


@export_app.command("objc-layout")
def export_objc_layout(
    project: str = typer.Argument(..., help="Ghidra project name."),
    program: str = typer.Argument("", help="Program name within the project (optional when --output given)."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Destination JSON file (default: exports/<project>/<program>/objc_layout.json)."),
) -> None:
    """Export per-class ObjC ivar and method layout to objc_layout.json.

    Runs ExportObjCTypeLayout.java via Ghidra headless. Walks __objc_classlist
    and __objc_catlist, parsing class_ro_t / ivar_list_t / method_list_t for
    every class defined in the binary. Outputs superclass chains, protocol
    conformances, ivar offsets/types, and method selectors/imp addresses.
    """
    from ghidra_re_skill.modules.exporter import export_objc_layout as _export

    try:
        result = _export(project, program or None, output)
        _print_json(result)
        if result.get("ok"):
            console.print(f"[green]Wrote[/green] {result.get('output')}")
    except Exception as e:
        _die(str(e))


@export_app.command("class-hierarchy")
def export_class_hierarchy(
    project: str = typer.Argument(..., help="Ghidra project name."),
    program: str = typer.Argument(..., help="Program name within the project."),
    objc_layout: Optional[str] = typer.Option(None, "--objc-layout", help="Path to objc_layout.json (auto-derived if omitted)."),
    swift_layout: Optional[str] = typer.Option(None, "--swift-layout", help="Path to swift_layout.json (auto-derived if omitted)."),
    output_json: Optional[str] = typer.Option(None, "--output-json", help="Destination class_hierarchy.json (auto-derived if omitted)."),
    output_mmd: Optional[str] = typer.Option(None, "--output-mmd", help="Destination class_hierarchy.mmd (auto-derived if omitted)."),
) -> None:
    """Build class/type hierarchy from objc_layout.json + swift_layout.json.

    Post-processes the output of 'ghidra-re export objc-layout' and
    'ghidra-re export swift-layout' to produce a cross-language type graph.
    Outputs class_hierarchy.json (nodes + edges + protocol conformance maps)
    and class_hierarchy.mmd (Mermaid diagram capped at 120 nodes).
    """
    from ghidra_re_skill.modules.hierarchy import build_class_hierarchy

    try:
        result = build_class_hierarchy(
            project=project,
            program=program,
            objc_layout_path=objc_layout,
            swift_layout_path=swift_layout,
            output_json=output_json,
            output_mmd=output_mmd,
        )
        _print_json(result)
        if result.get("ok"):
            console.print(
                f"[green]Wrote[/green] {result['output_json']} "
                f"({result['node_count']} nodes, {result['edge_count']} edges)"
            )
            console.print(f"[green]Wrote[/green] {result['output_mmd']}")
    except Exception as e:
        _die(str(e))


@export_app.command("framework-graph")
def export_framework_graph(
    project: str = typer.Argument(..., help="Ghidra project name."),
    program: str = typer.Argument(..., help="Program name within the project."),
    macho_structure: Optional[str] = typer.Option(None, "--macho-structure", help="Path to macho_structure.json (auto-derived if omitted)."),
    symbols: Optional[str] = typer.Option(None, "--symbols", help="Path to symbols.json (auto-derived if omitted)."),
    output: Optional[str] = typer.Option(None, "--output", help="Destination framework_graph.json (auto-derived if omitted)."),
    output_global: Optional[str] = typer.Option(None, "--output-global", help="Destination project-level framework_graph_global.json."),
) -> None:
    """Build a framework dependency graph from Mach-O metadata and symbol usage."""
    from ghidra_re_skill.modules.frameworks import build_framework_graph

    try:
        result = build_framework_graph(
            project=project,
            program=program,
            macho_structure_path=macho_structure,
            symbols_path=symbols,
            output=output,
            output_global=output_global,
        )
        _print_json(result)
        if result.get("ok"):
            console.print(f"[green]Wrote[/green] {result['output']}")
            console.print(f"[green]Wrote[/green] {result['output_global']}")
    except Exception as e:
        _die(str(e))


@export_app.command("subsystem-clusters")
def export_subsystem_clusters(
    project: str = typer.Argument(..., help="Ghidra project name."),
    program: str = typer.Argument(..., help="Program name within the project."),
    function_inventory: Optional[str] = typer.Option(None, "--function-inventory", help="Path to function_inventory.json (auto-derived if omitted)."),
    objc_layout: Optional[str] = typer.Option(None, "--objc-layout", help="Path to objc_layout.json (auto-derived if omitted)."),
    output: Optional[str] = typer.Option(None, "--output", help="Destination subsystem_clusters.json (auto-derived if omitted)."),
    min_prefix_size: int = typer.Option(3, "--min-prefix-size", help="Minimum shared prefix size to form a cluster."),
    no_xref_communities: bool = typer.Option(False, "--no-xref-communities", help="Disable NetworkX-based xref community detection."),
) -> None:
    """Group functions into subsystem clusters from function inventory and ObjC layout."""
    from ghidra_re_skill.modules.clusters import build_subsystem_clusters

    try:
        result = build_subsystem_clusters(
            project=project,
            program=program,
            function_inventory_path=function_inventory,
            objc_layout_path=objc_layout,
            output=output,
            min_prefix_size=min_prefix_size,
            use_xref_communities=not no_xref_communities,
        )
        _print_json(result)
        if result.get("ok"):
            console.print(
                f"[green]Wrote[/green] {result['output']} "
                f"({result['cluster_count']} clusters from {result['total_functions']} functions)"
            )
    except Exception as e:
        _die(str(e))


@export_app.command("xpc-surface")
def export_xpc_surface(
    project: str = typer.Argument(..., help="Ghidra project name."),
    program: str = typer.Argument(..., help="Program name within the project."),
    objc_metadata: Optional[str] = typer.Option(None, "--objc-metadata", help="Path to objc_metadata.json (auto-derived if omitted)."),
    strings: Optional[str] = typer.Option(None, "--strings", help="Path to strings.json (auto-derived if omitted)."),
    symbols: Optional[str] = typer.Option(None, "--symbols", help="Path to symbols.json (auto-derived if omitted)."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Destination xpc_surface.json."),
    markdown_output: Optional[str] = typer.Option(None, "--markdown-output", help="Destination xpc_surface.md."),
) -> None:
    """Recover XPC service, protocol, listener, and connection hints from exports."""
    from ghidra_re_skill.modules.xpc_surface import build_xpc_surface

    try:
        result = build_xpc_surface(
            project=project,
            program=program,
            objc_metadata_path=objc_metadata,
            strings_path=strings,
            symbols_path=symbols,
            output=output,
            markdown_output=markdown_output,
        )
        _print_json(result)
        if result.get("ok"):
            console.print(
                f"[green]Wrote[/green] {result['output']} and {result['markdown_output']} "
                f"({result['service_name_count']} services, {result['xpc_protocol_count']} protocols)"
            )
    except Exception as e:
        _die(str(e))


@export_app.command("xpc-graph")
def export_xpc_graph(
    targets: list[str] = typer.Argument(..., help="Targets formatted as project:program."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Destination xpc_graph.json."),
    markdown_output: Optional[str] = typer.Option(None, "--markdown-output", help="Destination xpc_graph.md."),
) -> None:
    """Merge per-binary XPC surface reports into a coarse IPC graph."""
    from ghidra_re_skill.modules.xpc_graph import build_xpc_graph

    try:
        result = build_xpc_graph(
            targets=targets,
            output=output,
            markdown_output=markdown_output,
        )
        _print_json(result)
        if result.get("ok"):
            console.print(
                f"[green]Wrote[/green] {result['output']} and {result['markdown_output']} "
                f"({result['node_count']} nodes, {result['edge_count']} edges)"
            )
    except Exception as e:
        _die(str(e))


@export_app.command("lldb-enrich")
def export_lldb_enrich(
    project: str = typer.Argument(..., help="Ghidra project name."),
    program: str = typer.Argument(..., help="Program name within the project."),
    trace_json: str = typer.Argument(..., help="LLDB trace JSON to enrich."),
    function_inventory: Optional[str] = typer.Option(None, "--function-inventory", help="Path to function_inventory.json (auto-derived if omitted)."),
    lldb_symbols: Optional[str] = typer.Option(None, "--lldb-symbols", help="Path to lldb_symbols.json (auto-derived if omitted)."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Destination enriched trace JSON."),
    known_runtime_pc: Optional[str] = typer.Option(None, "--known-runtime-pc", help="Manual runtime PC for slide calculation."),
    known_static_addr: Optional[str] = typer.Option(None, "--known-static-addr", help="Matching static/Ghidra address for slide calculation."),
) -> None:
    """Enrich LLDB trace hits with Ghidra addresses and function context."""
    from ghidra_re_skill.modules.lldb_enrich import enrich_lldb_trace

    try:
        result = enrich_lldb_trace(
            project=project,
            program=program,
            trace_path=trace_json,
            function_inventory_path=function_inventory,
            lldb_symbols_path=lldb_symbols,
            output=output,
            known_runtime_pc=known_runtime_pc,
            known_static_addr=known_static_addr,
        )
        _print_json(result)
        if result.get("ok"):
            console.print(
                f"[green]Wrote[/green] {result['output']} "
                f"({result['matched_function_count']}/{result['hit_count']} hits mapped)"
            )
    except Exception as e:
        _die(str(e))


@export_app.command("swift-layout")
def export_swift_layout(
    project: str = typer.Argument(..., help="Ghidra project name."),
    program: str = typer.Argument("", help="Program name within the project (optional when --output given)."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Destination JSON file (default: exports/<project>/<program>/swift_layout.json)."),
) -> None:
    """Export Swift 5 type layout to swift_layout.json.

    Runs ExportSwiftTypeLayout.java via Ghidra headless. Walks __swift5_fieldmd
    (field descriptors), __swift5_types (type context descriptors), and
    __swift5_protos (protocol conformance descriptors). Emits per-type kind,
    mangled/demangled names, field names and types, enum cases, and protocol
    conformances with witness table addresses. Demangling uses 'swift demangle'
    when available.
    """
    from ghidra_re_skill.modules.exporter import export_swift_layout as _export

    try:
        result = _export(project, program or None, output)
        _print_json(result)
        if result.get("ok"):
            console.print(f"[green]Wrote[/green] {result.get('output')}")
    except Exception as e:
        _die(str(e))


# ---------------------------------------------------------------------------
# install command
# ---------------------------------------------------------------------------


@app.command("install")
def install_cmd(
    host: str = typer.Option("auto", "--host", help="Target host: codex | claude | both | auto."),
    source: Optional[str] = typer.Option(None, "--source", help="Source directory to install from."),
    no_bootstrap: bool = typer.Option(False, "--no-bootstrap", help="Skip bootstrap after install."),
    skip_smoke_test: bool = typer.Option(False, "--skip-smoke-test", help="Skip smoke test in bootstrap."),
    skip_bridge_install: bool = typer.Option(False, "--skip-bridge-install", help="Skip bridge install in bootstrap."),
) -> None:
    """Install the skill into AI host directories (~/.codex/skills/ghidra-re etc.)."""
    from ghidra_re_skill.modules.publisher import install_skill

    source_path = Path(source) if source else None
    try:
        installed = install_skill(
            host=host,
            source_dir=source_path,
            run_bootstrap=not no_bootstrap,
            skip_smoke_test=skip_smoke_test,
            skip_bridge_install=skip_bridge_install,
        )
        for p in installed:
            console.print(f"install_skill: installed {p}")
    except Exception as e:
        _die(str(e))


# ---------------------------------------------------------------------------
# plugins subcommands
# ---------------------------------------------------------------------------


@plugins_app.command("install")
def plugins_install(
    plugin: str = typer.Argument("ghidraapple", help="Plugin to install (ghidraapple)."),
    force: bool = typer.Option(False, "--force", help="Re-install even if already present."),
    build_from_source: bool = typer.Option(
        False, "--build-from-source",
        help="Clone repo and build with Gradle instead of using the pre-built ZIP. "
             "Requires git and Gradle on PATH.",
    ),
) -> None:
    """Install a community Ghidra plugin."""
    if plugin.lower().replace("-", "").replace("_", "") not in ("ghidraapple", "apple"):
        _die(f"Unknown plugin '{plugin}'. Available: ghidraapple")
    try:
        from ghidra_re_skill.modules.plugins import install_ghidra_apple
        result = install_ghidra_apple(force=force, build_from_source=build_from_source)
        _print_json(result)
        if result.get("status") == "already_installed":
            console.print("[yellow]Already installed.[/yellow] Use --force to reinstall.")
        elif result.get("ok"):
            console.print("[bold green]GhidraApple installed.[/bold green]")
            console.print(f"[dim]{result.get('note', '')}[/dim]")
    except Exception as e:
        _die(str(e))


@plugins_app.command("status")
def plugins_status() -> None:
    """Show install status of all managed community plugins."""
    try:
        from ghidra_re_skill.modules.plugins import plugin_status
        result = plugin_status()
        _print_json(result)
    except Exception as e:
        _die(str(e))


# ---------------------------------------------------------------------------
# publish subcommands
# ---------------------------------------------------------------------------


@publish_app.command("share")
def publish_share(
    output: Optional[str] = typer.Argument(None, help="Output zip path."),
) -> None:
    """Build a cross-platform share package zip."""
    from ghidra_re_skill.modules.publisher import build_share_package

    try:
        out = build_share_package(Path(output) if output else None)
        console.print(f"Built share package: {out}")
    except Exception as e:
        _die(str(e))


@publish_app.command("mac-desktop")
def publish_mac(
    output: Optional[str] = typer.Argument(None, help="Output zip path."),
    without_ghidra_payload: bool = typer.Option(False, "--without-ghidra-payload", help="Omit embedded Ghidra."),
) -> None:
    """Build a macOS desktop share package zip."""
    from ghidra_re_skill.modules.publisher import build_mac_desktop_share_package

    try:
        out = build_mac_desktop_share_package(
            Path(output) if output else None,
            include_ghidra_payload=not without_ghidra_payload,
        )
        console.print(f"Built mac desktop share package: {out}")
    except Exception as e:
        _die(str(e))


@publish_app.command("windows-desktop")
def publish_windows(
    output: Optional[str] = typer.Argument(None, help="Output zip path."),
    ghidra_zip: Optional[str] = typer.Option(None, "--ghidra-zip", help="Path to Ghidra zip to embed."),
) -> None:
    """Build a Windows desktop share package zip."""
    from ghidra_re_skill.modules.publisher import build_windows_desktop_share_package

    try:
        out = build_windows_desktop_share_package(
            Path(output) if output else None,
            Path(ghidra_zip) if ghidra_zip else None,
        )
        console.print(f"Built windows desktop share package: {out}")
    except Exception as e:
        _die(str(e))
