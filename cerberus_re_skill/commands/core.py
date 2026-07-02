from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import typer

from cerberus_re_skill.cli_runtime import (
    app,
    bridge_app,
    validate_app,
    polish_app,
    frida_app,
    source_app,
    notes_app,
    import_app,
    export_app,
    publish_app,
    plugins_app,
    console,
    _die,
    _print_json,
)

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
    from cerberus_re_skill.modules.diffing import diff_exports

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
    compile_harness: bool = typer.Option(False, "--compile", help="Compile-check the generated harness without running it."),
    compile_output: Optional[str] = typer.Option(None, "--compile-output", help="Destination binary for --compile."),
) -> None:
    """Generate a source harness from an enriched LLDB trace."""
    from cerberus_re_skill.modules.harness import generate_harness

    try:
        result = generate_harness(
            trace_path=trace_json,
            target=target,
            language=language,
            output=output,
            framework=framework,
            bundle_path=bundle_path,
            compile_harness=compile_harness,
            compile_output=compile_output,
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
    from cerberus_re_skill.modules.xpc_harness import generate_xpc_harness

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
    from cerberus_re_skill.core.config import cfg
    from cerberus_re_skill.core.ghidra_locator import detect_ghidra_dir, detect_jdk_dir

    console.print("[bold]cerberus-re bootstrap[/bold]")

    detected_ghidra = detect_ghidra_dir()
    detected_jdk = detect_jdk_dir()

    if not detected_ghidra:
        _die("could not detect a Ghidra install; run 'cerberus-re doctor' for details")
    if not detected_jdk:
        _die("could not detect a Java 21 JDK; run 'cerberus-re doctor' for details")

    cfg.ghidra_install_dir = detected_ghidra
    cfg.ghidra_jdk = detected_jdk
    cfg._refresh_script_dirs()

    workspace = cfg.workspace
    for d in [
        workspace / "projects",
        workspace / "exports",
        workspace / "logs",
        workspace / "sources",
    ]:
        d.mkdir(parents=True, exist_ok=True)

    if not no_write_config:
        import datetime

        target = Path(config_file) if config_file else cfg.config_home / "config.env"
        target.parent.mkdir(parents=True, exist_ok=True)
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        target.write_text(
            f"# Generated by cerberus-re bootstrap on {now}\n"
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
            from cerberus_re_skill.modules.bridge import install
            install()
            bridge_status = "installed"
        except Exception as e:
            _die(f"bridge install failed: {e}")

    plugins_status_str = "skipped"
    if not skip_plugins_install:
        try:
            from cerberus_re_skill.modules.plugins import install_ghidra_apple
            result = install_ghidra_apple()
            plugins_status_str = result.get("status", "installed")
        except Exception as e:
            # Non-fatal: plugins are useful but not required for basic operation.
            plugins_status_str = f"failed ({e})"
            console.print(f"[yellow]Warning:[/yellow] GhidraApple install failed: {e}")
            console.print("[dim]Run 'cerberus-re plugins install' to retry.[/dim]")

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
    console.print("[bold green]cerberus-re bootstrap complete[/bold green]")


def _run_smoke_test(ghidra_dir: Path, jdk_dir: Path) -> None:
    import subprocess
    import tempfile

    from cerberus_re_skill.core.ghidra_locator import analyze_headless_path
    from cerberus_re_skill.core.platform_helpers import is_windows

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
            "GHIDRA_JDK": java_home,
            "JAVA_HOME": java_home,
            "JAVA_HOME_OVERRIDE": java_home,
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
            _die("analyzeHeadless smoke test failed; run 'cerberus-re doctor' for details")


# ---------------------------------------------------------------------------
# doctor
# ---------------------------------------------------------------------------


@app.command()
def doctor(
    frida_target: Optional[str] = typer.Option(
        None,
        "--frida-target",
        help="Optional macOS binary path to inspect for Frida attach-friendly signing entitlements.",
    ),
) -> None:
    """Check the Cerberus RE environment and report issues."""
    from cerberus_re_skill.core.config import cfg
    from cerberus_re_skill.core.ghidra_locator import (
        can_start_jdk,
        detect_ghidra_dir,
        detect_jdk_dir,
        is_valid_ghidra_dir,
        is_valid_jdk_dir,
        jdk_archs,
        macos_amfi_get_out_of_my_way_enabled,
    )
    from cerberus_re_skill.core.subprocess_utils import find_tool
    from cerberus_re_skill.modules.frida_diagnostics import collect_frida_diagnostics

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

    console.print(f"[bold]cerberus-re doctor[/bold]")
    console.print(f"Skill root: {cfg.skill_root}")
    console.print(f"Platform: {cfg.platform}")
    console.print(f"Config home: {cfg.config_home}")
    console.print()

    detected_ghidra = detect_ghidra_dir()
    detected_jdk = detect_jdk_dir()

    usable_ghidra = cfg.ghidra_install_dir if is_valid_ghidra_dir(cfg.ghidra_install_dir) else detected_ghidra
    usable_jdk = cfg.ghidra_jdk if can_start_jdk(cfg.ghidra_jdk) else detected_jdk

    if is_valid_ghidra_dir(cfg.ghidra_install_dir):
        record("OK", "Configured Ghidra", str(cfg.ghidra_install_dir))
    elif usable_ghidra:
        record("INFO", "Configured Ghidra", str(cfg.ghidra_install_dir) + " (using detected candidate)")
    else:
        record("WARN", "Configured Ghidra", str(cfg.ghidra_install_dir) + " (not set or invalid)")

    if can_start_jdk(cfg.ghidra_jdk):
        arch_note = ",".join(sorted(jdk_archs(cfg.ghidra_jdk))) or "unknown-arch"
        record("OK", "Configured JDK", f"{cfg.ghidra_jdk} ({arch_note})")
    elif usable_jdk:
        record("INFO", "Configured JDK", str(cfg.ghidra_jdk) + " (using detected launchable JDK)")
        arch_note = ",".join(sorted(jdk_archs(usable_jdk))) or "unknown-arch"
        record("OK", "Usable JDK", f"{usable_jdk} ({arch_note})")
    elif is_valid_jdk_dir(cfg.ghidra_jdk):
        record("WARN", "Configured JDK", str(cfg.ghidra_jdk) + " (java -version failed)")
    else:
        record("WARN", "Configured JDK", str(cfg.ghidra_jdk) + " (not set or invalid)")

    if macos_amfi_get_out_of_my_way_enabled():
        record("INFO", "macOS boot-args", "amfi_get_out_of_my_way=1; prefer x64/Rosetta Java 21")

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

    console.print()
    console.print("[bold]Frida diagnostics[/bold]")
    for diagnostic in collect_frida_diagnostics(frida_target):
        record(diagnostic.level, diagnostic.label, diagnostic.value)

    for path in [
        cfg.workspace,
        cfg.projects_dir,
        cfg.exports_dir,
        cfg.logs_dir,
        cfg.sources_cache_dir,
    ]:
        if path.is_dir():
            record("OK", "Directory exists", str(path))
        else:
            record("WARN", "Directory missing", str(path))

    for asset in [
        cfg.skill_root / "scripts" / "ghidra_notes_backend.py",
        cfg.skill_root / "references" / "triage-patterns.json",
    ]:
        if asset.exists():
            record("OK", "Asset present", str(asset))
        else:
            record("WARN", "Asset missing", str(asset))

    for script in [
        cfg.custom_scripts_dir / "TriageSupport.java",
        cfg.custom_scripts_dir / "ClassifySmallFunctions.java",
        cfg.custom_scripts_dir / "ExportAppleBundle.java",
        cfg.custom_scripts_dir / "ExportEntrypoints.java",
        cfg.custom_scripts_dir / "ExportXPCSurface.java",
        cfg.custom_scripts_dir / "ExportSinks.java",
        cfg.custom_scripts_dir / "TriagePaths.java",
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
        console.print("[bold green]READY[/bold green]    Cerberus RE looks ready to use")
    else:
        console.print(
            "[bold yellow]ACTION[/bold yellow]   Review WARN lines. "
            "Run 'cerberus-re bootstrap' for missing Ghidra assets; fix Frida policy warnings separately."
        )


# ---------------------------------------------------------------------------
# bridge subcommands
# ---------------------------------------------------------------------------
