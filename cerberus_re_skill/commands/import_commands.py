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

@import_app.command("analyze")
def import_analyze(
    binary: str = typer.Argument(..., help="Binary path or source:name:/path/in/image."),
    project: str = typer.Argument("", help="Ghidra project name (auto-derived if omitted)."),
    skip_macho_reexports: bool = typer.Option(
        False,
        "--skip-macho-reexports",
        help="Import a Mach-O target without recursively loading LC_REEXPORT_DYLIB dependencies.",
    ),
    macho_arch: str = typer.Option(
        "",
        "--macho-arch",
        help="Import the requested architecture slice from a universal Mach-O by staging a thin copy.",
    ),
    disable_analysis_option: list[str] = typer.Option(
        [],
        "--disable-analysis-option",
        help="Disable a named Ghidra analysis option before auto-analysis; repeatable.",
    ),
) -> None:
    """Import and analyze a binary with Ghidra."""
    from cerberus_re_skill.modules.importer import import_analyze

    try:
        result = import_analyze(
            binary,
            project or None,
            skip_macho_reexports=skip_macho_reexports,
            macho_arch=macho_arch,
            disable_analysis_options=disable_analysis_option,
        )
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
    from cerberus_re_skill.modules.importer import import_macos_framework

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
    from cerberus_re_skill.modules.importer import run_script

    try:
        result = run_script(script, project, program or None)
        _print_json(result)
    except Exception as e:
        _die(str(e))


# ---------------------------------------------------------------------------
# export subcommands
# ---------------------------------------------------------------------------
