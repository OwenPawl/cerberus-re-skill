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

@app.command("install")
def install_cmd(
    host: str = typer.Option("auto", "--host", help="Target host: codex | claude | both | auto."),
    source: Optional[str] = typer.Option(None, "--source", help="Source directory to install from."),
    no_bootstrap: bool = typer.Option(False, "--no-bootstrap", help="Skip bootstrap after install."),
    skip_smoke_test: bool = typer.Option(False, "--skip-smoke-test", help="Skip smoke test in bootstrap."),
    skip_bridge_install: bool = typer.Option(False, "--skip-bridge-install", help="Skip bridge install in bootstrap."),
) -> None:
    """Install the skill into AI host directories (~/.codex/skills/cerberus-re etc.)."""
    from cerberus_re_skill.modules.publisher import install_skill

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
        from cerberus_re_skill.modules.plugins import install_ghidra_apple
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
        from cerberus_re_skill.modules.plugins import plugin_status
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
    from cerberus_re_skill.modules.publisher import build_share_package

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
    from cerberus_re_skill.modules.publisher import build_mac_desktop_share_package

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
    from cerberus_re_skill.modules.publisher import build_windows_desktop_share_package

    try:
        out = build_windows_desktop_share_package(
            Path(output) if output else None,
            Path(ghidra_zip) if ghidra_zip else None,
        )
        console.print(f"Built windows desktop share package: {out}")
    except Exception as e:
        _die(str(e))
