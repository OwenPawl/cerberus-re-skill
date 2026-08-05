from __future__ import annotations

from pathlib import Path

import typer

from cerberus_re_skill.cli_runtime import _die, app, console, publish_app


@app.command("install")
def install_cmd(
    host: str = typer.Option("auto", "--host", help="Target host: codex | claude | both | auto."),
    source: str | None = typer.Option(None, "--source", help="Source directory to install from."),
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
        for path in installed:
            console.print(f"install_skill: installed {path}")
    except Exception as exc:  # noqa: BLE001 - Typer boundary converts failures to CLI errors.
        _die(str(exc))


@publish_app.command("share")
def publish_share(
    output: str | None = typer.Argument(None, help="Output zip path."),
) -> None:
    """Build a cross-platform share package zip."""
    from cerberus_re_skill.modules.publisher import build_share_package

    try:
        out = build_share_package(Path(output) if output else None)
        console.print(f"Built share package: {out}")
    except Exception as exc:  # noqa: BLE001 - Typer boundary converts failures to CLI errors.
        _die(str(exc))


@publish_app.command("mac-desktop")
def publish_mac(
    output: str | None = typer.Argument(None, help="Output zip path."),
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
    except Exception as exc:  # noqa: BLE001 - Typer boundary converts failures to CLI errors.
        _die(str(exc))


@publish_app.command("windows-desktop")
def publish_windows(
    output: str | None = typer.Argument(None, help="Output zip path."),
    ghidra_zip: str | None = typer.Option(None, "--ghidra-zip", help="Path to Ghidra zip to embed."),
) -> None:
    """Build a Windows desktop share package zip."""
    from cerberus_re_skill.modules.publisher import build_windows_desktop_share_package

    try:
        out = build_windows_desktop_share_package(
            Path(output) if output else None,
            Path(ghidra_zip) if ghidra_zip else None,
        )
        console.print(f"Built windows desktop share package: {out}")
    except Exception as exc:  # noqa: BLE001 - Typer boundary converts failures to CLI errors.
        _die(str(exc))
