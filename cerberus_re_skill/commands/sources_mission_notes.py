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

@source_app.command("add")
def source_add_cmd(
    name: str = typer.Argument(..., help="Source name."),
    root: str = typer.Option(..., "--root", help="Mounted or extracted root path."),
    platform: str = typer.Option("macos-image", "--platform", help="Source platform label."),
    copy: str = typer.Option("cache", "--copy", help="Default copy mode: cache or direct."),
) -> None:
    """Add or update a source registry entry."""
    from cerberus_re_skill.modules.sources import add_source

    try:
        _print_json(add_source(name, root, platform=platform, copy=copy))
    except Exception as e:
        _die(str(e))


@source_app.command("list")
def source_list_cmd() -> None:
    """List source registry entries."""
    from cerberus_re_skill.modules.sources import list_sources

    _print_json(list_sources())


@source_app.command("resolve")
def source_resolve_cmd(
    name: str = typer.Argument(..., help="Source name."),
    requested_path: str = typer.Argument(..., help="Path inside the source root."),
    copy: str = typer.Option("", "--copy", help="Override copy mode: cache or direct."),
    no_extract: bool = typer.Option(
        False,
        "--no-extract",
        help="Resolve direct or existing extracted files only; do not invoke dyld cache extraction.",
    ),
) -> None:
    """Resolve a path from a registered source."""
    from cerberus_re_skill.modules.sources import resolve_source

    try:
        _print_json(resolve_source(name, requested_path, copy=copy, no_extract=no_extract))
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
    status: str = typer.Option("open", help="Note status."),
) -> None:
    """Add a shared note."""
    from cerberus_re_skill.modules.notes import add

    try:
        result = add(
            title=title,
            body=body,
            category=category,
            target=target,
            mission_name=mission,
            project_name=project,
            program_name=program,
            status=status,
        )
        _print_json(result)
    except Exception as e:
        _die(str(e))


@notes_app.command("sync")
def notes_sync() -> None:
    """Push queued notes to GitHub and pull the latest state."""
    from cerberus_re_skill.modules.notes import sync

    try:
        result = sync()
        _print_json(result)
    except Exception as e:
        _die(str(e))


@notes_app.command("pull")
def notes_pull() -> None:
    """Pull the latest shared notes from GitHub."""
    from cerberus_re_skill.modules.notes import pull

    try:
        result = pull()
        _print_json(result)
    except Exception as e:
        _die(str(e))


@notes_app.command("status")
def notes_status_cmd() -> None:
    """Show shared notes status."""
    from cerberus_re_skill.modules.notes import notes_status

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
    from cerberus_re_skill.modules.notes import remediate

    try:
        result = remediate(note_id, resolution, comment)
        _print_json(result)
    except Exception as e:
        _die(str(e))


@notes_app.command("open-shared")
def notes_open_shared() -> None:
    """Open the shared notes issue in the default browser."""
    from cerberus_re_skill.modules.notes import open_shared

    try:
        open_shared()
    except Exception as e:
        _die(str(e))


# ---------------------------------------------------------------------------
# import subcommands
# ---------------------------------------------------------------------------
