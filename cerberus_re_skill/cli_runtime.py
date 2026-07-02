"""Shared Typer app objects and console helpers for Cerberus RE commands."""

from __future__ import annotations

import json

import typer
from rich.console import Console

app = typer.Typer(
    name="cerberus-re",
    help=(
        "Cerberus RE: a local Apple-focused reverse-engineering workbench for "
        "a repeatable three-headed static/dynamic/instrumentation loop around "
        "Ghidra, LLDB, and Frida."
    ),
    no_args_is_help=True,
)
bridge_app = typer.Typer(help="Bridge session management.", no_args_is_help=True)
validate_app = typer.Typer(help="Local validation report generation.", no_args_is_help=True)
polish_app = typer.Typer(help="Release-polish checks.", no_args_is_help=True)
frida_app = typer.Typer(help="Frida diagnostics and validation.", no_args_is_help=True)
source_app = typer.Typer(help="Source registry management.", no_args_is_help=True)
notes_app = typer.Typer(help="Shared notes management.", no_args_is_help=True)
import_app = typer.Typer(help="Import and analysis.", no_args_is_help=True)
export_app = typer.Typer(help="Export Apple binary analysis artifacts.", no_args_is_help=True)
publish_app = typer.Typer(help="Build share/install packages.", no_args_is_help=True)
plugins_app = typer.Typer(help="Community Ghidra plugin management.", no_args_is_help=True)

app.add_typer(bridge_app, name="bridge")
app.add_typer(validate_app, name="validate")
app.add_typer(polish_app, name="polish")
app.add_typer(frida_app, name="frida")
app.add_typer(source_app, name="source")
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
