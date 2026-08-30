"""Frida Gadget fallback commands."""

from __future__ import annotations

import json
from typing import Optional

import typer

from cerberus_re_skill.cli_runtime import _die, _print_json, frida_app


@frida_app.command("gadget-probe")
def frida_gadget_probe_cmd(
    target: str = typer.Argument(..., help="Owned executable to launch."),
    gadget: str = typer.Option(..., "--gadget", help="FridaGadget dylib path."),
    script: str = typer.Option(..., "--script", help="Autonomous Gadget script path."),
    output_dir: str = typer.Option(..., "--output-dir", "-o", help="Evidence directory."),
    stable_target_key: str = typer.Option(
        ...,
        "--stable-target-key",
        help="Stable identity for the owned target.",
    ),
    timeout_seconds: float = typer.Option(5.0, "--timeout", min=0.1),
    argument: Optional[list[str]] = typer.Option(
        None,
        "--arg",
        help="Target argument. Repeat for multiple arguments.",
    ),
    parameters: str = typer.Option(
        "{}",
        "--parameters",
        help="JSON object passed to the Gadget script init function.",
    ),
    architecture: str = typer.Option("", "--architecture"),
    allow_runtime: bool = typer.Option(
        False,
        "--allow-runtime",
        help="Launch the owned target; omitted means artifact-only planning.",
    ),
) -> None:
    """Run an autonomous Gadget script without Frida task-port attachment."""
    from cerberus_re_skill.modules.frida_gadget import run_frida_gadget_probe

    try:
        decoded = json.loads(parameters)
        if not isinstance(decoded, dict):
            raise RuntimeError("--parameters must decode to a JSON object")
        result = run_frida_gadget_probe(
            target,
            gadget,
            script,
            output_dir,
            stable_target_key=stable_target_key,
            timeout_seconds=timeout_seconds,
            arguments=argument or [],
            parameters=decoded,
            architecture=architecture,
            allow_runtime=allow_runtime,
        )
        _print_json(result)
        if not result.get("ok"):
            raise typer.Exit(code=1)
    except typer.Exit:
        raise
    except Exception as exc:
        _die(str(exc))
