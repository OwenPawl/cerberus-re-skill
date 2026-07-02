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

@export_app.command("simulator-framework-host")
def export_simulator_framework_host(
    framework: Optional[list[str]] = typer.Option(
        None,
        "--framework",
        help="Repeatable absolute framework binary path inside the simulator runtime.",
    ),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Destination Objective-C host source."),
    compile_harness: bool = typer.Option(False, "--compile", help="Compile and ad-hoc sign the simulator host."),
    compile_output: Optional[str] = typer.Option(None, "--compile-output", help="Destination compiled host executable."),
    deployment_target: str = typer.Option("18.0", "--deployment-target", help="Simulator deployment target."),
    hold_seconds: int = typer.Option(120, "--hold-seconds", help="Seconds the host waits for external probes."),
) -> None:
    """Generate a load-only disposable iOS Simulator framework host."""
    from cerberus_re_skill.modules.simulator_framework_host import generate_simulator_framework_host

    try:
        result = generate_simulator_framework_host(
            frameworks=framework or [],
            output=output,
            compile_harness=compile_harness,
            compile_output=compile_output,
            deployment_target=deployment_target,
            hold_seconds=hold_seconds,
        )
        _print_json(result)
        if result.get("ok"):
            console.print(f"[green]Wrote[/green] {result['output']} ({result['safety_default']})")
    except Exception as e:
        _die(str(e))


@export_app.command("trigger-attempt-index")
def export_trigger_attempt_index(
    attempt: list[str] = typer.Option(
        ...,
        "--attempt",
        help="Repeatable trigger attempt mapping formatted as id=path.",
    ),
    checklist: Optional[list[str]] = typer.Option(
        None,
        "--checklist",
        help="Optional trigger checklist mapping formatted as id=path.",
    ),
    runtime_status: Optional[list[str]] = typer.Option(
        None,
        "--runtime-status",
        help="Optional LLDB runtime-status mapping formatted as id=path.",
    ),
    instrumentation: Optional[list[str]] = typer.Option(
        None,
        "--instrumentation",
        help="Optional Frida/instrumentation mapping formatted as id=path.",
    ),
    frida_capture_plan: Optional[list[str]] = typer.Option(
        None,
        "--frida-capture-plan",
        help="Optional Frida capture-plan mapping formatted as id=path.",
    ),
    session_pack: Optional[str] = typer.Option(None, "--session-pack", help="Optional session-pack report JSON for friction/readiness context."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Destination trigger attempt index JSON."),
    markdown_output: Optional[str] = typer.Option(None, "--markdown-output", help="Destination trigger attempt index Markdown."),
) -> None:
    """Build a ranked trigger-attempt index from bounded trigger artifacts."""
    from cerberus_re_skill.modules.trigger_attempt_index import build_trigger_attempt_index

    try:
        result = build_trigger_attempt_index(
            attempts=attempt,
            checklists=checklist or [],
            runtime_statuses=runtime_status or [],
            instrumentation=instrumentation or [],
            frida_capture_plans=frida_capture_plan or [],
            session_pack=session_pack,
            output=output,
            markdown_output=markdown_output,
        )
        _print_json(result)
        if result.get("ok"):
            console.print(
                f"[green]Wrote[/green] {result['output']} and {result['markdown_output']} "
                f"({result['attempt_count']} attempts, next={result['recommended_trigger']})"
            )
    except Exception as e:
        _die(str(e))


@export_app.command("breakpoint-plan-preflight")
def export_breakpoint_plan_preflight(
    plan: str = typer.Argument(..., help="Breakpoint plan JSON containing a symbols list."),
    function_inventory: Optional[str] = typer.Option(None, "--function-inventory", help="function_inventory.json for the target image."),
    lldb_symbols: Optional[str] = typer.Option(None, "--lldb-symbols", help="lldb_symbols.json sidecar for the target image."),
    program_summary: Optional[str] = typer.Option(None, "--program-summary", help="program_summary.json for sidecar provenance checks."),
    lldb_trace: Optional[str] = typer.Option(None, "--lldb-trace", help="Optional lldb_trace.json from a bounded replay."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Destination preflight JSON."),
    markdown_output: Optional[str] = typer.Option(None, "--markdown-output", help="Destination preflight Markdown."),
) -> None:
    """Preflight LLDB breakpoint plans against static sources and live replay state."""
    from cerberus_re_skill.modules.breakpoint_plan_preflight import build_breakpoint_plan_preflight

    try:
        result = build_breakpoint_plan_preflight(
            plan=plan,
            function_inventory=function_inventory,
            lldb_symbols=lldb_symbols,
            program_summary=program_summary,
            lldb_trace=lldb_trace,
            output=output,
            markdown_output=markdown_output,
        )
        _print_json(result)
        if result.get("ok"):
            console.print(
                f"[green]Wrote[/green] {result['output']} and {result['markdown_output']} "
                f"({result['symbol_count']} symbols, {result['pending_live_count']} pending live)"
            )
    except Exception as e:
        _die(str(e))


@export_app.command("nil-selector-triage")
def export_nil_selector_triage(
    artifact: list[str] = typer.Option(
        ...,
        "--artifact",
        help="Repeatable action artifact mapping formatted as id=path.",
    ),
    function_inventory: Optional[str] = typer.Option(None, "--function-inventory", help="function_inventory.json for static selector matches."),
    strings: Optional[str] = typer.Option(None, "--strings", help="strings.json for selector/key evidence."),
    dossier: Optional[list[str]] = typer.Option(
        None,
        "--dossier",
        help="Optional function dossier directory mapping formatted as id=path.",
    ),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Destination nil-selector triage JSON."),
    markdown_output: Optional[str] = typer.Option(None, "--markdown-output", help="Destination nil-selector triage Markdown."),
) -> None:
    """Triage selectors that are present but return nil/default values."""
    from cerberus_re_skill.modules.nil_selector_triage import build_nil_selector_triage

    try:
        result = build_nil_selector_triage(
            artifacts=artifact,
            function_inventory=function_inventory,
            strings=strings,
            dossiers=dossier or [],
            output=output,
            markdown_output=markdown_output,
        )
        _print_json(result)
        if result.get("ok"):
            console.print(
                f"[green]Wrote[/green] {result['output']} and {result['markdown_output']} "
                f"({result['candidate_count']} candidates, top={result['top_candidate']})"
            )
    except Exception as e:
        _die(str(e))


@export_app.command("frida-capture-plan")
def export_frida_capture_plan(
    live_attach: Optional[list[str]] = typer.Option(
        None,
        "--live-attach",
        help="Optional Frida live-attach artifact mapping formatted as id=path.",
    ),
    runtime_recheck: Optional[list[str]] = typer.Option(
        None,
        "--runtime-recheck",
        help="Optional Frida runtime-recheck artifact mapping formatted as id=path.",
    ),
    diagnostics: Optional[list[str]] = typer.Option(
        None,
        "--diagnostics",
        help="Optional Frida diagnostics artifact mapping formatted as id=path.",
    ),
    enriched_runtime: Optional[list[str]] = typer.Option(
        None,
        "--enriched-runtime",
        help="Optional enriched runtime-hits artifact mapping formatted as id=path.",
    ),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Destination Frida capture plan JSON."),
    markdown_output: Optional[str] = typer.Option(None, "--markdown-output", help="Destination Frida capture plan Markdown."),
) -> None:
    """Rank Frida capture fallbacks when live daemon attach is protected."""
    from cerberus_re_skill.modules.frida_capture_plan import build_frida_capture_plan

    try:
        result = build_frida_capture_plan(
            live_attach=live_attach or [],
            runtime_recheck=runtime_recheck or [],
            diagnostics=diagnostics or [],
            enriched_runtime=enriched_runtime or [],
            output=output,
            markdown_output=markdown_output,
        )
        _print_json(result)
        if result.get("ok"):
            console.print(
                f"[green]Wrote[/green] {result['output']} and {result['markdown_output']} "
                f"(recommended={result['recommended_capture_path']})"
            )
    except Exception as e:
        _die(str(e))
