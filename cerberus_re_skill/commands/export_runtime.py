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
    include_decompile: bool = typer.Option(False, "--include-decompile", help="Attach cached decompiler output for each matched function."),
    decompile_timeout: int = typer.Option(60, "--decompile-timeout", help="Per-function decompiler timeout in seconds."),
    auto_apply: bool = typer.Option(False, "--auto-apply", help="Apply runtime-observed comments/bookmarks back to the project."),
) -> None:
    """Enrich LLDB trace hits with Ghidra addresses and function context."""
    from cerberus_re_skill.modules.lldb_enrich import enrich_lldb_trace

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
            include_decompile=include_decompile,
            decompile_timeout=decompile_timeout,
            auto_apply=auto_apply,
        )
        _print_json(result)
        if result.get("ok"):
            mismatch_suffix = ""
            if int(result.get("symbol_mismatch_count") or 0):
                mismatch_suffix = f", mismatches={result['symbol_mismatch_count']}"
            if int(result.get("symbol_resolved_mismatch_count") or 0):
                mismatch_suffix += f", symbol-resolved={result['symbol_resolved_mismatch_count']}"
            if int(result.get("interior_boundary_mismatch_count") or 0):
                mismatch_suffix += f", interior-boundaries={result['interior_boundary_mismatch_count']}"
            console.print(
                f"[green]Wrote[/green] {result['output']} "
                f"({_mapping_summary(result)}{mismatch_suffix})"
            )
    except Exception as e:
        _die(str(e))


@export_app.command("runtime-enrich")
def export_runtime_enrich(
    project: str = typer.Argument(..., help="Ghidra project name."),
    program: str = typer.Argument(..., help="Program name within the project."),
    runtime_hits_json: str = typer.Argument(..., help="runtime_hits.json bundle to enrich."),
    function_inventory: Optional[str] = typer.Option(None, "--function-inventory", help="Path to function_inventory.json (auto-derived if omitted)."),
    lldb_symbols: Optional[str] = typer.Option(None, "--lldb-symbols", help="Path to lldb_symbols.json for slide evidence (auto-derived if omitted)."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Destination enriched runtime-hit JSON."),
    known_runtime_pc: Optional[str] = typer.Option(None, "--known-runtime-pc", help="Known runtime PC for manual slide computation."),
    known_static_addr: Optional[str] = typer.Option(None, "--known-static-addr", help="Known static/Ghidra address for manual slide computation."),
    include_decompile: bool = typer.Option(False, "--include-decompile", help="Attach cached decompiler output for each matched function."),
    decompile_timeout: int = typer.Option(60, "--decompile-timeout", help="Per-function decompiler timeout in seconds."),
) -> None:
    """Enrich shared LLDB/Frida runtime-hit bundles with static export context."""
    from cerberus_re_skill.modules.runtime_enrich import enrich_runtime_hits

    try:
        result = enrich_runtime_hits(
            project,
            program,
            runtime_hits_json,
            function_inventory_path=function_inventory,
            lldb_symbols_path=lldb_symbols,
            output=output,
            known_runtime_pc=known_runtime_pc,
            known_static_addr=known_static_addr,
            include_decompile=include_decompile,
            decompile_timeout=decompile_timeout,
        )
        _print_json(result)
        if result.get("ok"):
            mismatch_suffix = ""
            if int(result.get("symbol_mismatch_count") or 0):
                mismatch_suffix = f", mismatches={result['symbol_mismatch_count']}"
            if int(result.get("symbol_resolved_mismatch_count") or 0):
                mismatch_suffix += f", symbol-resolved={result['symbol_resolved_mismatch_count']}"
            if int(result.get("interior_boundary_mismatch_count") or 0):
                mismatch_suffix += f", interior-boundaries={result['interior_boundary_mismatch_count']}"
            console.print(
                f"[green]Wrote[/green] {result['output']} "
                f"({_mapping_summary(result)}{mismatch_suffix})"
            )
    except Exception as e:
        _die(str(e))


def _mapping_summary(result: dict[str, object]) -> str:
    matched = int(result.get("matched_function_count") or 0)
    address_mapped = int(result.get("address_mapped_function_count") or 0)
    evidence = int(result.get("address_or_symbol_evidence_count") or 0)
    hit_count = int(result.get("hit_count") or 0)
    if evidence > matched:
        return f"evidence={evidence}/{hit_count}, matched={matched}/{hit_count}, address-mapped={address_mapped}/{hit_count}"
    if address_mapped != matched:
        return f"matched={matched}/{hit_count}, address-mapped={address_mapped}/{hit_count}"
    return f"{matched}/{hit_count} hits mapped"


@export_app.command("function-identity-report")
def export_function_identity_report(
    project: str = typer.Argument(..., help="Ghidra project name."),
    program: str = typer.Argument(..., help="Program name within the project."),
    headless: str = typer.Argument(..., help="Headless function_inventory.json."),
    live: str = typer.Argument(..., help="Live bridge function JSON, /function JSON, or /functions/search JSON."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Destination identity comparison JSON."),
) -> None:
    """Compare normalized function identity fields across headless and live outputs."""
    from cerberus_re_skill.modules.function_identity import build_function_identity_report

    try:
        result = build_function_identity_report(
            project=project,
            program=program,
            headless_path=headless,
            live_path=live,
            output=output,
        )
        _print_json(result)
        if result.get("ok"):
            console.print(
                f"[green]Wrote[/green] {result['output']} "
                f"({result['matched_count']} matched, "
                f"{len(result['missing_in_live'])} missing, {len(result['extra_in_live'])} extra)"
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
    from cerberus_re_skill.modules.exporter import export_swift_layout as _export

    try:
        result = _export(project, program or None, output)
        _print_json(result)
        if result.get("ok"):
            console.print(f"[green]Wrote[/green] {result.get('output')}")
    except Exception as e:
        _die(str(e))
