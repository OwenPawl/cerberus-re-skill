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

@export_app.command("xpc-method-inventory")
def export_xpc_method_inventory(
    targets: list[str] = typer.Argument(..., help="Targets formatted as project:program."),
    xpc_dossier: Optional[str] = typer.Option(None, "--xpc-dossier", help="Path to xpc-interface-dossier JSON for ranked interface context."),
    interface_config: Optional[list[str]] = typer.Option(
        None,
        "--interface-config",
        help="NSXPC interface configuration artifact from export nsxpc-interface-config. Repeatable.",
    ),
    allowed_classes: Optional[list[str]] = typer.Option(
        None,
        "--allowed-classes",
        help="No-call NSXPCInterface allowed-class report to attach selector-specific argument/reply classes. Repeatable.",
    ),
    interface: Optional[list[str]] = typer.Option(
        None,
        "--interface",
        help="Interface to include. Repeatable. Use Interface or project:program=Interface.",
    ),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Destination method inventory JSON."),
    markdown_output: Optional[str] = typer.Option(None, "--markdown-output", help="Destination method inventory Markdown."),
    harness_output_dir: Optional[str] = typer.Option(None, "--harness-output-dir", help="Optional directory for no-call Objective-C harness stubs."),
    macho: Optional[list[str]] = typer.Option(
        None,
        "--macho",
        help="Optional Mach-O path for decoding relative Objective-C protocol method lists. Repeatable; use project:program=/path for multiple targets.",
    ),
    macho_arch: Optional[str] = typer.Option(None, "--macho-arch", help="Architecture slice for --macho, for example arm64e."),
    limit: int = typer.Option(12, "--limit", min=1, help="Maximum interfaces to inventory."),
) -> None:
    """Recover method candidates for ranked XPC interfaces."""
    from cerberus_re_skill.modules.xpc_method_inventory import build_xpc_method_inventory

    try:
        result = build_xpc_method_inventory(
            targets=targets,
            xpc_dossier_path=xpc_dossier,
            interface_config_paths=interface_config or [],
            allowed_class_paths=allowed_classes or [],
            interfaces=interface or [],
            output=output,
            markdown_output=markdown_output,
            harness_output_dir=harness_output_dir,
            macho_paths=macho or [],
            macho_arch=macho_arch,
            limit=limit,
        )
        _print_json(result)
        if result.get("ok"):
            console.print(
                f"[green]Wrote[/green] {result['output']} and {result['markdown_output']} "
                f"({result['interface_count']} interfaces, {result['method_candidate_count']} candidates)"
            )
    except Exception as e:
        _die(str(e))


@export_app.command("xpc-connection-evidence")
def export_xpc_connection_evidence(
    targets: list[str] = typer.Argument(..., help="Targets formatted as project:program."),
    xpc_dossier: Optional[str] = typer.Option(None, "--xpc-dossier", help="Path to xpc-interface-dossier JSON for ranked interface context."),
    xpc_method_inventory: Optional[str] = typer.Option(None, "--xpc-method-inventory", help="Path to xpc-method-inventory JSON for method/service context."),
    interface: Optional[list[str]] = typer.Option(
        None,
        "--interface",
        help="Explicit connection formatted as Interface=service or project:program=Interface=service.",
    ),
    framework_load: Optional[list[str]] = typer.Option(
        None,
        "--framework-load",
        help="Private framework/image path to dlopen before protocol lookup; repeatable.",
    ),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Destination connection evidence JSON."),
    markdown_output: Optional[str] = typer.Option(None, "--markdown-output", help="Destination connection evidence Markdown."),
    harness_output_dir: Optional[str] = typer.Option(None, "--harness-output-dir", help="Directory for no-call Objective-C harnesses and run logs."),
    compile_harnesses: bool = typer.Option(False, "--compile-harnesses", help="Compile generated no-call harnesses with clang."),
    run_harnesses: bool = typer.Option(False, "--run-harnesses", help="Run compiled harnesses. They create/resume/invalidate connections but invoke no remote methods."),
    timeout: float = typer.Option(5.0, "--timeout", min=0.1, help="Per-harness runtime timeout in seconds."),
    limit: int = typer.Option(6, "--limit", min=1, help="Maximum connection targets to report."),
) -> None:
    """Gather guarded no-call XPC connection evidence for ranked interfaces."""
    from cerberus_re_skill.modules.xpc_connection_evidence import build_xpc_connection_evidence

    try:
        result = build_xpc_connection_evidence(
            targets=targets,
            xpc_dossier_path=xpc_dossier,
            xpc_method_inventory_path=xpc_method_inventory,
            interfaces=interface or [],
            framework_loads=framework_load or [],
            output=output,
            markdown_output=markdown_output,
            harness_output_dir=harness_output_dir,
            compile_harnesses=compile_harnesses,
            run_harnesses=run_harnesses,
            timeout_seconds=timeout,
            limit=limit,
        )
        _print_json(result)
        if result.get("ok"):
            console.print(
                f"[green]Wrote[/green] {result['output']} and {result['markdown_output']} "
                f"({result['connection_count']} connections, {result['run_ok_count']} run ok)"
            )
    except Exception as e:
        _die(str(e))


@export_app.command("xpc-safe-read-dossier")
def export_xpc_safe_read_dossier(
    targets: list[str] = typer.Argument(..., help="Targets formatted as project:program."),
    xpc_method_inventory: str = typer.Option(..., "--xpc-method-inventory", help="Path to xpc-method-inventory JSON for selector/service context."),
    access_policy: Optional[str] = typer.Option(None, "--access-policy", help="Optional access-policy JSON, such as an access-context safe-read shape artifact."),
    connection_evidence: Optional[str] = typer.Option(None, "--connection-evidence", help="Optional xpc-connection-evidence JSON for no-call harness status."),
    completion_shapes: Optional[str] = typer.Option(None, "--completion-shapes", help="Optional xpc-completion-shapes JSON for precise reply block contracts."),
    runtime_evidence: Optional[list[str]] = typer.Option(
        None,
        "--runtime-evidence",
        help="Repeatable runtime evidence mapping formatted as id=path. Supports LLDB validation and Frida recheck JSON.",
    ),
    interface: Optional[list[str]] = typer.Option(
        None,
        "--interface",
        help="Interface to include. Repeatable. Use Interface, Interface=service, or project:program=Interface=service.",
    ),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Destination safe-read dossier JSON."),
    markdown_output: Optional[str] = typer.Option(None, "--markdown-output", help="Destination safe-read dossier Markdown."),
    limit: int = typer.Option(8, "--limit", min=1, help="Maximum interfaces to report."),
) -> None:
    """Merge safe-read XPC method, policy, and no-call harness evidence."""
    from cerberus_re_skill.modules.xpc_safe_read_dossier import build_xpc_safe_read_dossier

    try:
        result = build_xpc_safe_read_dossier(
            targets=targets,
            xpc_method_inventory_path=xpc_method_inventory,
            access_policy_path=access_policy,
            connection_evidence_path=connection_evidence,
            completion_shapes_path=completion_shapes,
            runtime_evidence=runtime_evidence or [],
            interfaces=interface or [],
            output=output,
            markdown_output=markdown_output,
            limit=limit,
        )
        _print_json(result)
        if result.get("ok"):
            console.print(
                f"[green]Wrote[/green] {result['output']} and {result['markdown_output']} "
                f"({result['interface_count']} interfaces, {result['safe_read_candidate_count']} strict reads)"
            )
    except Exception as e:
        _die(str(e))


@export_app.command("xpc-completion-shapes")
def export_xpc_completion_shapes(
    targets: list[str] = typer.Argument(..., help="Targets formatted as project:program."),
    xpc_method_inventory: str = typer.Option(..., "--xpc-method-inventory", help="Path to xpc-method-inventory JSON."),
    completion_probe: Optional[list[str]] = typer.Option(
        None,
        "--completion-probe",
        help="Focused completion-shape or allowed-class probe JSON; repeatable.",
    ),
    function_dossier: Optional[list[str]] = typer.Option(
        None,
        "--function-dossier",
        help="Function dossier directory containing decompile.c/context.json; repeatable.",
    ),
    interface: Optional[list[str]] = typer.Option(
        None,
        "--interface",
        help="Restrict to interface name or Interface=service mapping; repeatable.",
    ),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Destination completion-shape JSON."),
    markdown_output: Optional[str] = typer.Option(None, "--markdown-output", help="Destination completion-shape Markdown."),
    limit: int = typer.Option(12, "--limit", min=1, help="Maximum interfaces to report."),
) -> None:
    """Recover XPC completion/reply shapes from allowed classes and block evidence."""
    from cerberus_re_skill.modules.xpc_completion_shapes import build_xpc_completion_shapes

    try:
        result = build_xpc_completion_shapes(
            targets=targets,
            xpc_method_inventory_path=xpc_method_inventory,
            completion_probe_paths=completion_probe or [],
            function_dossier_dirs=function_dossier or [],
            interfaces=interface or [],
            output=output,
            markdown_output=markdown_output,
            limit=limit,
        )
        _print_json(result)
        if result.get("ok"):
            console.print(
                f"[green]Wrote[/green] {result['output']} and {result['markdown_output']} "
                f"({result['completion_method_count']} completion methods, {result['reply_shape_count']} reply shapes)"
            )
    except Exception as e:
        _die(str(e))


@export_app.command("xpc-allowed-class-focus")
def export_xpc_allowed_class_focus(
    allowed_class_probe: str = typer.Option(..., "--allowed-class-probe", help="Focused or broad allowed-class probe JSON."),
    selector: Optional[list[str]] = typer.Option(
        None,
        "--selector",
        help="Selector to include. Repeatable. Defaults to selectors found in the probe.",
    ),
    method_inventory: Optional[str] = typer.Option(None, "--method-inventory", help="Optional xpc-method-inventory JSON."),
    readiness: Optional[str] = typer.Option(None, "--readiness", help="Optional readiness JSON."),
    completion_shapes: Optional[str] = typer.Option(None, "--completion-shapes", help="Optional xpc-completion-shapes JSON."),
    static_config: Optional[str] = typer.Option(None, "--static-config", help="Optional nsxpc-interface-config JSON."),
    lldb_validation: Optional[str] = typer.Option(None, "--lldb-validation", help="Optional lldb-trace-validation JSON."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Destination allowed-class focus JSON."),
    markdown_output: Optional[str] = typer.Option(None, "--markdown-output", help="Destination allowed-class focus Markdown."),
) -> None:
    """Join no-call allowed-class probes with readiness and LLDB boundary evidence."""
    from cerberus_re_skill.modules.xpc_allowed_class_focus import build_xpc_allowed_class_focus

    try:
        result = build_xpc_allowed_class_focus(
            allowed_class_probe_path=allowed_class_probe,
            selectors=selector or [],
            method_inventory_path=method_inventory,
            readiness_path=readiness,
            completion_shapes_path=completion_shapes,
            static_config_path=static_config,
            lldb_validation_path=lldb_validation,
            output=output,
            markdown_output=markdown_output,
        )
        _print_json(result)
        if result.get("ok"):
            console.print(
                f"[green]Wrote[/green] {result['output']} and {result['markdown_output']} "
                f"({result['selector_count']} selectors, {result['allowed_class_recovered_selector_count']} recovered)"
            )
    except Exception as e:
        _die(str(e))


@export_app.command("xpc-interface-factory")
def export_xpc_interface_factory(
    targets: list[str] = typer.Argument(..., help="Targets formatted as project:program."),
    xpc_dossier: Optional[str] = typer.Option(None, "--xpc-dossier", help="Path to xpc-interface-dossier JSON for ranked interface context."),
    xpc_method_inventory: Optional[str] = typer.Option(None, "--xpc-method-inventory", help="Path to xpc-method-inventory JSON for method/service context."),
    interface_config: Optional[list[str]] = typer.Option(
        None,
        "--interface-config",
        help="NSXPC interface configuration artifact from export nsxpc-interface-config. Repeatable.",
    ),
    function_dossier: Optional[list[str]] = typer.Option(
        None,
        "--function-dossier",
        help="Function dossier mapping formatted as Interface=directory or project:program=Interface=directory.",
    ),
    interface: Optional[list[str]] = typer.Option(
        None,
        "--interface",
        help="Interface to include. Repeatable. Use Interface or project:program=Interface.",
    ),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Destination interface factory JSON."),
    markdown_output: Optional[str] = typer.Option(None, "--markdown-output", help="Destination interface factory Markdown."),
    limit: int = typer.Option(10, "--limit", min=1, help="Maximum interfaces to report."),
) -> None:
    """Recover XPC interface factory evidence from exports and function dossiers."""
    from cerberus_re_skill.modules.xpc_interface_factory import build_xpc_interface_factory_catalog

    try:
        result = build_xpc_interface_factory_catalog(
            targets=targets,
            xpc_dossier_path=xpc_dossier,
            xpc_method_inventory_path=xpc_method_inventory,
            interface_config_paths=interface_config or [],
            function_dossiers=function_dossier or [],
            interfaces=interface or [],
            output=output,
            markdown_output=markdown_output,
            limit=limit,
        )
        _print_json(result)
        if result.get("ok"):
            console.print(
                f"[green]Wrote[/green] {result['output']} and {result['markdown_output']} "
                f"({result['factory_count']} factories, {result['local_factory_count']} local)"
            )
    except Exception as e:
        _die(str(e))


@export_app.command("nsxpc-interface-config")
def export_nsxpc_interface_config_cmd(
    project: str = typer.Argument(..., help="Ghidra project name."),
    program: str = typer.Argument(..., help="Program name within the project."),
    factory_report: Optional[str] = typer.Option(None, "--factory-report", help="Optional xpc-interface-factory JSON used to seed local factory functions."),
    function: Optional[list[str]] = typer.Option(None, "--function", help="Function name to decompile. Repeatable."),
    address: Optional[list[str]] = typer.Option(None, "--address", help="Function address to decompile. Repeatable."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Destination configuration JSON."),
    markdown_output: Optional[str] = typer.Option(None, "--markdown-output", help="Destination configuration Markdown."),
    include_discovered: bool = typer.Option(True, "--include-discovered/--no-include-discovered", help="Also discover functions from NSXPCInterface selector call references."),
    limit: int = typer.Option(40, "--limit", min=1, help="Maximum functions to decompile."),
    timeout: int = typer.Option(60, "--timeout", min=1, help="Per-function decompiler timeout in seconds."),
) -> None:
    """Recover NSXPCInterface configuration patterns through a Ghidra script."""
    from cerberus_re_skill.modules.nsxpc_interface_config import export_nsxpc_interface_config

    try:
        result = export_nsxpc_interface_config(
            project,
            program,
            factory_report=factory_report,
            functions=function or [],
            addresses=address or [],
            output=output,
            markdown_output=markdown_output,
            include_discovered=include_discovered,
            limit=limit,
            timeout=timeout,
        )
        _print_json(result)
        if result.get("ok"):
            console.print(
                f"[green]Wrote[/green] {result['output']} and {result['markdown_output']} "
                f"({result['pattern_function_count']} pattern functions, {result['allowed_class_call_count']} allowed-class calls)"
            )
    except Exception as e:
        _die(str(e))
