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


@export_app.command("apple-bundle")
def export_apple_bundle_cmd(
    project: str = typer.Argument(..., help="Ghidra project name."),
    program: str = typer.Argument(..., help="Program name within the project."),
    output_dir: Optional[str] = typer.Option(None, "--output-dir", "-o", help="Destination bundle directory."),
) -> None:
    """Export the standard Apple-focused JSON bundle for an existing project."""
    from cerberus_re_skill.core.config import cfg
    from cerberus_re_skill.modules.importer import run_script

    try:
        out_path = Path(output_dir) if output_dir else cfg.export_dir(project, program)
        result = run_script(
            "ExportAppleBundle.java",
            project,
            program,
            script_args=[f"outdir={out_path}"],
        )
        result["output"] = str(out_path)
        _print_json(result)
        if result.get("ok"):
            console.print(f"[green]Wrote[/green] {result['output']}")
    except Exception as e:
        _die(str(e))


@export_app.command("term-index")
def export_term_index_cmd(
    inputs: list[str] = typer.Argument(
        ...,
        help="Export bundle inputs: label=/path, /path, or project:program.",
    ),
    term: list[str] = typer.Option(
        ...,
        "--term",
        help="Term to search for in exported JSON records. Repeatable.",
    ),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Destination term-index JSON."),
    markdown_output: Optional[str] = typer.Option(None, "--markdown-output", help="Destination term-index Markdown."),
    max_samples: int = typer.Option(10, "--max-samples", min=1, help="Maximum total samples per input bundle."),
    ignore_case: bool = typer.Option(False, "--ignore-case", help="Match terms case-insensitively."),
    json_file: Optional[list[str]] = typer.Option(
        None,
        "--json-file",
        help="Restrict scanning to an exported JSON filename. Repeatable.",
    ),
) -> None:
    """Build a bounded cross-export term index from existing JSON bundles."""
    from cerberus_re_skill.modules.term_index import DEFAULT_JSON_FILES, build_term_index

    try:
        result = build_term_index(
            inputs=inputs,
            terms=term,
            output=output,
            markdown_output=markdown_output,
            max_samples=max_samples,
            ignore_case=ignore_case,
            json_files=tuple(json_file) if json_file else DEFAULT_JSON_FILES,
        )
        _print_json(result)
        if result.get("ok"):
            console.print(
                f"[green]Wrote[/green] {result['output']} and {result['markdown_output']} "
                f"({result['input_count']} inputs, {len(result['terms'])} terms)"
            )
    except Exception as e:
        _die(str(e))


@export_app.command("triage-bundle")
def export_triage_bundle_cmd(
    project: str = typer.Argument(..., help="Ghidra project name."),
    program: str = typer.Argument(..., help="Program name within the project."),
    output_dir: Optional[str] = typer.Option(None, "--output-dir", "-o", help="Destination bundle directory."),
    manifest: Optional[str] = typer.Option(None, "--manifest", help="Triage pattern manifest JSON."),
    sample_limit: int = typer.Option(20, "--sample-limit", help="Evidence samples per match category."),
    max_depth: int = typer.Option(4, "--max-depth", help="Maximum entrypoint-to-sink path depth."),
    max_visited_functions: int = typer.Option(
        1500,
        "--max-visited-functions",
        help="Maximum functions visited while triaging paths.",
    ),
    top_candidates: int = typer.Option(50, "--top-candidates", help="Maximum ranked candidate paths to emit."),
    xref_limit: int = typer.Option(25, "--xref-limit", help="Maximum xrefs sampled per node."),
    entrypoint_limit: int = typer.Option(40, "--entrypoint-limit", help="Maximum entrypoints considered for path triage."),
) -> None:
    """Export entrypoints, sinks, candidate paths, and a Markdown triage summary."""
    from cerberus_re_skill.modules.triage import export_triage_bundle

    try:
        result = export_triage_bundle(
            project=project,
            program=program,
            output_dir=output_dir,
            manifest=manifest,
            sample_limit=sample_limit,
            max_depth=max_depth,
            max_visited_functions=max_visited_functions,
            top_candidates=top_candidates,
            xref_limit=xref_limit,
            entrypoint_limit=entrypoint_limit,
        )
        _print_json(result)
        if result.get("ok"):
            counts = result.get("counts", {})
            console.print(
                f"[green]Wrote[/green] {result['output_dir']} "
                f"({counts.get('entrypoint_count', 0)} entrypoints, "
                f"{counts.get('sink_count', 0)} sinks, "
                f"{counts.get('candidate_count', 0)} candidate paths)"
            )
    except Exception as e:
        _die(str(e))


@export_app.command("function-dossier")
def export_function_dossier_cmd(
    project: str = typer.Argument(..., help="Ghidra project name."),
    program: str = typer.Argument(..., help="Program name within the project."),
    function: str = typer.Option("", "--function", "-f", help="Function name to inspect."),
    address: str = typer.Option("", "--address", "-a", help="Function entry address to inspect."),
    output_dir: Optional[str] = typer.Option(None, "--output-dir", "-o", help="Destination dossier directory."),
    manifest: Optional[str] = typer.Option(None, "--manifest", help="Triage pattern manifest JSON."),
    sample_limit: int = typer.Option(25, "--sample-limit", help="Evidence samples per dossier section."),
    linear_instruction_limit: int = typer.Option(
        96,
        "--linear-instruction-limit",
        help="Maximum decoded listing instructions preserved beside the decompile output.",
    ),
    timeout: int = typer.Option(60, "--timeout", help="Decompiler timeout in seconds."),
) -> None:
    """Export metadata, decompile output, raw instruction context, and review notes for one function."""
    from cerberus_re_skill.modules.triage import export_function_dossier

    try:
        result = export_function_dossier(
            project=project,
            program=program,
            function=function,
            address=address,
            output_dir=output_dir,
            manifest=manifest,
            sample_limit=sample_limit,
            linear_instruction_limit=linear_instruction_limit,
            timeout=timeout,
        )
        _print_json(result)
        if result.get("ok"):
            console.print(f"[green]Wrote[/green] {result['output_dir']}")
        else:
            raise RuntimeError(str(result.get("failure_reason") or "function dossier export failed"))
    except Exception as e:
        _die(str(e))


@export_app.command("swift-outlined")
def export_swift_outlined_cmd(
    project: str = typer.Argument(..., help="Ghidra project name."),
    program: str = typer.Argument(..., help="Program name within the project."),
    output_dir: Optional[str] = typer.Option(None, "--output-dir", "-o", help="Destination report directory."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Classify and report without renaming functions."),
    no_inline: bool = typer.Option(False, "--no-inline", help="Do not mark eligible helper functions inline."),
    skip_stubs: bool = typer.Option(False, "--skip-stubs", help="Skip authstub renames."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Emit per-function resolver logs."),
    no_scan_fun_stubs: bool = typer.Option(False, "--no-scan-fun-stubs", help="Do not scan anonymous FUN_* authstub candidates."),
    no_second_pass: bool = typer.Option(False, "--no-second-pass", help="Disable pactail re-resolution pass."),
    authstub_map: Optional[str] = typer.Option(None, "--authstub-map", help="Optional authstub_map.json sidecar."),
    build_authstub_map: bool = typer.Option(False, "--build-authstub-map", help="Build a dyld-backed authstub_map.json first."),
    binary: Optional[str] = typer.Option(None, "--binary", help="Mach-O binary to use when building --build-authstub-map."),
    dyld_source: Optional[str] = typer.Option(None, "--dyld-source", help="Mounted or extracted dyld/source root for --build-authstub-map."),
) -> None:
    """Resolve Swift outlined helpers and authstub names with the bundled Ghidra script."""
    from cerberus_re_skill.modules.swift_outlined import resolve_swift_outlined

    try:
        if build_authstub_map and not authstub_map:
            from cerberus_re_skill.modules.authstub_map import build_authstub_map as _build_authstub_map

            map_result = _build_authstub_map(
                project=project,
                program=program,
                output_dir=output_dir,
                binary=binary,
                dyld_source=dyld_source,
            )
            authstub_map = map_result["output"]
        result = resolve_swift_outlined(
            project=project,
            program=program,
            output_dir=output_dir,
            dry_run=dry_run,
            inline=not no_inline,
            skip_stubs=skip_stubs,
            verbose=verbose,
            scan_fun_stubs=not no_scan_fun_stubs,
            second_pass=not no_second_pass,
            authstub_map=authstub_map,
        )
        _print_json(result)
        if result.get("ok"):
            summary = result.get("summary", {})
            console.print(
                f"[green]Wrote[/green] {result['report']} "
                f"({summary.get('total_outlined_functions', 0)} found, "
                f"{summary.get('renamed', 0)} renamed)"
            )
    except Exception as e:
        _die(str(e))


@export_app.command("authstub-map")
def export_authstub_map_cmd(
    project: str = typer.Argument(..., help="Ghidra project name."),
    program: str = typer.Argument(..., help="Program name within the project."),
    output_dir: Optional[str] = typer.Option(None, "--output-dir", "-o", help="Destination report directory."),
    output: Optional[str] = typer.Option(None, "--output", help="Destination authstub_map.json."),
    binary: Optional[str] = typer.Option(None, "--binary", help="Mach-O binary to inspect with dyld-backed tools."),
    dyld_source: Optional[str] = typer.Option(None, "--dyld-source", help="Mounted or extracted dyld/source root."),
    swift_outlined_report: Optional[str] = typer.Option(None, "--swift-outlined-report", help="Existing swift_outlined_resolved.json."),
    no_generate_report: bool = typer.Option(False, "--no-generate-report", help="Do not run a dry-run Swift outlined pass if the report is missing."),
    no_ghidra_probe: bool = typer.Option(False, "--no-ghidra-probe", help="Skip Ghidra-side slot pointer probing."),
    timeout: float = typer.Option(60.0, "--timeout", help="dyld_info/otool timeout in seconds."),
) -> None:
    """Build a dyld-backed authstub_map.json sidecar for Swift outlined resolution."""
    from cerberus_re_skill.modules.authstub_map import build_authstub_map

    try:
        result = build_authstub_map(
            project=project,
            program=program,
            output_dir=output_dir,
            output=output,
            binary=binary,
            dyld_source=dyld_source,
            swift_outlined_report=swift_outlined_report,
            generate_report=not no_generate_report,
            ghidra_probe=not no_ghidra_probe,
            timeout=timeout,
        )
        _print_json(result)
        if result.get("ok"):
            stats = result.get("stats", {})
            console.print(
                f"[green]Wrote[/green] {result['output']} "
                f"({stats.get('resolved_stub_count', 0)}/{stats.get('stub_count', 0)} stubs resolved, "
                f"{stats.get('resolved_slot_count', 0)}/{stats.get('slot_count', 0)} slots resolved)"
            )
    except Exception as e:
        _die(str(e))


@export_app.command("macho-structure")
def export_macho_structure(
    project: str = typer.Argument(..., help="Ghidra project name."),
    program: str = typer.Argument("", help="Program name within the project (optional when --output given)."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Destination JSON file (default: exports/<project>/<program>/macho_structure.json)."),
) -> None:
    """Export Mach-O structural metadata to macho_structure.json.

    Runs ExportMachOStructure.java via Ghidra headless and writes a JSON file
    containing load commands, segments/sections, UUID, build/source versions,
    dylib ordinal table, rpaths, encryption info, and entitlements.
    """
    from cerberus_re_skill.modules.exporter import export_macho_structure as _export

    try:
        result = _export(project, program or None, output)
        _print_json(result)
        if result.get("ok"):
            console.print(f"[green]Wrote[/green] {result.get('output')}")
    except Exception as e:
        _die(str(e))


@export_app.command("objc-layout")
def export_objc_layout(
    project: str = typer.Argument(..., help="Ghidra project name."),
    program: str = typer.Argument("", help="Program name within the project (optional when --output given)."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Destination JSON file (default: exports/<project>/<program>/objc_layout.json)."),
) -> None:
    """Export per-class ObjC ivar and method layout to objc_layout.json.

    Runs ExportObjCTypeLayout.java via Ghidra headless. Walks __objc_classlist
    and __objc_catlist, parsing class_ro_t / ivar_list_t / method_list_t for
    every class defined in the binary. Outputs superclass chains, protocol
    conformances, ivar offsets/types, and method selectors/imp addresses.
    """
    from cerberus_re_skill.modules.exporter import export_objc_layout as _export

    try:
        result = _export(project, program or None, output)
        _print_json(result)
        if result.get("ok"):
            console.print(f"[green]Wrote[/green] {result.get('output')}")
    except Exception as e:
        _die(str(e))


@export_app.command("class-hierarchy")
def export_class_hierarchy(
    project: str = typer.Argument(..., help="Ghidra project name."),
    program: str = typer.Argument(..., help="Program name within the project."),
    objc_layout: Optional[str] = typer.Option(None, "--objc-layout", help="Path to objc_layout.json (auto-derived if omitted)."),
    swift_layout: Optional[str] = typer.Option(None, "--swift-layout", help="Path to swift_layout.json (auto-derived if omitted)."),
    output_json: Optional[str] = typer.Option(None, "--output-json", help="Destination class_hierarchy.json (auto-derived if omitted)."),
    output_mmd: Optional[str] = typer.Option(None, "--output-mmd", help="Destination class_hierarchy.mmd (auto-derived if omitted)."),
) -> None:
    """Build class/type hierarchy from objc_layout.json + swift_layout.json.

    Post-processes the output of 'ghidra-re export objc-layout' and
    'ghidra-re export swift-layout' to produce a cross-language type graph.
    Outputs class_hierarchy.json (nodes + edges + protocol conformance maps)
    and class_hierarchy.mmd (Mermaid diagram capped at 120 nodes).
    """
    from cerberus_re_skill.modules.hierarchy import build_class_hierarchy

    try:
        result = build_class_hierarchy(
            project=project,
            program=program,
            objc_layout_path=objc_layout,
            swift_layout_path=swift_layout,
            output_json=output_json,
            output_mmd=output_mmd,
        )
        _print_json(result)
        if result.get("ok"):
            console.print(
                f"[green]Wrote[/green] {result['output_json']} "
                f"({result['node_count']} nodes, {result['edge_count']} edges)"
            )
            console.print(f"[green]Wrote[/green] {result['output_mmd']}")
    except Exception as e:
        _die(str(e))


@export_app.command("framework-graph")
def export_framework_graph(
    project: str = typer.Argument(..., help="Ghidra project name."),
    program: str = typer.Argument(..., help="Program name within the project."),
    macho_structure: Optional[str] = typer.Option(None, "--macho-structure", help="Path to macho_structure.json (auto-derived if omitted)."),
    symbols: Optional[str] = typer.Option(None, "--symbols", help="Path to symbols.json (auto-derived if omitted)."),
    output: Optional[str] = typer.Option(None, "--output", help="Destination framework_graph.json (auto-derived if omitted)."),
    output_global: Optional[str] = typer.Option(None, "--output-global", help="Destination project-level framework_graph_global.json."),
) -> None:
    """Build a framework dependency graph from Mach-O metadata and symbol usage."""
    from cerberus_re_skill.modules.frameworks import build_framework_graph

    try:
        result = build_framework_graph(
            project=project,
            program=program,
            macho_structure_path=macho_structure,
            symbols_path=symbols,
            output=output,
            output_global=output_global,
        )
        _print_json(result)
        if result.get("ok"):
            console.print(f"[green]Wrote[/green] {result['output']}")
            console.print(f"[green]Wrote[/green] {result['output_global']}")
    except Exception as e:
        _die(str(e))


@export_app.command("subsystem-clusters")
def export_subsystem_clusters(
    project: str = typer.Argument(..., help="Ghidra project name."),
    program: str = typer.Argument(..., help="Program name within the project."),
    function_inventory: Optional[str] = typer.Option(None, "--function-inventory", help="Path to function_inventory.json (auto-derived if omitted)."),
    objc_layout: Optional[str] = typer.Option(None, "--objc-layout", help="Path to objc_layout.json (auto-derived if omitted)."),
    output: Optional[str] = typer.Option(None, "--output", help="Destination subsystem_clusters.json (auto-derived if omitted)."),
    min_prefix_size: int = typer.Option(3, "--min-prefix-size", help="Minimum shared prefix size to form a cluster."),
    no_xref_communities: bool = typer.Option(False, "--no-xref-communities", help="Disable NetworkX-based xref community detection."),
) -> None:
    """Group functions into subsystem clusters from function inventory and ObjC layout."""
    from cerberus_re_skill.modules.clusters import build_subsystem_clusters

    try:
        result = build_subsystem_clusters(
            project=project,
            program=program,
            function_inventory_path=function_inventory,
            objc_layout_path=objc_layout,
            output=output,
            min_prefix_size=min_prefix_size,
            use_xref_communities=not no_xref_communities,
        )
        _print_json(result)
        if result.get("ok"):
            console.print(
                f"[green]Wrote[/green] {result['output']} "
                f"({result['cluster_count']} clusters from {result['total_functions']} functions)"
            )
    except Exception as e:
        _die(str(e))


@export_app.command("xpc-surface")
def export_xpc_surface(
    project: str = typer.Argument(..., help="Ghidra project name."),
    program: str = typer.Argument(..., help="Program name within the project."),
    bundle_dir: Optional[str] = typer.Option(None, "--bundle-dir", help="Directory containing apple-bundle JSON inputs."),
    objc_metadata: Optional[str] = typer.Option(None, "--objc-metadata", help="Path to objc_metadata.json (auto-derived if omitted)."),
    strings: Optional[str] = typer.Option(None, "--strings", help="Path to strings.json (auto-derived if omitted)."),
    symbols: Optional[str] = typer.Option(None, "--symbols", help="Path to symbols.json (auto-derived if omitted)."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Destination xpc_surface.json."),
    markdown_output: Optional[str] = typer.Option(None, "--markdown-output", help="Destination xpc_surface.md."),
) -> None:
    """Recover XPC service, protocol, listener, and connection hints from exports."""
    from cerberus_re_skill.modules.xpc_surface import build_xpc_surface

    try:
        result = build_xpc_surface(
            project=project,
            program=program,
            bundle_dir=bundle_dir,
            objc_metadata_path=objc_metadata,
            strings_path=strings,
            symbols_path=symbols,
            output=output,
            markdown_output=markdown_output,
        )
        _print_json(result)
        if result.get("ok"):
            for warning in result.get("warnings", []):
                console.print(f"[yellow]Warning:[/yellow] {warning}")
            console.print(
                f"[green]Wrote[/green] {result['output']} and {result['markdown_output']} "
                f"({result['service_name_count']} services, "
                f"{result.get('reverse_dns_service_hint_count', 0)} service hints, "
                f"{result['xpc_protocol_count']} protocols)"
            )
    except Exception as e:
        _die(str(e))


@export_app.command("xpc-graph")
def export_xpc_graph(
    targets: list[str] = typer.Argument(..., help="Targets formatted as project:program."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Destination xpc_graph.json."),
    markdown_output: Optional[str] = typer.Option(None, "--markdown-output", help="Destination xpc_graph.md."),
    owner_hint: Optional[list[str]] = typer.Option(
        None,
        "--owner-hint",
        help="Repeatable service owner hint formatted as service=project:program.",
    ),
) -> None:
    """Merge per-binary XPC surface reports into a coarse IPC graph."""
    from cerberus_re_skill.modules.xpc_graph import build_xpc_graph

    try:
        result = build_xpc_graph(
            targets=targets,
            output=output,
            markdown_output=markdown_output,
            owner_hints=owner_hint or [],
        )
        _print_json(result)
        if result.get("ok"):
            console.print(
                f"[green]Wrote[/green] {result['output']} and {result['markdown_output']} "
                f"({result['node_count']} nodes, {result['edge_count']} edges)"
            )
    except Exception as e:
        _die(str(e))


@export_app.command("xpc-interface-dossier")
def export_xpc_interface_dossier(
    targets: list[str] = typer.Argument(..., help="Targets formatted as project:program."),
    xpc_graph: Optional[str] = typer.Option(None, "--xpc-graph", help="Path to xpc_graph.json for edge context."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Destination dossier JSON."),
    markdown_output: Optional[str] = typer.Option(None, "--markdown-output", help="Destination dossier Markdown."),
    limit: int = typer.Option(25, "--limit", min=1, help="Maximum ranked candidates to write."),
) -> None:
    """Rank XPC interface candidates for harness follow-up."""
    from cerberus_re_skill.modules.xpc_interface_dossier import build_xpc_interface_dossier

    try:
        result = build_xpc_interface_dossier(
            targets=targets,
            xpc_graph_path=xpc_graph,
            output=output,
            markdown_output=markdown_output,
            limit=limit,
        )
        _print_json(result)
        if result.get("ok"):
            console.print(
                f"[green]Wrote[/green] {result['output']} and {result['markdown_output']} "
                f"({result['reported_candidate_count']}/{result['candidate_count']} candidates)"
            )
    except Exception as e:
        _die(str(e))
