"""Export NSXPCInterface configuration-pattern evidence from Ghidra."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cerberus_re_skill.core.config import cfg


NSXPC_INTERFACE_CONFIG_SCHEMA = "ghidra-re.nsxpc-interface-config.v1"


def export_nsxpc_interface_config(
    project: str,
    program: str,
    *,
    output: str | Path | None = None,
    markdown_output: str | Path | None = None,
    factory_report: str | Path | None = None,
    functions: list[str] | None = None,
    addresses: list[str] | None = None,
    include_discovered: bool = True,
    limit: int = 40,
    timeout: int = 60,
) -> dict[str, Any]:
    """Run Ghidra-side NSXPCInterface configuration recovery for one target."""
    from cerberus_re_skill.modules.importer import run_script

    out_path = Path(output) if output else cfg.export_dir(project, program) / "nsxpc_interface_config.json"
    md_path = Path(markdown_output) if markdown_output else out_path.with_suffix(".md")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    selected_functions = _dedupe([*(functions or []), *_functions_from_factory_report(factory_report, project, program)])
    selected_addresses = _dedupe(addresses or [])

    script_args = [
        f"output={out_path}",
        f"project={project}",
        f"limit={limit}",
        f"timeout={timeout}",
        f"include_discovered={'true' if include_discovered else 'false'}",
    ]
    script_args.extend(f"function={name}" for name in selected_functions)
    script_args.extend(f"address={address}" for address in selected_addresses)
    step = run_script("ExportNSXPCInterfaceConfig.java", project, program, script_args)
    payload = _load_json(out_path, "NSXPC interface config output")
    payload.setdefault("schema", NSXPC_INTERFACE_CONFIG_SCHEMA)
    md_path.write_text(_render_markdown(payload), encoding="utf-8")
    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    return {
        "ok": True,
        "project_name": project,
        "program_name": program,
        "output": str(out_path),
        "markdown_output": str(md_path),
        "function_count": int(summary.get("function_count") or 0),
        "pattern_function_count": int(summary.get("pattern_function_count") or 0),
        "allowed_class_call_count": int(summary.get("allowed_class_call_count") or 0),
        "interface_with_protocol_call_count": int(summary.get("interface_with_protocol_call_count") or 0),
        "protocol_reference_count": int(summary.get("protocol_reference_count") or 0),
        "selected_functions": selected_functions,
        "selected_addresses": selected_addresses,
        "step": step,
    }


def _functions_from_factory_report(path: str | Path | None, project: str, program: str) -> list[str]:
    if not path:
        return []
    payload = _load_json(Path(path), "XPC interface factory report")
    target = f"{project}:{program}"
    names: list[str] = []
    for item in payload.get("factories", []) if isinstance(payload.get("factories"), list) else []:
        if not isinstance(item, dict) or item.get("target") != target:
            continue
        function = item.get("function") if isinstance(item.get("function"), dict) else {}
        name = str(function.get("name") or "")
        if name:
            names.append(name)
    return names


def _load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RuntimeError(f"{label} not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{label} is not valid JSON: {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"{label} must be a JSON object: {path}")
    return payload


def _dedupe(values: list[str]) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        deduped.append(text)
    return deduped


def _render_markdown(payload: dict[str, Any]) -> str:
    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    lines = [
        "# NSXPCInterface Configuration Patterns",
        "",
        f"- Schema: `{payload.get('schema', NSXPC_INTERFACE_CONFIG_SCHEMA)}`",
        f"- Target: `{payload.get('project_name') or ''}:{payload.get('program_name') or ''}`",
        f"- Functions scanned: {summary.get('function_count', 0)}",
        f"- Pattern functions: {summary.get('pattern_function_count', 0)}",
        f"- Allowed-class calls: {summary.get('allowed_class_call_count', 0)}",
        f"- `interfaceWithProtocol:` calls: {summary.get('interface_with_protocol_call_count', 0)}",
        f"- Protocol references: {summary.get('protocol_reference_count', 0)}",
        "",
    ]
    for item in payload.get("functions", []) if isinstance(payload.get("functions"), list) else []:
        if not isinstance(item, dict):
            continue
        lines.append(f"## {item.get('function')}")
        lines.append("")
        lines.append(f"- Entry: `{item.get('entry')}`")
        reasons = item.get("selection_reasons") if isinstance(item.get("selection_reasons"), list) else []
        if reasons:
            lines.append("- Selection reasons: " + ", ".join(f"`{reason}`" for reason in reasons))
        protocols = item.get("protocol_references") if isinstance(item.get("protocol_references"), list) else []
        if protocols:
            lines.append("- Protocol references: " + ", ".join(f"`{value}`" for value in protocols))
        lines.append(f"- Allowed-class calls: {item.get('allowed_class_call_count', 0)}")
        lines.append(f"- `interfaceWithProtocol:` calls: {item.get('interface_with_protocol_call_count', 0)}")
        allowed_calls = item.get("allowed_class_calls") if isinstance(item.get("allowed_class_calls"), list) else []
        for call in allowed_calls[:5]:
            if not isinstance(call, dict):
                continue
            lines.append(f"- Allowed-class selector: `{call.get('selector')}` at decompile line `{call.get('line_number')}`")
            class_refs = call.get("class_references") if isinstance(call.get("class_references"), list) else []
            if class_refs:
                lines.append("  Classes: " + ", ".join(f"`{value}`" for value in class_refs))
        if item.get("decompile_error"):
            lines.append(f"- Decompile error: `{item['decompile_error']}`")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
