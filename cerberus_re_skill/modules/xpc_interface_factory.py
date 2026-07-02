"""Recover XPC interface factory evidence from exports and dossiers."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from cerberus_re_skill.core.config import cfg
from cerberus_re_skill.core.utils import utc_now


XPC_INTERFACE_FACTORY_SCHEMA = "ghidra-re.xpc-interface-factory.v1"


def build_xpc_interface_factory_catalog(
    targets: list[str],
    *,
    xpc_dossier_path: str | Path | None = None,
    xpc_method_inventory_path: str | Path | None = None,
    interface_config_paths: list[str] | None = None,
    function_dossiers: list[str] | None = None,
    interfaces: list[str] | None = None,
    output: str | Path | None = None,
    markdown_output: str | Path | None = None,
    limit: int = 10,
) -> dict[str, Any]:
    """Build a catalog of XPC interface factory recovery status."""
    parsed_targets = [_parse_target(target) for target in targets]
    if not parsed_targets:
        raise RuntimeError("at least one target is required")
    inventory = _load_json(Path(xpc_method_inventory_path), "xpc method inventory") if xpc_method_inventory_path else {}
    dossier = _load_json(Path(xpc_dossier_path), "xpc interface dossier") if xpc_dossier_path else {}
    dossier_map = _parse_function_dossiers(function_dossiers or [])
    config_map = _parse_interface_configs(interface_config_paths or [])
    selected = _selected_interfaces(parsed_targets, inventory, dossier, interfaces or [], limit)
    factories = [
        _factory_record(project, program, interface, context, dossier_map, config_map)
        for project, program, interface, context in selected
    ]
    summary = {
        "factory_count": len(factories),
        "local_factory_count": sum(1 for item in factories if item["factory_status"] == "local_factory"),
        "unresolved_authstub_count": sum(1 for item in factories if item["factory_status"] == "unresolved_authstub"),
        "protocol_reference_count": sum(len(item["protocol_references"]) for item in factories),
        "allowed_class_call_count": sum(item["allowed_class_call_count"] for item in factories),
        "needs_decompile_count": sum(1 for item in factories if item["factory_status"] == "local_factory_needs_dossier"),
    }
    report = {
        "schema": XPC_INTERFACE_FACTORY_SCHEMA,
        "ok": True,
        "created_at": utc_now(),
        "inputs": {
            "targets": [{"project": project, "program": program} for project, program in parsed_targets],
            "xpc_dossier": str(xpc_dossier_path) if xpc_dossier_path else None,
            "xpc_method_inventory": str(xpc_method_inventory_path) if xpc_method_inventory_path else None,
            "interface_configs": interface_config_paths or [],
            "function_dossiers": function_dossiers or [],
            "interfaces": interfaces or [],
        },
        "summary": summary,
        "factories": factories,
    }
    out_path = Path(output) if output else cfg.exports_dir / "xpc_interface_factory.json"
    md_path = Path(markdown_output) if markdown_output else cfg.exports_dir / "xpc_interface_factory.md"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    md_path.write_text(_render_markdown(report), encoding="utf-8")
    return {"ok": True, "output": str(out_path), "markdown_output": str(md_path), **summary}


def _selected_interfaces(
    targets: list[tuple[str, str]],
    inventory: dict[str, Any],
    dossier: dict[str, Any],
    interfaces: list[str],
    limit: int,
) -> list[tuple[str, str, str, dict[str, Any]]]:
    target_set = {f"{project}:{program}" for project, program in targets}
    selected: list[tuple[str, str, str, dict[str, Any]]] = []
    for spec in interfaces:
        if "=" in spec:
            target, interface = spec.split("=", 1)
            if ":" not in target:
                raise RuntimeError(f"interface target must be project:program=Interface: {spec}")
            project, program = target.split(":", 1)
        else:
            project, program = targets[0]
            interface = spec
        selected.append((project, program, interface, {"source": "explicit"}))
    if inventory:
        for item in inventory.get("interfaces", []):
            if not isinstance(item, dict):
                continue
            target = str(item.get("target") or "")
            interface = str(item.get("interface") or "")
            if target not in target_set or not interface:
                continue
            project, program = target.split(":", 1)
            selected.append((project, program, interface, _context_from_inventory(item)))
            if len(selected) >= limit:
                break
    if dossier and len(selected) < limit:
        for candidate in dossier.get("candidates", []):
            if not isinstance(candidate, dict):
                continue
            target = str(candidate.get("target") or "")
            interface = str(candidate.get("interface") or "")
            if target not in target_set or not interface:
                continue
            project, program = target.split(":", 1)
            selected.append((project, program, interface, _context_from_dossier(candidate)))
            if len(selected) >= limit:
                break
    deduped: list[tuple[str, str, str, dict[str, Any]]] = []
    seen: set[tuple[str, str, str]] = set()
    for project, program, interface, context in selected:
        key = (project, program, interface)
        if key in seen:
            continue
        seen.add(key)
        deduped.append((project, program, interface, context))
    return deduped[: max(1, limit)]


def _factory_record(
    project: str,
    program: str,
    interface: str,
    context: dict[str, Any],
    dossier_map: dict[str, Path],
    config_map: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    export_dir = cfg.export_dir(project, program)
    functions = _load_optional_json(export_dir / "function_inventory.json")
    symbols = _load_optional_json(export_dir / "symbols.json")
    authstubs = _load_optional_json(export_dir / "authstub_map.json")
    function = _find_function(functions, interface)
    symbol = _find_symbol(symbols, interface)
    authstub = _find_authstub(authstubs, interface)
    dossier_dir = (
        dossier_map.get(f"{project}:{program}:{interface}")
        or dossier_map.get(f"{project}:{program}:{interface.lstrip('_')}")
        or dossier_map.get(interface)
        or dossier_map.get(interface.lstrip("_"))
    )
    dossier_evidence = _dossier_evidence(dossier_dir) if dossier_dir else {}
    config_evidence = _config_evidence(project, program, interface, function, config_map)
    allowed_class_calls = _merge_allowed_calls(dossier_evidence, config_evidence)
    protocol_references = sorted(
        {
            *[str(item) for item in dossier_evidence.get("protocol_references", [])],
            *[str(item) for item in config_evidence.get("protocol_references", [])],
        }
    )
    interface_with_protocol_count = max(
        int(dossier_evidence.get("interface_with_protocol_call_count", 0) or 0),
        int(config_evidence.get("interface_with_protocol_call_count", 0) or 0),
    )
    status = "missing"
    if function:
        status = "local_factory" if dossier_evidence else "local_factory_needs_dossier"
    elif authstub:
        status = "unresolved_authstub"
    elif symbol:
        status = "symbol_only"
    return {
        "target": f"{project}:{program}",
        "project": project,
        "program": program,
        "interface": interface,
        "factory_status": status,
        "function": function,
        "symbol": symbol,
        "authstub": authstub,
        "context": context,
        "function_dossier": str(dossier_dir) if dossier_dir else "",
        "interface_config": config_evidence.get("artifact", ""),
        "protocol_references": protocol_references,
        "interface_with_protocol_call_count": interface_with_protocol_count,
        "config_interface_with_protocol_call_count": config_evidence.get("interface_with_protocol_call_count", 0),
        "dossier_allowed_class_call_count": dossier_evidence.get("allowed_class_call_count", 0),
        "config_allowed_class_call_count": config_evidence.get("allowed_class_call_count", 0),
        "allowed_class_call_count": len(allowed_class_calls),
        "allowed_class_selectors": sorted({str(item.get("selector") or "") for item in allowed_class_calls if item.get("selector")}),
        "allowed_class_calls": allowed_class_calls,
        "configuration_selection_reasons": config_evidence.get("selection_reasons", []),
        "decompile_excerpt": dossier_evidence.get("decompile_excerpt", ""),
    }


def _dossier_evidence(dossier_dir: Path) -> dict[str, Any]:
    decompile = dossier_dir / "decompile.c"
    if not decompile.exists():
        return {}
    text = decompile.read_text(encoding="utf-8", errors="replace")
    protocol_refs = sorted(
        {
            _clean_protocol_ref(match)
            for match in re.findall(r"__OBJC_PROTOCOL_REFERENCE_+\$?([A-Za-z_][A-Za-z0-9_]*)", text)
        }
    )
    allowed_class_calls = _allowed_class_calls_from_text(text)
    allowed_class_selectors = sorted({call["selector"] for call in allowed_class_calls})
    return {
        "protocol_references": [item for item in protocol_refs if item],
        "interface_with_protocol_call_count": text.count("interfaceWithProtocol"),
        "allowed_class_call_count": len(allowed_class_calls),
        "allowed_class_calls": allowed_class_calls,
        "allowed_class_selectors": allowed_class_selectors,
        "decompile_excerpt": "\n".join(text.splitlines()[:24]),
    }


def _allowed_class_calls_from_text(text: str) -> list[dict[str, Any]]:
    calls = []
    for index, line in enumerate(text.splitlines(), start=1):
        selector = _canonical_allowed_selector(line)
        if not selector:
            continue
        calls.append(
            {
                "selector": selector,
                "line_number": index,
                "line": line.strip(),
                "source": "function_dossier",
            }
        )
    return calls


def _canonical_allowed_selector(text: str) -> str:
    lowered = text.lower()
    if "setclasses:forselector:argumentindex:ofreply" in lowered or "setclasses_forselector_argumentindex_ofreply" in lowered:
        return "setClasses:forSelector:argumentIndex:ofReply:"
    if "setclass:forselector:argumentindex:ofreply" in lowered or "setclass_forselector_argumentindex_ofreply" in lowered:
        return "setClass:forSelector:argumentIndex:ofReply:"
    return ""


def _parse_interface_configs(paths: list[str]) -> dict[str, dict[str, Any]]:
    mapping: dict[str, dict[str, Any]] = {}
    for spec in paths:
        path = Path(spec)
        payload = _load_json(path, "NSXPC interface config")
        project = str(payload.get("project_name") or "")
        program = str(payload.get("program_name") or "")
        for item in payload.get("functions", []) if isinstance(payload.get("functions"), list) else []:
            if not isinstance(item, dict):
                continue
            function = str(item.get("function") or "")
            entry = str(item.get("entry") or "")
            record = dict(item)
            record["artifact"] = str(path)
            if project and program:
                keys = [f"{project}:{program}:{function}", f"{project}:{program}:{function.lstrip('_')}"]
                if entry:
                    keys.append(f"{project}:{program}:{entry}")
            else:
                keys = [function, function.lstrip("_")]
            for key in keys:
                if key and key not in mapping:
                    mapping[key] = record
    return mapping


def _config_evidence(
    project: str,
    program: str,
    interface: str,
    function: dict[str, Any],
    config_map: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    function_name = str(function.get("name") or "")
    entry = str(function.get("entry") or function.get("address") or "")
    candidates = [
        f"{project}:{program}:{function_name}",
        f"{project}:{program}:{function_name.lstrip('_')}",
        f"{project}:{program}:{entry}",
        function_name,
        function_name.lstrip("_"),
        f"{project}:{program}:{interface}",
        f"{project}:{program}:{interface.lstrip('_')}",
        interface,
        interface.lstrip("_"),
    ]
    for key in candidates:
        if key and key in config_map:
            return config_map[key]
    return {}


def _merge_allowed_calls(dossier_evidence: dict[str, Any], config_evidence: dict[str, Any]) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for source_name, evidence in (("function_dossier", dossier_evidence), ("nsxpc_interface_config", config_evidence)):
        for call in evidence.get("allowed_class_calls", []) if isinstance(evidence.get("allowed_class_calls"), list) else []:
            if not isinstance(call, dict):
                continue
            selector = str(call.get("selector") or "")
            line = str(call.get("line") or call.get("excerpt") or "")
            line_number = str(call.get("line_number") or "")
            key = (selector, line_number, line)
            if key in seen:
                continue
            seen.add(key)
            item = dict(call)
            item.setdefault("source", source_name)
            merged.append(item)
    return merged


def _clean_protocol_ref(value: str) -> str:
    return value.lstrip("_")


def _find_function(payload: dict[str, Any], interface: str) -> dict[str, Any]:
    names = {interface, interface.lstrip("_")}
    for item in payload.get("functions", []) if isinstance(payload, dict) else []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "")
        if name in names:
            return {
                "name": name,
                "entry": item.get("entry") or item.get("address"),
                "signature": item.get("signature"),
                "is_external": item.get("is_external"),
            }
    return {}


def _find_symbol(payload: dict[str, Any], interface: str) -> dict[str, Any]:
    names = {interface, interface.lstrip("_")}
    for item in payload.get("symbols", []) if isinstance(payload, dict) else []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or item.get("label") or "")
        if name in names:
            return {"name": name, "address": item.get("address")}
    return {}


def _find_authstub(payload: dict[str, Any], interface: str) -> dict[str, Any]:
    names = {interface, interface.lstrip("_")}
    for item in _records(payload.get("stubs") if isinstance(payload, dict) else []):
        if not isinstance(item, dict):
            continue
        name = str(item.get("resolved_name") or item.get("name") or "")
        if name in names:
            return {
                "name": name,
                "resolved_name": item.get("resolved_name"),
                "address": item.get("address"),
                "source": item.get("source"),
            }
    return {}


def _records(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return list(value.values())
    return []


def _parse_function_dossiers(specs: list[str]) -> dict[str, Path]:
    mapping: dict[str, Path] = {}
    for spec in specs:
        if "=" not in spec:
            raise RuntimeError(f"function dossier must be Interface=path or project:program=Interface=path: {spec}")
        parts = spec.split("=", 2)
        if len(parts) == 3:
            target, interface, path = parts
            if ":" not in target:
                raise RuntimeError(f"targeted function dossier must be project:program=Interface=path: {spec}")
            mapping[f"{target}:{interface}"] = Path(path)
        else:
            interface, path = parts
            mapping[interface] = Path(path)
    return mapping


def _context_from_inventory(item: dict[str, Any]) -> dict[str, Any]:
    graph = item.get("graph_context") if isinstance(item.get("graph_context"), dict) else {}
    return {
        "source": "xpc-method-inventory",
        "method_count": item.get("method_count", 0),
        "services": graph.get("services", []),
        "score": graph.get("score"),
        "reasons": graph.get("reasons", []),
    }


def _context_from_dossier(candidate: dict[str, Any]) -> dict[str, Any]:
    return {
        "source": "xpc-interface-dossier",
        "score": candidate.get("score"),
        "services": candidate.get("services", []),
        "reasons": candidate.get("reasons", []),
    }


def _parse_target(target: str) -> tuple[str, str]:
    if ":" not in target:
        raise RuntimeError(f"target must be formatted as project:program: {target}")
    project, program = target.split(":", 1)
    if not project or not program:
        raise RuntimeError(f"target must include both project and program: {target}")
    return project, program


def _load_json(path: Path, label: str) -> dict[str, Any]:
    if not path.exists():
        raise RuntimeError(f"{label} not found: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{label} is not valid JSON: {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"{label} must be a JSON object: {path}")
    return payload


def _load_optional_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# XPC Interface Factory Catalog",
        "",
        f"- Schema: `{report['schema']}`",
        f"- Factories: {report['summary']['factory_count']}",
        f"- Local factories: {report['summary']['local_factory_count']}",
        f"- Unresolved authstubs: {report['summary']['unresolved_authstub_count']}",
        f"- Protocol references: {report['summary']['protocol_reference_count']}",
        f"- Allowed-class calls: {report['summary']['allowed_class_call_count']}",
        "",
    ]
    for item in report["factories"]:
        lines.append(f"## {item['interface']}")
        lines.append("")
        lines.append(f"- Target: `{item['target']}`")
        lines.append(f"- Status: `{item['factory_status']}`")
        if item.get("function"):
            lines.append(f"- Function: `{item['function'].get('name')}` at `{item['function'].get('entry')}`")
        if item.get("authstub"):
            lines.append(f"- Authstub: `{item['authstub'].get('name')}` source=`{item['authstub'].get('source')}`")
        if item.get("protocol_references"):
            lines.append("- Protocol references: " + ", ".join(f"`{name}`" for name in item["protocol_references"]))
        if item.get("allowed_class_selectors"):
            lines.append("- Allowed-class selectors: " + ", ".join(f"`{name}`" for name in item["allowed_class_selectors"]))
        if item.get("context", {}).get("services"):
            lines.append("- Services: " + ", ".join(f"`{service}`" for service in item["context"]["services"][:4]))
        if item.get("function_dossier"):
            lines.append(f"- Dossier: `{item['function_dossier']}`")
        if item.get("interface_config"):
            lines.append(f"- Interface config: `{item['interface_config']}`")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
