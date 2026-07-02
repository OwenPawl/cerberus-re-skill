"""Recover candidate method inventories for ranked XPC interfaces."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cerberus_re_skill.core.config import cfg
from cerberus_re_skill.core.utils import utc_now
from cerberus_re_skill.modules.macho_objc_protocol_methods import (
    MachOObjCDecodeError,
    decode_protocol_methods_from_macho,
)


XPC_METHOD_INVENTORY_SCHEMA = "ghidra-re.xpc-method-inventory.v1"


def build_xpc_method_inventory(
    targets: list[str],
    *,
    xpc_dossier_path: str | Path | None = None,
    interface_config_paths: list[str] | None = None,
    allowed_class_paths: list[str] | None = None,
    interfaces: list[str] | None = None,
    output: str | Path | None = None,
    markdown_output: str | Path | None = None,
    harness_output_dir: str | Path | None = None,
    macho_paths: list[str] | None = None,
    macho_arch: str | None = None,
    limit: int = 12,
) -> dict[str, Any]:
    """Build method-candidate inventories for XPC interfaces."""
    parsed_targets = [_parse_target(target) for target in targets]
    if not parsed_targets:
        raise RuntimeError("at least one target is required")
    macho_path_map = _parse_macho_paths(parsed_targets, macho_paths or [])
    dossier = _load_json(Path(xpc_dossier_path), "xpc interface dossier") if xpc_dossier_path else {}
    config_map = _parse_interface_configs(interface_config_paths or [])
    allowed_class_map = _parse_allowed_class_reports(allowed_class_paths or [])
    selected = _selected_interfaces(parsed_targets, dossier, interfaces or [], limit)
    inventories = [
        _inventory_for(
            project,
            program,
            interface,
            dossier,
            config_map,
            allowed_class_map,
            macho_path=macho_path_map.get(f"{project}:{program}"),
            macho_arch=macho_arch,
        )
        for project, program, interface in selected
    ]
    harnesses = []
    if harness_output_dir:
        harnesses = _write_harness_stubs(inventories, Path(harness_output_dir))

    report = {
        "schema": XPC_METHOD_INVENTORY_SCHEMA,
        "ok": True,
        "created_at": utc_now(),
        "inputs": {
            "targets": [{"project": project, "program": program} for project, program in parsed_targets],
            "xpc_dossier": str(xpc_dossier_path) if xpc_dossier_path else None,
            "interface_configs": interface_config_paths or [],
            "allowed_classes": allowed_class_paths or [],
            "interfaces": interfaces or [],
            "macho_paths": macho_path_map,
            "macho_arch": macho_arch,
        },
        "summary": {
            "interface_count": len(inventories),
            "interfaces_with_method_candidates": sum(1 for item in inventories if item["method_count"] > 0),
            "protocol_symbol_hit_count": sum(len(item["protocol_symbol_hits"]) for item in inventories),
            "macho_protocol_method_count": sum(item.get("macho_protocol_method_count", 0) for item in inventories),
            "method_candidate_count": sum(item["method_count"] for item in inventories),
            "typed_method_candidate_count": sum(item["typed_method_candidate_count"] for item in inventories),
            "reply_block_candidate_count": sum(item["reply_block_candidate_count"] for item in inventories),
            "configured_interface_count": sum(1 for item in inventories if item["configuration_context"].get("pattern_function_count")),
            "allowed_class_backed_method_count": sum(item["allowed_class_backed_method_count"] for item in inventories),
            "safe_read_method_count": sum(item["safety_counts"]["safe_read"] for item in inventories),
            "state_changing_method_count": sum(item["safety_counts"]["state_changing"] for item in inventories),
            "ui_method_count": sum(item["safety_counts"]["ui"] for item in inventories),
            "unknown_safety_method_count": sum(item["safety_counts"]["unknown"] for item in inventories),
            "harness_stub_count": len(harnesses),
        },
        "interfaces": inventories,
        "harness_stubs": harnesses,
    }
    out_path = Path(output) if output else cfg.exports_dir / "xpc_method_inventory.json"
    md_path = Path(markdown_output) if markdown_output else cfg.exports_dir / "xpc_method_inventory.md"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    md_path.write_text(_render_markdown(report), encoding="utf-8")
    return {
        "ok": True,
        "output": str(out_path),
        "markdown_output": str(md_path),
        **report["summary"],
    }


def _parse_target(target: str) -> tuple[str, str]:
    if ":" not in target:
        raise RuntimeError(f"target must be formatted as project:program: {target}")
    project, program = target.split(":", 1)
    if not project or not program:
        raise RuntimeError(f"target must include both project and program: {target}")
    return project, program


def _parse_macho_paths(targets: list[tuple[str, str]], specs: list[str]) -> dict[str, str]:
    if not specs:
        return {}
    target_keys = {f"{project}:{program}" for project, program in targets}
    mapping: dict[str, str] = {}
    for spec in specs:
        if "=" in spec:
            target, path = spec.split("=", 1)
            if target not in target_keys:
                raise RuntimeError(f"--macho target must match a requested project:program target: {target}")
            if not path:
                raise RuntimeError(f"--macho path is empty for target {target}")
            mapping[target] = path
            continue
        if len(target_keys) != 1:
            raise RuntimeError("bare --macho path requires exactly one target; use project:program=/path")
        mapping[next(iter(target_keys))] = spec
    return mapping


def _selected_interfaces(
    targets: list[tuple[str, str]],
    dossier: dict[str, Any],
    interfaces: list[str],
    limit: int,
) -> list[tuple[str, str, str]]:
    selected: list[tuple[str, str, str]] = []
    target_set = {f"{project}:{program}" for project, program in targets}
    for interface_spec in interfaces:
        if "=" in interface_spec:
            target, interface = interface_spec.split("=", 1)
            if ":" not in target:
                raise RuntimeError(f"interface target must be project:program=Interface: {interface_spec}")
            project, program = target.split(":", 1)
            selected.append((project, program, interface))
        else:
            for project, program in targets:
                selected.append((project, program, interface_spec))
    if dossier:
        for candidate in dossier.get("candidates", []):
            if not isinstance(candidate, dict):
                continue
            target = str(candidate.get("target") or "")
            interface = str(candidate.get("interface") or "")
            if not target or not interface or target not in target_set:
                continue
            project, program = target.split(":", 1)
            selected.append((project, program, interface))
            if len(selected) >= limit:
                break
    deduped: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for item in selected:
        if item in seen:
            continue
        seen.add(item)
        deduped.append(item)
    return deduped[: max(1, limit)]


def _inventory_for(
    project: str,
    program: str,
    interface: str,
    dossier: dict[str, Any],
    config_map: dict[str, list[dict[str, Any]]],
    allowed_class_map: dict[str, list[dict[str, Any]]],
    *,
    macho_path: str | None = None,
    macho_arch: str | None = None,
) -> dict[str, Any]:
    export_dir = cfg.export_dir(project, program)
    symbols = _load_optional_json(export_dir / "symbols.json")
    objc = _load_optional_json(export_dir / "objc_metadata.json")
    lldb = _load_optional_json(export_dir / "lldb_symbols.json")
    selectors = _selector_values(objc)
    symbol_hits = _protocol_symbol_hits(symbols, interface)
    warnings: list[str] = []
    protocol_methods: list[dict[str, Any]] = []
    if macho_path:
        try:
            protocol_methods = decode_protocol_methods_from_macho(
                macho_path,
                symbols,
                [interface],
                arch=macho_arch,
            ).get(interface, [])
        except MachOObjCDecodeError as exc:
            warnings.append(f"macho_protocol_decode_failed: {exc}")
    configuration_context = _configuration_context(project, program, interface, config_map)
    method_candidates = [
        _with_signature_hint(candidate, configuration_context, allowed_class_map.get(str(candidate.get("selector") or ""), []))
        for candidate in _method_candidates(interface, selectors, lldb, protocol_methods)
    ]
    graph_context = _dossier_context(dossier, project, program, interface)
    status = "selector_candidates" if method_candidates else "interface_symbol_only"
    if symbol_hits:
        status = "objc_protocol_symbols"
    if protocol_methods:
        status = "objc_protocol_methods"
    typed_count = sum(
        1
        for item in method_candidates
        if item.get("signature_hint", {}).get("argument_count") is not None or item.get("type_encoding")
    )
    reply_count = sum(1 for item in method_candidates if item.get("signature_hint", {}).get("reply_block_likely"))
    allowed_backed_count = sum(
        1 for item in method_candidates if item.get("configuration_backing", {}).get("has_allowed_class_evidence")
    )
    safety_counts = _safety_counts(method_candidates)
    return {
        "target": f"{project}:{program}",
        "project": project,
        "program": program,
        "interface": interface,
        "extraction_status": status,
        "method_count": len(method_candidates),
        "macho_protocol_method_count": len(protocol_methods),
        "typed_method_candidate_count": typed_count,
        "reply_block_candidate_count": reply_count,
        "allowed_class_backed_method_count": allowed_backed_count,
        "safety_counts": safety_counts,
        "method_candidates": method_candidates,
        "protocol_symbol_hits": symbol_hits[:20],
        "warnings": warnings,
        "graph_context": graph_context,
        "configuration_context": configuration_context,
    }


def _protocol_symbol_hits(symbols_payload: dict[str, Any], interface: str) -> list[dict[str, Any]]:
    symbols = symbols_payload.get("symbols", []) if isinstance(symbols_payload, dict) else []
    hits = []
    for symbol in symbols if isinstance(symbols, list) else []:
        if not isinstance(symbol, dict):
            continue
        name = str(symbol.get("name") or symbol.get("label") or "")
        if interface in name and "PROTOCOL" in name:
            hits.append({"name": name, "address": symbol.get("address")})
    return hits


def _selector_values(objc_payload: dict[str, Any]) -> list[str]:
    selectors = []
    for key in ("selector_strings", "selectors"):
        raw = objc_payload.get(key, []) if isinstance(objc_payload, dict) else []
        if not isinstance(raw, list):
            continue
        for item in raw:
            if isinstance(item, str):
                selectors.append(item)
            elif isinstance(item, dict):
                value = item.get("value") or item.get("name")
                if value:
                    selectors.append(str(value))
    return sorted(set(selectors), key=str.lower)


def _method_candidates(
    interface: str,
    selectors: list[str],
    lldb_payload: dict[str, Any],
    protocol_methods: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    candidates: dict[str, dict[str, Any]] = {}
    for method in protocol_methods:
        selector = str(method.get("selector") or "")
        if not selector:
            continue
        candidates[selector] = {
            "selector": selector,
            "score": 80,
            "source": "macho_protocol_method_list",
            "type_encoding": method.get("type_encoding"),
            "method_list_symbol": method.get("method_list_symbol"),
            "method_list_address": method.get("method_list_address"),
            "selector_ref_address": method.get("selector_ref_address"),
            "selector_string_address": method.get("selector_string_address"),
        }
    for selector in selectors:
        score = _selector_score(interface, selector)
        if score <= 0:
            continue
        existing = candidates.get(selector, {"selector": selector, "score": 0, "source": "selector"})
        existing["score"] = int(existing["score"]) + score
        source = str(existing.get("source") or "")
        existing["source"] = source if "selector" in source else f"{source}+selector".strip("+")
        candidates[selector] = existing
    for method in _objc_methods_for_interface(interface, lldb_payload):
        selector = method["selector"]
        existing = candidates.get(selector, {"selector": selector, "score": 0, "source": "lldb_symbols"})
        existing["score"] = int(existing["score"]) + 20
        source = str(existing.get("source") or "")
        existing["source"] = source if "lldb_symbols" in source else f"{source}+lldb_symbols".strip("+")
        existing["symbol"] = method["symbol"]
        existing["address"] = method.get("address")
        candidates[selector] = existing
    return sorted(candidates.values(), key=lambda item: (-int(item["score"]), item["selector"]))[:30]


def _class_name_from_interface(interface: str) -> str:
    name = interface.strip("_")
    for suffix in ("XPCInterface", "Interface", "Protocol"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
            break
    return name


def _objc_methods_for_interface(interface: str, lldb_payload: dict[str, Any]) -> list[dict[str, Any]]:
    class_name = _class_name_from_interface(interface)
    if not class_name:
        return []
    methods = lldb_payload.get("objc_methods", []) if isinstance(lldb_payload, dict) else []
    results = []
    prefix = f"-[{class_name} "
    for item in methods if isinstance(methods, list) else []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "")
        if not name.startswith(prefix):
            continue
        selector = name[len(prefix) :].rstrip("]")
        if selector in {".cxx_destruct"} or selector.startswith("set"):
            continue
        results.append({"selector": selector, "symbol": name, "address": item.get("address")})
    return results[:40]


def _selector_score(interface: str, selector: str) -> int:
    lowered = selector.lower()
    interface_lower = interface.lower()
    score = 0
    groups = {
        "automation": ["automation", "run", "trigger", "intent", "execute"],
        "outofprocesscontroller": ["controller", "run", "cancel", "pause", "resume", "variable", "environment"],
        "taskcontroller": ["task", "controller", "run", "cancel", "pause", "resume", "request"],
        "uipresenter": ["present", "dismiss", "dialog", "alert", "userinterface", "viewcontroller"],
        "actionmanager": ["action", "record", "access", "phrase", "suggestion", "serialized", "migration"],
        "executionstatus": ["status", "progress", "running"],
    }
    for needle, words in groups.items():
        if needle in interface_lower:
            for word in words:
                if word in lowered:
                    score += 10
    if selector.startswith("T@"):
        score -= 8
    if selector.startswith("_"):
        score -= 4
    return score


def _dossier_context(dossier: dict[str, Any], project: str, program: str, interface: str) -> dict[str, Any]:
    target = f"{project}:{program}"
    for candidate in dossier.get("candidates", []) if isinstance(dossier, dict) else []:
        if not isinstance(candidate, dict):
            continue
        if candidate.get("target") == target and candidate.get("interface") == interface:
            return {
                "score": candidate.get("score"),
                "services": candidate.get("services", []),
                "owner_edges": candidate.get("owner_edges", []),
                "reasons": candidate.get("reasons", []),
            }
    return {}


def _parse_interface_configs(paths: list[str]) -> dict[str, list[dict[str, Any]]]:
    mapping: dict[str, list[dict[str, Any]]] = {}
    for spec in paths:
        path = Path(spec)
        payload = _load_json(path, "NSXPC interface config")
        project = str(payload.get("project_name") or "")
        program = str(payload.get("program_name") or "")
        for item in payload.get("functions", []) if isinstance(payload.get("functions"), list) else []:
            if not isinstance(item, dict):
                continue
            record = dict(item)
            record["artifact"] = str(path)
            function = str(item.get("function") or "")
            protocol_refs = [str(value) for value in item.get("protocol_references", []) if value]
            keys = []
            if project and program:
                for value in [function, function.lstrip("_"), *protocol_refs]:
                    if value:
                        keys.append(f"{project}:{program}:{value}")
                        keys.append(f"{project}:{program}:{value.lstrip('_')}")
            else:
                keys.extend([function, function.lstrip("_"), *protocol_refs])
            for key in keys:
                if key:
                    mapping.setdefault(key, []).append(record)
    return mapping


def _parse_allowed_class_reports(paths: list[str]) -> dict[str, list[dict[str, Any]]]:
    mapping: dict[str, list[dict[str, Any]]] = {}
    for path_text in paths:
        path = Path(path_text)
        payload = _load_json(path, "allowed-class report")
        records = payload.get("allowed_class_entries", []) if isinstance(payload.get("allowed_class_entries"), list) else []
        for record in records:
            if not isinstance(record, dict):
                continue
            selector = str(record.get("selector") or "")
            if not selector:
                continue
            classes = [str(value) for value in record.get("classes", []) if value]
            normalized = {
                "selector": selector,
                "argument_index": record.get("argument_index"),
                "of_reply": bool(record.get("of_reply")),
                "classes": sorted(set(classes), key=str.lower),
                "class_count": len(set(classes)),
                "source": payload.get("schema") or "allowed-class-report",
                "artifact": str(path),
            }
            mapping.setdefault(selector, []).append(normalized)
    return mapping


def _configuration_context(
    project: str,
    program: str,
    interface: str,
    config_map: dict[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    names = [interface, interface.lstrip("_")]
    records: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for name in names:
        for record in config_map.get(f"{project}:{program}:{name}", []):
            key = (str(record.get("artifact") or ""), str(record.get("function") or ""))
            if key in seen:
                continue
            seen.add(key)
            records.append(record)
    allowed_calls = []
    protocols = set()
    functions = []
    for record in records:
        functions.append(
            {
                "function": record.get("function"),
                "entry": record.get("entry"),
                "artifact": record.get("artifact"),
                "selection_reasons": record.get("selection_reasons", []),
                "allowed_class_call_count": record.get("allowed_class_call_count", 0),
                "interface_with_protocol_call_count": record.get("interface_with_protocol_call_count", 0),
            }
        )
        protocols.update(str(value) for value in record.get("protocol_references", []) if value)
        for call in record.get("allowed_class_calls", []) if isinstance(record.get("allowed_class_calls"), list) else []:
            if isinstance(call, dict):
                allowed_calls.append(call)
    return {
        "pattern_function_count": len(functions),
        "functions": functions,
        "protocol_references": sorted(protocols),
        "allowed_class_call_count": len(allowed_calls),
        "allowed_class_calls": allowed_calls,
        "interface_with_protocol_call_count": sum(int(record.get("interface_with_protocol_call_count") or 0) for record in records),
    }


def _with_signature_hint(
    candidate: dict[str, Any],
    configuration_context: dict[str, Any],
    allowed_class_evidence: list[dict[str, Any]],
) -> dict[str, Any]:
    item = dict(candidate)
    hint = _selector_signature_hint(str(item.get("selector") or ""))
    if item.get("type_encoding"):
        hint["objc_type_encoding"] = item.get("type_encoding")
        hint["source"] = f"{hint.get('source')}+objc_type_encoding"
    item["signature_hint"] = hint
    item["input_shape_hints"] = hint.get("argument_hints", [])
    safety = _safety_classification(str(item.get("selector") or ""), hint)
    item["safety_classification"] = safety
    argument_classes = _allowed_class_roles(allowed_class_evidence, of_reply=False)
    reply_classes = _allowed_class_roles(allowed_class_evidence, of_reply=True)
    item["configuration_backing"] = {
        "pattern_function_count": configuration_context.get("pattern_function_count", 0),
        "allowed_class_call_count": configuration_context.get("allowed_class_call_count", 0),
        "allowed_class_selectors": sorted(
            {str(call.get("selector") or "") for call in configuration_context.get("allowed_class_calls", []) if isinstance(call, dict) and call.get("selector")}
        ),
        "allowed_class_evidence_count": len(allowed_class_evidence),
        "has_allowed_class_evidence": bool(allowed_class_evidence)
        or bool(configuration_context.get("allowed_class_call_count")),
        "argument_allowed_classes": argument_classes,
        "reply_allowed_classes": reply_classes,
    }
    item["remote_invocation_default"] = safety["probe_readiness"]
    return item


def _allowed_class_roles(records: list[dict[str, Any]], *, of_reply: bool) -> list[dict[str, Any]]:
    roles = []
    for record in records:
        if bool(record.get("of_reply")) != of_reply:
            continue
        classes = [str(value) for value in record.get("classes", []) if value]
        if not classes:
            continue
        roles.append(
            {
                "argument_index": record.get("argument_index"),
                "classes": sorted(set(classes), key=str.lower),
                "source": record.get("source"),
                "artifact": record.get("artifact"),
            }
        )
    return roles


def _safety_counts(method_candidates: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"safe_read": 0, "state_changing": 0, "ui": 0, "unknown": 0}
    for item in method_candidates:
        classification = item.get("safety_classification") if isinstance(item.get("safety_classification"), dict) else {}
        category = str(classification.get("category") or "unknown")
        if category not in counts:
            category = "unknown"
        counts[category] += 1
    return counts


def _safety_classification(selector: str, signature_hint: dict[str, Any]) -> dict[str, Any]:
    lowered = selector.lower()
    reasons: list[str] = []
    ui_words = ["present", "dismiss", "dialog", "alert", "userinterface", "viewcontroller", "activatealert", "deactivatealert"]
    state_words = [
        "add",
        "update",
        "delete",
        "remove",
        "set",
        "cancel",
        "run",
        "start",
        "stop",
        "pause",
        "resume",
        "save",
        "create",
        "log",
        "open",
        "register",
        "enable",
        "disable",
        "invalidate",
        "activate",
    ]
    read_words = ["get", "fetch", "list", "enumerate", "status", "is", "can", "has", "current", "request", "retrieve"]
    category = "unknown"
    confidence = "low"
    if any(word in lowered for word in ui_words):
        category = "ui"
        confidence = "medium"
        reasons.append("selector_mentions_ui")
    elif any(_word_boundary(lowered, word) for word in state_words):
        category = "state_changing"
        confidence = "medium"
        reasons.append("selector_mentions_state_change")
    elif any(lowered.startswith(word) or _word_boundary(lowered, word) for word in read_words):
        category = "safe_read"
        confidence = "low"
        reasons.append("selector_mentions_read_status")
    if signature_hint.get("reply_block_likely"):
        reasons.append("has_reply_or_completion_block")
    probe_readiness = "blocked_pending_input_shape_and_safety"
    if category == "safe_read":
        probe_readiness = "blocked_pending_entitlement_and_input_shape"
    if category in {"state_changing", "ui"}:
        probe_readiness = "blocked_state_or_ui_effects"
    return {
        "category": category,
        "confidence": confidence,
        "reasons": reasons or ["no_clear_selector_safety_signal"],
        "probe_readiness": probe_readiness,
    }


def _word_boundary(value: str, word: str) -> bool:
    return (
        value.startswith(word)
        or f":{word}" in value
        or f"_{word}" in value
        or f"{word}:" in value
        or f"{word}with" in value
    )


def _selector_signature_hint(selector: str) -> dict[str, Any]:
    property_metadata = selector.startswith("T") and "," in selector
    labels = [label for label in selector.split(":")[:-1] if label] if not property_metadata else []
    argument_hints = [_argument_hint(label, index + 1) for index, label in enumerate(labels)]
    return {
        "source": "selector_heuristic",
        "confidence": "low" if property_metadata else "medium",
        "selector": selector,
        "argument_count": len(labels),
        "argument_labels": labels,
        "reply_block_likely": any(hint["role"] in {"completion_block", "reply_block"} for hint in argument_hints),
        "property_metadata": property_metadata,
        "argument_hints": argument_hints,
    }


def _argument_hint(label: str, position: int) -> dict[str, Any]:
    lowered = label.lower()
    role = "unknown"
    types: list[str] = []
    if "accessspecifier" in lowered or "accesstoken" in lowered or "authorization" in lowered:
        role = "access_context"
        types = ["NSObject", "NSString"]
    elif "completion" in lowered or "completionhandler" in lowered:
        role = "completion_block"
        types = ["block"]
    elif "reply" in lowered:
        role = "reply_block"
        types = ["block"]
    elif "error" in lowered:
        role = "error"
        types = ["NSError"]
    elif "url" in lowered:
        role = "url"
        types = ["NSURL", "NSString"]
    elif "identifier" in lowered or lowered.endswith("id") or "uuid" in lowered:
        role = "identifier"
        types = ["NSString", "NSUUID"]
    elif "workflow" in lowered:
        role = "workflow"
        types = ["NSObject", "NSString"]
    elif "input" in lowered:
        role = "input"
        types = ["NSObject"]
    elif "metadata" in lowered or "dictionary" in lowered:
        role = "metadata"
        types = ["NSDictionary"]
    elif "phrase" in lowered:
        role = "phrase"
        types = ["NSString"]
    elif "limit" in lowered or "numberof" in lowered or "count" in lowered:
        role = "count"
        types = ["NSUInteger", "NSInteger"]
    elif "date" in lowered:
        role = "date"
        types = ["NSDate"]
    elif lowered.startswith("is") or lowered.startswith("should") or lowered.startswith("can") or "enabled" in lowered:
        role = "boolean"
        types = ["BOOL"]
    elif "endpoint" in lowered or "listener" in lowered or "connection" in lowered:
        role = "xpc_endpoint"
        types = ["NSXPCListenerEndpoint", "NSXPCConnection"]
    elif "delegate" in lowered:
        role = "delegate"
        types = ["id"]
    return {"position": position, "label": label, "role": role, "type_hints": types}


def _write_harness_stubs(inventories: list[dict[str, Any]], out_dir: Path) -> list[dict[str, str]]:
    out_dir.mkdir(parents=True, exist_ok=True)
    results = []
    for item in inventories:
        path = out_dir / f"{_safe_name(item['target'])}_{_safe_name(item['interface'])}_MethodInventoryHarness.m"
        service = ""
        services = item.get("graph_context", {}).get("services", [])
        if services:
            service = next((str(candidate) for candidate in services if not str(candidate).startswith("_")), str(services[0]))
        source = _render_harness_stub(item, service)
        path.write_text(source, encoding="utf-8")
        results.append({"interface": item["interface"], "path": str(path), "service": service})
    return results


def _render_harness_stub(item: dict[str, Any], service: str) -> str:
    methods = "\n".join(_method_comment(m) for m in item.get("method_candidates", [])[:20]) or "// - No method candidates recovered yet."
    service_line = service or "<set-mach-service-before-runtime-use>"
    return f"""// Generated by ghidra-re XPC method inventory.
// Target: {item['target']}
// Interface: {item['interface']}
// Extraction status: {item['extraction_status']}
// Service: {service_line}
//
// Candidate selectors:
{methods}
//
// Safety default: this harness intentionally performs no remote method calls.

#import <Foundation/Foundation.h>

int main(int argc, const char * argv[]) {{
    @autoreleasepool {{
        NSLog(@"No-call XPC method inventory harness for {item['interface']}");
    }}
    return 0;
}}
"""


def _method_comment(method: dict[str, Any]) -> str:
    signature = method.get("signature_hint", {}) if isinstance(method.get("signature_hint"), dict) else {}
    safety = method.get("safety_classification", {}) if isinstance(method.get("safety_classification"), dict) else {}
    hints = method.get("input_shape_hints", []) if isinstance(method.get("input_shape_hints"), list) else []
    roles = []
    for hint in hints[:8]:
        if not isinstance(hint, dict):
            continue
        types = "/".join(str(value) for value in hint.get("type_hints", []) if value) or "unknown"
        roles.append(f"{hint.get('label')}={hint.get('role')}[{types}]")
    role_text = ", ".join(roles) if roles else "none"
    return "\n".join(
        [
            f"// - {method.get('selector')}",
            f"//   args={signature.get('argument_count', '?')} roles={role_text}",
            f"//   safety={safety.get('category', 'unknown')} readiness={method.get('remote_invocation_default', 'blocked')}",
            "//   no-call: do not invoke this selector until category, input shape, and entitlement behavior are cleared.",
        ]
    )


def _safe_name(value: str) -> str:
    return "".join(ch if ch.isalnum() else "_" for ch in value).strip("_") or "xpc_interface"


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
        "# XPC Method Inventory",
        "",
        f"- Schema: `{report['schema']}`",
        f"- Interfaces: {report['summary']['interface_count']}",
        f"- Interfaces with method candidates: {report['summary']['interfaces_with_method_candidates']}",
        f"- Mach-O protocol methods: {report['summary'].get('macho_protocol_method_count', 0)}",
        f"- Method candidates: {report['summary']['method_candidate_count']}",
        f"- Typed method candidates: {report['summary'].get('typed_method_candidate_count', 0)}",
        f"- Reply-block candidates: {report['summary'].get('reply_block_candidate_count', 0)}",
        f"- Configured interfaces: {report['summary'].get('configured_interface_count', 0)}",
        f"- Allowed-class-backed methods: {report['summary'].get('allowed_class_backed_method_count', 0)}",
        f"- Safe-read methods: {report['summary'].get('safe_read_method_count', 0)}",
        f"- State-changing methods: {report['summary'].get('state_changing_method_count', 0)}",
        f"- UI methods: {report['summary'].get('ui_method_count', 0)}",
        f"- Unknown safety methods: {report['summary'].get('unknown_safety_method_count', 0)}",
        f"- Harness stubs: {report['summary']['harness_stub_count']}",
        "",
    ]
    for item in report["interfaces"]:
        lines.append(f"## {item['interface']}")
        lines.append("")
        lines.append(f"- Target: `{item['target']}`")
        lines.append(f"- Status: `{item['extraction_status']}`")
        lines.append(f"- Method candidates: {item['method_count']}")
        if item.get("macho_protocol_method_count"):
            lines.append(f"- Mach-O protocol methods: {item.get('macho_protocol_method_count')}")
        lines.append(f"- Typed method candidates: {item.get('typed_method_candidate_count', 0)}")
        counts = item.get("safety_counts", {}) if isinstance(item.get("safety_counts"), dict) else {}
        lines.append(
            "- Safety buckets: "
            f"safe-read={counts.get('safe_read', 0)}, "
            f"state-changing={counts.get('state_changing', 0)}, "
            f"ui={counts.get('ui', 0)}, "
            f"unknown={counts.get('unknown', 0)}"
        )
        if item.get("configuration_context", {}).get("functions"):
            config_functions = [
                str(fn.get("function"))
                for fn in item["configuration_context"]["functions"]
                if isinstance(fn, dict) and fn.get("function")
            ]
            lines.append("- Config functions: " + ", ".join(f"`{fn}`" for fn in config_functions[:4]))
        if item.get("graph_context", {}).get("services"):
            lines.append("- Services: " + ", ".join(f"`{s}`" for s in item["graph_context"]["services"][:4]))
        for warning in item.get("warnings", []):
            lines.append(f"- Warning: `{warning}`")
        for method in item.get("method_candidates", [])[:12]:
            signature = method.get("signature_hint", {}) if isinstance(method.get("signature_hint"), dict) else {}
            safety = method.get("safety_classification", {}) if isinstance(method.get("safety_classification"), dict) else {}
            type_text = ""
            if method.get("type_encoding"):
                type_text = f", type=`{method.get('type_encoding')}`"
            lines.append(
                f"- `{method['selector']}` "
                f"(score={method['score']}, args={signature.get('argument_count')}, "
                f"reply={signature.get('reply_block_likely')}, safety={safety.get('category', 'unknown')}, "
                f"default=`{method.get('remote_invocation_default', 'blocked')}`{type_text})"
            )
            backing = method.get("configuration_backing", {}) if isinstance(method.get("configuration_backing"), dict) else {}
            if backing.get("allowed_class_evidence_count"):
                lines.append(
                    f"  Allowed-class evidence: {backing.get('allowed_class_evidence_count')} entries; "
                    f"reply slots={len(backing.get('reply_allowed_classes', []))}"
                )
        if not item.get("method_candidates"):
            lines.append("- No method candidates recovered yet.")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
