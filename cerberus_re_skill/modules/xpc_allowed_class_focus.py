"""Build focused NSXPC allowed-class reports from no-call probes."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cerberus_re_skill.core.config import cfg
from cerberus_re_skill.core.utils import utc_now


XPC_ALLOWED_CLASS_FOCUS_SCHEMA = "ghidra-re.xpc-allowed-class-focus.v1"


def build_xpc_allowed_class_focus(
    *,
    allowed_class_probe_path: str | Path,
    selectors: list[str] | None = None,
    method_inventory_path: str | Path | None = None,
    readiness_path: str | Path | None = None,
    completion_shapes_path: str | Path | None = None,
    static_config_path: str | Path | None = None,
    lldb_validation_path: str | Path | None = None,
    output: str | Path | None = None,
    markdown_output: str | Path | None = None,
) -> dict[str, Any]:
    """Summarize allowed-class behavior for a small selector set."""
    probe_path = Path(allowed_class_probe_path)
    probe = _load_json(probe_path, "allowed-class probe")
    method_inventory = _load_optional_json(method_inventory_path)
    readiness = _load_optional_json(readiness_path)
    completion_shapes = _load_optional_json(completion_shapes_path)
    static_config = _load_optional_json(static_config_path)
    lldb_validation = _load_optional_json(lldb_validation_path)

    selected = _dedupe(selectors or _selectors_from_probe(probe))
    method_index = _method_index(method_inventory)
    readiness_index = _readiness_index(readiness)
    completion_index = _completion_index(completion_shapes)
    protocol_index = _protocol_index(probe)
    probe_entries = probe.get("allowed_class_entries", []) if isinstance(probe.get("allowed_class_entries"), list) else []

    selector_reports = []
    for selector in selected:
        records = [entry for entry in probe_entries if isinstance(entry, dict) and entry.get("selector") == selector]
        ok_records = [entry for entry in records if entry.get("ok")]
        method = method_index.get(selector, {})
        ready = readiness_index.get(selector, {})
        completion = ready.get("completion_contract") if isinstance(ready.get("completion_contract"), dict) else {}
        if not completion:
            completion = completion_index.get(selector, {})
        protocol_description = protocol_index.get(selector, {"selector": selector, "protocol_contains_selector": None})
        slots = _allowed_class_slots(selector, ok_records, method, completion)
        report = {
            "selector": selector,
            "classification": _classification(protocol_description, ok_records, slots),
            "protocol": protocol_description,
            "allowed_class_slots": slots,
            "ok_allowed_class_entry_count": len(ok_records),
            "non_empty_allowed_class_entry_count": sum(1 for item in ok_records if _int(item.get("class_count")) > 0),
            "out_of_range_or_exception_count": sum(1 for item in records if not item.get("ok")),
            "readiness_bucket": ready.get("readiness_bucket", ""),
            "remote_invocation_default": ready.get("remote_invocation_default", "blocked_no_remote_call"),
            "method_inventory_evidence": _method_evidence(method),
            "completion_contract": completion,
            "next_step": _next_step(selector, protocol_description, ready),
        }
        selector_reports.append(report)

    runtime_boundary = _runtime_boundary(probe, lldb_validation)
    static_summary = _static_summary(static_config)
    summary = {
        "selector_count": len(selector_reports),
        "protocol_backed_selector_count": sum(1 for item in selector_reports if item.get("protocol", {}).get("protocol_contains_selector") is True),
        "non_protocol_selector_count": sum(1 for item in selector_reports if item.get("protocol", {}).get("protocol_contains_selector") is False),
        "allowed_class_recovered_selector_count": sum(1 for item in selector_reports if item.get("classification") == "allowed_classes_recovered"),
        "next_bounded_probe_candidate_count": sum(
            1 for item in selector_reports if item.get("readiness_bucket") == "next_bounded_probe_candidate_policy_gated"
        ),
        "needs_input_value_count": sum(1 for item in selector_reports if item.get("readiness_bucket") == "needs_input_value"),
        "remote_methods_invoked": runtime_boundary["remote_methods_invoked"],
        "lldb_trace_status": runtime_boundary["trace_status"],
        "lldb_hit_count": runtime_boundary["hit_count"],
        "direct_remote_invocation_default": "blocked_no_remote_methods_invoked",
    }
    report = {
        "schema": XPC_ALLOWED_CLASS_FOCUS_SCHEMA,
        "ok": True,
        "created_at": utc_now(),
        "inputs": {
            "allowed_class_probe": str(probe_path),
            "method_inventory": str(method_inventory_path or ""),
            "readiness": str(readiness_path or ""),
            "completion_shapes": str(completion_shapes_path or ""),
            "static_config": str(static_config_path or ""),
            "lldb_validation": str(lldb_validation_path or ""),
        },
        "summary": {**summary, **static_summary},
        "runtime_boundary": runtime_boundary,
        "selectors": selector_reports,
        "safety_policy": {
            "remote_methods_invoked": runtime_boundary["remote_methods_invoked"],
            "default": "do_not_invoke_remote_methods_until allowed classes, completion shape, entitlement, input, and runtime gates are explicit",
            "next_allowed_step": "use the recovered allowed-class boundary to plan a no-side-effect entitlement/input probe; keep remote calls blocked by default",
        },
    }

    out_path = Path(output) if output else cfg.exports_dir / "xpc_allowed_class_focus.json"
    md_path = Path(markdown_output) if markdown_output else cfg.exports_dir / "xpc_allowed_class_focus.md"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    md_path.write_text(_render_markdown(report), encoding="utf-8")
    return {
        "ok": True,
        "output": str(out_path),
        "markdown_output": str(md_path),
        **summary,
        **static_summary,
    }


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


def _load_optional_json(path: str | Path | None) -> dict[str, Any]:
    if not path:
        return {}
    return _load_json(Path(path), "optional input")


def _selectors_from_probe(probe: dict[str, Any]) -> list[str]:
    selectors: list[str] = []
    for entry in probe.get("selector_descriptions", []) if isinstance(probe.get("selector_descriptions"), list) else []:
        if isinstance(entry, dict) and entry.get("selector"):
            selectors.append(str(entry["selector"]))
    for entry in probe.get("allowed_class_entries", []) if isinstance(probe.get("allowed_class_entries"), list) else []:
        if isinstance(entry, dict) and entry.get("selector"):
            selectors.append(str(entry["selector"]))
    return _dedupe(selectors)


def _dedupe(values: list[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value or "").strip()
        if text and text not in seen:
            seen.add(text)
            result.append(text)
    return result


def _protocol_index(probe: dict[str, Any]) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for entry in probe.get("selector_descriptions", []) if isinstance(probe.get("selector_descriptions"), list) else []:
        if isinstance(entry, dict) and entry.get("selector"):
            index[str(entry["selector"])] = dict(entry)
    for entry in probe.get("protocol_selectors", []) if isinstance(probe.get("protocol_selectors"), list) else []:
        if isinstance(entry, dict) and entry.get("selector"):
            item = dict(entry)
            item["protocol_contains_selector"] = True
            index.setdefault(str(entry["selector"]), item)
    return index


def _method_index(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for interface in payload.get("interfaces", []) if isinstance(payload.get("interfaces"), list) else []:
        if not isinstance(interface, dict):
            continue
        for method in interface.get("method_candidates", []) if isinstance(interface.get("method_candidates"), list) else []:
            if isinstance(method, dict) and method.get("selector"):
                index[str(method["selector"])] = method
    return index


def _readiness_index(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for item in payload.get("ranked_methods", []) if isinstance(payload.get("ranked_methods"), list) else []:
        if isinstance(item, dict) and item.get("selector"):
            index[str(item["selector"])] = item
    return index


def _completion_index(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            selector = value.get("selector")
            if selector and ("reply_arguments" in value or "completion" in value):
                index.setdefault(str(selector), value)
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(payload)
    return index


def _allowed_class_slots(
    selector: str,
    records: list[dict[str, Any]],
    method: dict[str, Any],
    completion: dict[str, Any],
) -> list[dict[str, Any]]:
    roles = _argument_roles(method)
    reply_roles = _reply_roles(completion)
    slots: list[dict[str, Any]] = []
    for record in sorted(records, key=lambda item: (bool(item.get("of_reply")), _int(item.get("argument_index")))):
        index = _int(record.get("argument_index"))
        of_reply = bool(record.get("of_reply"))
        role = reply_roles.get(index, "unknown") if of_reply else roles.get(index, "unknown")
        classes = [str(item) for item in record.get("classes", []) if item]
        note = ""
        if not classes and role in {"completion_block", "reply_block"}:
            note = "block slot has no object class set"
        elif not classes and of_reply and role in {"count", "primitive"}:
            note = "primitive reply slot has no object class expected"
        slots.append(
            {
                "kind": "reply" if of_reply else "argument",
                "argument_index": index,
                "role": role,
                "classes": classes,
                "class_count": _int(record.get("class_count")),
                "note": note,
            }
        )
    return slots


def _argument_roles(method: dict[str, Any]) -> dict[int, str]:
    roles: dict[int, str] = {}
    candidates = method.get("input_shape_hints")
    if not isinstance(candidates, list):
        candidates = method.get("signature_hint", {}).get("argument_hints") if isinstance(method.get("signature_hint"), dict) else []
    for item in candidates if isinstance(candidates, list) else []:
        if not isinstance(item, dict):
            continue
        position = _int(item.get("position"))
        role = str(item.get("role") or "")
        if position > 0 and role:
            roles[position - 1] = role
    return roles


def _reply_roles(completion: dict[str, Any]) -> dict[int, str]:
    roles: dict[int, str] = {}
    for item in completion.get("reply_arguments", []) if isinstance(completion.get("reply_arguments"), list) else []:
        if not isinstance(item, dict):
            continue
        index = _int(item.get("index"))
        role = str(item.get("role") or item.get("kind") or "")
        if role:
            roles[index] = role
    return roles


def _classification(protocol: dict[str, Any], records: list[dict[str, Any]], slots: list[dict[str, Any]]) -> str:
    if protocol.get("protocol_contains_selector") is False and not records:
        return "not_protocol_backed_or_local"
    if any(slot.get("class_count", 0) > 0 for slot in slots):
        return "allowed_classes_recovered"
    if records:
        return "boundary_valid_empty_classes"
    return "unrecovered"


def _method_evidence(method: dict[str, Any]) -> dict[str, Any]:
    backing = method.get("configuration_backing") if isinstance(method.get("configuration_backing"), dict) else {}
    safety = method.get("safety_classification") if isinstance(method.get("safety_classification"), dict) else {}
    return {
        "has_allowed_class_evidence": backing.get("has_allowed_class_evidence"),
        "allowed_class_evidence_count": backing.get("allowed_class_evidence_count"),
        "safety_category": safety.get("category"),
        "probe_readiness": safety.get("probe_readiness"),
    }


def _runtime_boundary(probe: dict[str, Any], lldb: dict[str, Any]) -> dict[str, Any]:
    trace = lldb.get("trace") if isinstance(lldb.get("trace"), dict) else {}
    return {
        "remote_methods_invoked": bool(probe.get("remote_methods_invoked")),
        "connection_created": bool(probe.get("connection_created")),
        "interface_source": probe.get("interface_source", ""),
        "trace_status": lldb.get("trace_status", ""),
        "hit_count": _int(lldb.get("hit_count")),
        "breakpoint_count": _int(trace.get("breakpoint_count")),
        "resolved_breakpoint_locations": _int(trace.get("resolved_breakpoint_locations")),
        "breakpoints_hit": _int(trace.get("breakpoints_hit")),
        "symbols_requested": trace.get("symbols_requested", []),
        "lldb_validation": lldb.get("json_report", ""),
    }


def _static_summary(config: dict[str, Any]) -> dict[str, Any]:
    summary = config.get("summary") if isinstance(config.get("summary"), dict) else {}
    return {
        "config_function_count": summary.get("function_count", 0),
        "config_pattern_function_count": summary.get("pattern_function_count", 0),
        "config_allowed_class_call_count": summary.get("allowed_class_call_count", 0),
        "config_interface_with_protocol_call_count": summary.get("interface_with_protocol_call_count", 0),
    }


def _next_step(selector: str, protocol: dict[str, Any], readiness: dict[str, Any]) -> str:
    if protocol.get("protocol_contains_selector") is False:
        return "treat as local or non-protocol behavior until separate static evidence proves a remote endpoint"
    if readiness.get("readiness_bucket") == "next_bounded_probe_candidate_policy_gated":
        return "plan entitlement/input gate validation before any remote call"
    if readiness.get("readiness_bucket") == "needs_input_value":
        return "choose a bounded input value before any remote call"
    return "keep remote invocation blocked until remaining gates are explicit"


def _render_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary", {})
    lines = [
        "# XPC Allowed-Class Focus Report",
        "",
        f"- Schema: `{report.get('schema', XPC_ALLOWED_CLASS_FOCUS_SCHEMA)}`",
        f"- Selectors: {summary.get('selector_count', 0)}",
        f"- Protocol-backed selectors: {summary.get('protocol_backed_selector_count', 0)}",
        f"- Allowed-class recovered selectors: {summary.get('allowed_class_recovered_selector_count', 0)}",
        f"- LLDB status: `{summary.get('lldb_trace_status', '')}` ({summary.get('lldb_hit_count', 0)} hits)",
        f"- Remote methods invoked: `{summary.get('remote_methods_invoked', False)}`",
        f"- Direct remote invocation default: `{summary.get('direct_remote_invocation_default')}`",
        "",
    ]
    for item in report.get("selectors", []) if isinstance(report.get("selectors"), list) else []:
        lines.append(f"## `{item.get('selector')}`")
        lines.append("")
        lines.append(f"- Classification: `{item.get('classification')}`")
        protocol = item.get("protocol") if isinstance(item.get("protocol"), dict) else {}
        if protocol:
            lines.append(f"- Protocol contains selector: `{protocol.get('protocol_contains_selector')}`")
            if protocol.get("types"):
                lines.append(f"- Protocol types: `{protocol.get('types')}`")
        lines.append(f"- Readiness bucket: `{item.get('readiness_bucket', '')}`")
        for slot in item.get("allowed_class_slots", []) if isinstance(item.get("allowed_class_slots"), list) else []:
            classes = ", ".join(f"`{name}`" for name in slot.get("classes", [])) or "`<none>`"
            note = f" ({slot['note']})" if slot.get("note") else ""
            lines.append(
                f"- {slot.get('kind')}[{slot.get('argument_index')}] `{slot.get('role')}`: {classes}{note}"
            )
        if not item.get("allowed_class_slots"):
            lines.append("- Allowed-class slots: none.")
        completion = item.get("completion_contract") if isinstance(item.get("completion_contract"), dict) else {}
        if completion.get("completion"):
            lines.append(f"- Completion contract: `{completion.get('completion')}`")
        lines.append(f"- Next step: {item.get('next_step')}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _int(value: object) -> int:
    return value if isinstance(value, int) else 0
