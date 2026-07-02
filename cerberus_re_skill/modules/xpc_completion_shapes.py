"""Recover XPC completion/reply shapes from protocol, allowed-class, and static block evidence."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from cerberus_re_skill.core.config import cfg
from cerberus_re_skill.core.utils import utc_now


XPC_COMPLETION_SHAPES_SCHEMA = "ghidra-re.xpc-completion-shapes.v1"


def build_xpc_completion_shapes(
    targets: list[str],
    *,
    xpc_method_inventory_path: str | Path,
    completion_probe_paths: list[str | Path] | None = None,
    function_dossier_dirs: list[str | Path] | None = None,
    interfaces: list[str] | None = None,
    output: str | Path | None = None,
    markdown_output: str | Path | None = None,
    limit: int = 12,
) -> dict[str, Any]:
    """Build a deterministic completion/reply-shape report for XPC methods."""
    parsed_targets = [_parse_target(target) for target in targets]
    if not parsed_targets:
        raise RuntimeError("at least one target is required")
    target_set = {f"{project}:{program}" for project, program in parsed_targets}
    inventory = _load_json(Path(xpc_method_inventory_path), "xpc method inventory")
    completion_probes = [_load_completion_probe(Path(path)) for path in completion_probe_paths or []]
    dossier_evidence = _load_dossier_evidence([Path(path) for path in function_dossier_dirs or []])
    selected = _selected_inventory_items(inventory, target_set, interfaces or [], limit)

    interface_reports = []
    for item in selected:
        methods = []
        for method in item.get("method_candidates", []) if isinstance(item.get("method_candidates"), list) else []:
            if not isinstance(method, dict) or not _has_completion(method):
                continue
            selector = str(method.get("selector") or "")
            if not _looks_read_or_getter(selector, method):
                continue
            probe = _probe_for_selector(completion_probes, selector)
            static = _static_evidence_for_selector(dossier_evidence, selector)
            shape = _completion_shape(selector, method, probe, static)
            methods.append(
                {
                    "selector": selector,
                    "score": method.get("score"),
                    "protocol_types": probe.get("protocol_types") or method.get("signature_hint", {}).get("types"),
                    "argument_allowed_classes": _argument_allowed_classes(method, probe),
                    "reply_allowed_classes": _reply_allowed_classes(method, probe),
                    "static_block_evidence": static,
                    "runtime_completion_observation": probe.get("runtime_completion_observation", {}),
                    "completion_shape": shape,
                }
            )
        if methods:
            interface_reports.append(
                {
                    "target": item.get("target"),
                    "project": item.get("project"),
                    "program": item.get("program"),
                    "interface": item.get("interface"),
                    "method_count": item.get("method_count", 0),
                    "completion_method_count": len(methods),
                    "methods": methods,
                }
            )

    summary = {
        "interface_count": len(interface_reports),
        "completion_method_count": sum(item["completion_method_count"] for item in interface_reports),
        "reply_shape_count": sum(
            1
            for interface in interface_reports
            for method in interface["methods"]
            if method.get("completion_shape", {}).get("reply_arguments")
        ),
        "primitive_reply_count": sum(
            1
            for interface in interface_reports
            for method in interface["methods"]
            for arg in method.get("completion_shape", {}).get("reply_arguments", [])
            if arg.get("kind") == "primitive"
        ),
        "static_block_descriptor_count": sum(
            len(method.get("static_block_evidence", {}).get("block_descriptors", []))
            for interface in interface_reports
            for method in interface["methods"]
        ),
        "direct_completion_invocation_count": sum(
            len(method.get("static_block_evidence", {}).get("direct_completion_invocations", []))
            for interface in interface_reports
            for method in interface["methods"]
        ),
        "runtime_completion_observation_count": sum(
            1
            for interface in interface_reports
            for method in interface["methods"]
            if method.get("runtime_completion_observation")
        ),
    }
    report = {
        "schema": XPC_COMPLETION_SHAPES_SCHEMA,
        "ok": True,
        "created_at": utc_now(),
        "inputs": {
            "targets": [{"project": project, "program": program} for project, program in parsed_targets],
            "xpc_method_inventory": str(xpc_method_inventory_path),
            "completion_probes": [str(path) for path in completion_probe_paths or []],
            "function_dossiers": [str(path) for path in function_dossier_dirs or []],
            "interfaces": interfaces or [],
        },
        "summary": summary,
        "interfaces": interface_reports,
    }
    out_path = Path(output) if output else cfg.exports_dir / "xpc_completion_shapes.json"
    md_path = Path(markdown_output) if markdown_output else cfg.exports_dir / "xpc_completion_shapes.md"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    md_path.write_text(_render_markdown(report), encoding="utf-8")
    return {
        "ok": True,
        "output": str(out_path),
        "markdown_output": str(md_path),
        **summary,
    }


def _selected_inventory_items(
    inventory: dict[str, Any],
    target_set: set[str],
    interfaces: list[str],
    limit: int,
) -> list[dict[str, Any]]:
    items = [item for item in inventory.get("interfaces", []) if isinstance(item, dict)]
    requested = {_interface_name(spec) for spec in interfaces}
    selected = []
    for item in items:
        if str(item.get("target") or "") not in target_set:
            continue
        if requested and str(item.get("interface") or "") not in requested:
            continue
        selected.append(item)
    if not requested:
        selected.sort(
            key=lambda item: (
                -sum(1 for method in item.get("method_candidates", []) if isinstance(method, dict) and _has_completion(method)),
                -int(item.get("method_count") or 0),
                str(item.get("interface") or ""),
            )
        )
    return selected[: max(1, limit)]


def _interface_name(spec: str) -> str:
    parts = spec.split("=")
    if len(parts) == 3:
        return parts[1]
    if len(parts) == 2:
        return parts[0]
    return spec


def _has_completion(method: dict[str, Any]) -> bool:
    selector = str(method.get("selector") or "")
    signature = method.get("signature_hint", {}) if isinstance(method.get("signature_hint"), dict) else {}
    return "completion" in selector.lower() or bool(signature.get("reply_block_likely"))


def _looks_read_or_getter(selector: str, method: dict[str, Any]) -> bool:
    source = method.get("safety_classification", {}) if isinstance(method.get("safety_classification"), dict) else {}
    lowered = selector.lower()
    return source.get("category") == "safe_read" or lowered.startswith(("get", "fetch", "list", "current", "is", "can", "has"))


def _completion_shape(
    selector: str,
    method: dict[str, Any],
    probe: dict[str, Any],
    static: dict[str, Any],
) -> dict[str, Any]:
    reply = _reply_allowed_classes(method, probe)
    reply_arguments = []
    max_index = max(
        [
            int(item.get("argument_index") or 0)
            for item in reply
            if item.get("ok") is not False or item.get("classes")
        ]
        + [0]
    )
    for index in range(max_index + 1):
        item = next((entry for entry in reply if int(entry.get("argument_index") or 0) == index), {})
        classes = [str(value) for value in item.get("classes", []) if value]
        arg = _reply_argument_shape(selector, index, classes)
        if arg:
            reply_arguments.append(arg)
    direct_reply_arguments = _direct_reply_arguments(static, selector)
    runtime_reply_arguments = probe.get("direct_completion_reply_arguments", [])
    if not reply_arguments and isinstance(runtime_reply_arguments, list) and runtime_reply_arguments:
        reply_arguments = runtime_reply_arguments
    if not reply_arguments and direct_reply_arguments:
        reply_arguments = direct_reply_arguments
    sources = []
    if reply:
        sources.append("nsxpc_allowed_classes")
    if probe.get("protocol_types"):
        sources.append("protocol_method_types")
    if static.get("block_descriptors"):
        sources.append("ghidra_block_descriptors")
    if static.get("direct_completion_invocations"):
        sources.append("ghidra_direct_completion_invoke")
    if probe.get("runtime_completion_observation"):
        sources.append("runtime_completion_observation")
    gaps = []
    if not reply_arguments:
        gaps.append("no_reply_arguments_recovered")
    if selector.lower().startswith("getnumberof") and not any(arg.get("kind") == "primitive" for arg in reply_arguments):
        gaps.append("count_primitive_not_recovered")
    confidence = (
        "high"
        if reply_arguments and (static.get("block_descriptors") or probe.get("runtime_completion_observation"))
        else "medium"
        if reply_arguments
        else "low"
    )
    return {
        "source": "+".join(sources) if sources else "unrecovered",
        "confidence": confidence,
        "completion": _completion_text(reply_arguments),
        "reply_arguments": reply_arguments,
        "residual_gaps": gaps,
    }


def _reply_argument_shape(selector: str, index: int, classes: list[str]) -> dict[str, Any]:
    class_set = set(classes)
    lowered = selector.lower()
    if classes:
        if class_set == {"NSError"}:
            return {"index": index, "kind": "object", "type": "NSError *", "classes": classes, "role": "error"}
        if "NSArray" in class_set:
            return {"index": index, "kind": "object", "type": "NSArray *", "classes": classes, "role": "result"}
        if "NSDictionary" in class_set:
            return {"index": index, "kind": "object", "type": "NSDictionary *", "classes": classes, "role": "result"}
        return {"index": index, "kind": "object", "type": " | ".join(classes), "classes": classes, "role": "result"}
    if index == 0 and "numberof" in lowered:
        return {
            "index": index,
            "kind": "primitive",
            "type": "NSUInteger",
            "classes": [],
            "role": "count",
            "inference": "selector_numberOf_without_reply_classes",
        }
    return {}


def _completion_text(reply_arguments: list[dict[str, Any]]) -> str:
    return "; ".join(f"reply[{arg['index']}] {arg['type']}" for arg in reply_arguments)


def _argument_allowed_classes(method: dict[str, Any], probe: dict[str, Any]) -> list[dict[str, Any]]:
    backing = method.get("configuration_backing", {}) if isinstance(method.get("configuration_backing"), dict) else {}
    values = backing.get("argument_allowed_classes") if isinstance(backing.get("argument_allowed_classes"), list) else []
    return values or probe.get("argument_allowed_classes", [])


def _reply_allowed_classes(method: dict[str, Any], probe: dict[str, Any]) -> list[dict[str, Any]]:
    backing = method.get("configuration_backing", {}) if isinstance(method.get("configuration_backing"), dict) else {}
    values = backing.get("reply_allowed_classes") if isinstance(backing.get("reply_allowed_classes"), list) else []
    return values or probe.get("reply_allowed_classes", [])


def _load_completion_probe(path: Path) -> dict[str, Any]:
    payload = _load_json(path, "completion probe")
    selectors = {}
    for item in payload.get("selectors", []) if isinstance(payload.get("selectors"), list) else []:
        if isinstance(item, dict) and item.get("selector"):
            selectors[str(item["selector"])] = item
    for item in payload.get("protocol_selectors", []) if isinstance(payload.get("protocol_selectors"), list) else []:
        if isinstance(item, dict) and item.get("selector"):
            selectors.setdefault(str(item["selector"]), {}).update({"protocol_types": item.get("types")})
    for item in payload.get("invocations", []) if isinstance(payload.get("invocations"), list) else []:
        if not isinstance(item, dict) or not item.get("selector"):
            continue
        selector = str(item["selector"])
        selectors.setdefault(selector, {}).update(
            {
                "direct_completion_reply_arguments": _runtime_reply_arguments(selector, item),
                "runtime_completion_observation": {
                    "artifact": str(path),
                    "completion_called": bool(item.get("completion_called")),
                    "completion_enabled": item.get("completion_enabled"),
                    "completion_error": item.get("completion_error", {}),
                    "remote_methods_invoked": bool(item.get("remote_methods_invoked", True)),
                },
            }
        )
    return {"path": str(path), "selectors": selectors}


def _probe_for_selector(probes: list[dict[str, Any]], selector: str) -> dict[str, Any]:
    for probe in probes:
        item = probe.get("selectors", {}).get(selector)
        if isinstance(item, dict):
            return {
                "artifact": probe.get("path", ""),
                "protocol_types": item.get("protocol_types") or item.get("types"),
                "argument_allowed_classes": item.get("argument_allowed_classes", []),
                "reply_allowed_classes": item.get("reply_allowed_classes", []),
                "direct_completion_reply_arguments": item.get("direct_completion_reply_arguments", []),
                "runtime_completion_observation": item.get("runtime_completion_observation", {}),
            }
    return {}


def _load_dossier_evidence(paths: list[Path]) -> list[dict[str, Any]]:
    evidence = []
    for path in paths:
        decompile = path / "decompile.c"
        if not decompile.exists():
            continue
        text = decompile.read_text(encoding="utf-8", errors="replace")
        context_path = path / "context.json"
        function = ""
        if context_path.exists():
            try:
                context = json.loads(context_path.read_text(encoding="utf-8"))
                function = str(context.get("function", {}).get("name") or "")
            except json.JSONDecodeError:
                function = ""
        evidence.append(
            {
                "path": str(path),
                "function": function,
                "text": text,
                "block_descriptors": _block_descriptors(text),
                "direct_completion_invocations": _direct_completion_invocations(text),
            }
        )
    return evidence


def _static_evidence_for_selector(evidence: list[dict[str, Any]], selector: str) -> dict[str, Any]:
    fragment = selector.replace(":", "_").replace("-", "_").replace(" ", "_")
    compact = re.sub(r"[^A-Za-z0-9]", "", selector)
    hits = []
    descriptors = []
    direct_invocations = []
    for item in evidence:
        haystack = f"{item.get('function', '')}\n{item.get('text', '')}"
        compact_haystack = re.sub(r"[^A-Za-z0-9]", "", haystack)
        if selector in haystack or fragment in haystack or compact in compact_haystack:
            hits.append({"path": item["path"], "function": item.get("function", "")})
            descriptors.extend(item.get("block_descriptors", []))
            direct_invocations.extend(
                dict(invocation, path=item["path"], function=item.get("function", ""))
                for invocation in item.get("direct_completion_invocations", [])
            )
    return {
        "dossier_hits": hits,
        "block_descriptors": _unique(descriptors),
        "direct_completion_invocations": direct_invocations,
    }


def _block_descriptors(text: str) -> list[str]:
    return _unique(re.findall(r"___block_descriptor_[A-Za-z0-9_<>]+", text))


def _direct_completion_invocations(text: str) -> list[dict[str, Any]]:
    normalized = re.sub(r"\s+", " ", text)
    invocations = []
    pattern = re.compile(r"\(\*\*\(code \*\*\)\((?P<block>[^)]*?)\s*\+\s*0x10\)\)\((?P<args>[^;]+?)\);")
    for match in pattern.finditer(normalized):
        args = [arg.strip() for arg in match.group("args").split(",") if arg.strip()]
        reply_args = _literal_reply_arguments("", args[1:])
        invocations.append(
            {
                "block_expression": match.group("block").strip(),
                "argument_values": args,
                "reply_arguments": reply_args,
            }
        )
    return invocations


def _direct_reply_arguments(static: dict[str, Any], selector: str) -> list[dict[str, Any]]:
    for invocation in static.get("direct_completion_invocations", []):
        args = invocation.get("reply_arguments", [])
        if isinstance(args, list) and args:
            if args[0].get("type") == "BOOL" and args[0].get("role") == "result":
                args = [dict(args[0], role=_bool_role(selector)), *args[1:]]
            return args
    return []


def _runtime_reply_arguments(selector: str, item: dict[str, Any]) -> list[dict[str, Any]]:
    if not item.get("completion_called"):
        return []
    values = []
    if "completion_enabled" in item:
        values.append("1" if bool(item.get("completion_enabled")) else "0")
    error = item.get("completion_error", {}) if isinstance(item.get("completion_error"), dict) else {}
    if error:
        values.append("0" if error.get("is_nil") else "NSError")
    return _literal_reply_arguments(selector, values)


def _literal_reply_arguments(selector: str, values: list[str]) -> list[dict[str, Any]]:
    if not values:
        return []
    normalized = [str(value).strip() for value in values]
    if len(normalized) >= 2 and _is_bool_literal(normalized[0]) and _is_nil_literal(normalized[1]):
        return [
            {
                "index": 0,
                "kind": "primitive",
                "type": "BOOL",
                "classes": [],
                "role": _bool_role(selector),
                "value": normalized[0],
                "inference": "direct_completion_literal",
            },
            {
                "index": 1,
                "kind": "object",
                "type": "NSError *",
                "classes": ["NSError"],
                "role": "error",
                "value": normalized[1],
                "inference": "direct_completion_nil_error",
            },
        ]
    if len(normalized) == 1 and (_is_nil_literal(normalized[0]) or "error" in selector.lower()):
        return [
            {
                "index": 0,
                "kind": "object",
                "type": "NSError *",
                "classes": ["NSError"],
                "role": "error",
                "value": normalized[0],
                "inference": "direct_completion_error_argument",
            }
        ]
    return []


def _is_bool_literal(value: str) -> bool:
    return value in {"0", "1", "true", "false", "YES", "NO"}


def _is_nil_literal(value: str) -> bool:
    return value in {"0", "nil", "NULL", "nullptr"}


def _bool_role(selector: str) -> str:
    lowered = selector.lower()
    if "enablement" in lowered or "enabled" in lowered:
        return "enabled"
    if lowered.startswith("can"):
        return "can"
    if lowered.startswith("has"):
        return "has"
    return "result"


def _render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# XPC Completion Shapes",
        "",
        f"- Schema: `{report['schema']}`",
        f"- Interfaces: {report['summary']['interface_count']}",
        f"- Completion methods: {report['summary']['completion_method_count']}",
        f"- Reply shapes: {report['summary']['reply_shape_count']}",
        f"- Primitive replies: {report['summary']['primitive_reply_count']}",
        f"- Direct completion invocations: {report['summary'].get('direct_completion_invocation_count', 0)}",
        f"- Runtime completion observations: {report['summary'].get('runtime_completion_observation_count', 0)}",
        "",
    ]
    for interface in report["interfaces"]:
        lines.append(f"## {interface['interface']}")
        lines.append("")
        for method in interface["methods"]:
            shape = method.get("completion_shape", {})
            lines.append(f"### {method['selector']}")
            lines.append("")
            lines.append(f"- Protocol types: `{method.get('protocol_types') or ''}`")
            lines.append(f"- Completion: {shape.get('completion') or 'unrecovered'}")
            lines.append(f"- Confidence: `{shape.get('confidence')}` source=`{shape.get('source')}`")
            for descriptor in method.get("static_block_evidence", {}).get("block_descriptors", []):
                lines.append(f"- Static block descriptor: `{descriptor}`")
            for invocation in method.get("static_block_evidence", {}).get("direct_completion_invocations", []):
                lines.append(f"- Direct completion invoke: `{', '.join(invocation.get('argument_values', []))}`")
            observation = method.get("runtime_completion_observation", {})
            if observation:
                lines.append(
                    "- Runtime completion observation: "
                    f"called={observation.get('completion_called')} remote_methods_invoked={observation.get('remote_methods_invoked')}"
                )
            for gap in shape.get("residual_gaps", []):
                lines.append(f"- Gap: `{gap}`")
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


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


def _unique(values: list[str]) -> list[str]:
    result = []
    seen = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result
