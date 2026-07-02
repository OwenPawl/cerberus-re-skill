"""Merge per-binary XPC surface reports into a coarse IPC graph."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from cerberus_re_skill.core.config import cfg
from cerberus_re_skill.modules.xpc_surface import build_xpc_surface


def build_xpc_graph(
    targets: list[str],
    output: str | Path | None = None,
    markdown_output: str | Path | None = None,
    owner_hints: list[str] | None = None,
) -> dict[str, Any]:
    """Merge XPC surface reports for targets formatted as project:program."""
    parsed_targets = [_parse_target(target) for target in targets]
    if len(parsed_targets) < 1:
        raise RuntimeError("at least one target is required")

    parsed_owner_hints = _parse_owner_hints(owner_hints or [])
    surfaces = [_load_or_build_surface(project, program) for project, program in parsed_targets]
    nodes = [_node_from_surface(surface) for surface in surfaces]
    nodes = _apply_registered_owners(nodes, parsed_owner_hints)
    edges = _infer_edges(nodes, parsed_owner_hints)
    follow_ups = _suggest_follow_ups(nodes, edges)

    out_path = Path(output) if output else cfg.exports_dir / "xpc_graph.json"
    md_path = Path(markdown_output) if markdown_output else cfg.exports_dir / "xpc_graph.md"
    report = {
        "ok": True,
        "targets": [{"project": project, "program": program} for project, program in parsed_targets],
        "summary": {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "follow_up_count": len(follow_ups),
            "service_count": sum(len(node["services"]) for node in nodes),
        },
        "nodes": nodes,
        "edges": edges,
        "follow_ups": follow_ups,
        "owner_hints": [
            {"service": service, "owner": owner}
            for service, owner in sorted(parsed_owner_hints.items(), key=lambda item: (item[0], item[1]))
        ],
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
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


def _parse_owner_hints(owner_hints: list[str]) -> dict[str, str]:
    hints: dict[str, str] = {}
    for hint in owner_hints:
        if "=" not in hint:
            raise RuntimeError(f"owner hint must be formatted as service=project:program: {hint}")
        service, owner = hint.split("=", 1)
        service = service.strip()
        owner = owner.strip()
        if not service or ":" not in owner:
            raise RuntimeError(f"owner hint must include a service and project:program owner: {hint}")
        _parse_target(owner)
        hints[service] = owner
    return hints


def _load_or_build_surface(project: str, program: str) -> dict[str, Any]:
    surface_path = cfg.export_dir(project, program) / "xpc_surface.json"
    if surface_path.exists():
        data = _load_json(surface_path)
        if data.get("ok"):
            return data
    build_xpc_surface(project, program)
    return _load_json(surface_path)


def _node_from_surface(surface: dict[str, Any]) -> dict[str, Any]:
    project = str(surface.get("project") or "")
    program = str(surface.get("program") or "")
    topology = surface.get("topology_hints") if isinstance(surface.get("topology_hints"), dict) else {}
    services = _service_values(topology.get("probable_services", []))
    return {
        "id": f"{project}:{program}",
        "project": project,
        "program": program,
        "services": services,
        "classes": surface.get("xpc_classes", [])[:100] if isinstance(surface.get("xpc_classes"), list) else [],
        "protocols": _names(topology.get("probable_interfaces", []))[:100],
        "listeners": _names(topology.get("probable_listeners", []))[:100],
        "clients": _names(topology.get("probable_clients", []))[:100],
    }


def _apply_registered_owners(nodes: list[dict[str, Any]], owner_hints: dict[str, str]) -> list[dict[str, Any]]:
    if not owner_hints:
        return nodes
    by_id = {node["id"]: dict(node) for node in nodes}
    for service, owner_id in owner_hints.items():
        if owner_id not in by_id:
            project, program = _parse_target(owner_id)
            by_id[owner_id] = {
                "id": owner_id,
                "project": project,
                "program": program,
                "registered_owner": True,
                "services": [],
                "classes": [],
                "protocols": [],
                "listeners": [],
                "clients": [],
            }
        owner = by_id[owner_id]
        services = list(owner.get("services", []))
        if not any(item.get("value") == service for item in services if isinstance(item, dict)):
            services.append({"value": service, "address": None, "referenced_from": [], "registered_owner_hint": True})
        owner["services"] = services
        by_id[owner_id] = owner
    return sorted(by_id.values(), key=lambda node: node["id"])


def _service_values(items: Any) -> list[dict[str, Any]]:
    if not isinstance(items, list):
        return []
    services = []
    for item in items:
        if not isinstance(item, dict):
            continue
        value = item.get("value")
        if not value:
            continue
        services.append(
            {
                "value": str(value),
                "address": item.get("address"),
                "referenced_from": item.get("referenced_from", []),
            }
        )
    return services


def _names(items: Any) -> list[str]:
    if not isinstance(items, list):
        return []
    names = []
    for item in items:
        if isinstance(item, str):
            names.append(item)
        elif isinstance(item, dict):
            name = item.get("name") or item.get("value")
            if name:
                names.append(str(name))
    return sorted(set(names), key=str.lower)


def _infer_edges(nodes: list[dict[str, Any]], owner_hints: dict[str, str] | None = None) -> list[dict[str, Any]]:
    edges = []
    for source in nodes:
        for service in source["services"]:
            owner = _best_owner(service["value"], nodes, owner_hints or {})
            if owner is None:
                continue
            relation = "provides_service" if owner["id"] == source["id"] else "references_service"
            edges.append(
                {
                    "from": source["id"],
                    "to": owner["id"],
                    "relation": relation,
                    "service": service["value"],
                    "evidence": {
                        "service_address": service.get("address"),
                        "referenced_from": service.get("referenced_from", []),
                        "registered_owner_hint": service.get("registered_owner_hint", False)
                        or (owner_hints or {}).get(service["value"]) == owner["id"],
                    },
                }
            )
    return _dedupe_edges(edges)


def _suggest_follow_ups(nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> list[dict[str, Any]]:
    suggestions = []
    resolved_services = {edge["service"] for edge in edges}
    provided_services = {edge["service"] for edge in edges if edge.get("relation") == "provides_service"}
    referenced_services = {edge["service"] for edge in edges if edge.get("relation") == "references_service"}
    node_by_id = {node["id"]: node for node in nodes}

    for node in nodes:
        for service in node["services"]:
            value = service["value"]
            if value not in resolved_services:
                suggestions.append(
                    {
                        "kind": "missing_service_owner",
                        "priority": "high",
                        "target": node["id"],
                        "service": value,
                        "reason": "No imported target appears to own this Mach service.",
                        "next_step": f"Import the daemon/helper likely responsible for `{value}` and rebuild the XPC graph.",
                    }
                )
            elif value in provided_services and value not in referenced_services:
                suggestions.append(
                    {
                        "kind": "service_without_client_edge",
                        "priority": "medium",
                        "target": node["id"],
                        "service": value,
                        "reason": "The service has an owner but no cross-target client edge in the current graph.",
                        "next_step": f"Search other targets for `{value}` or trace NSXPCConnection setup at runtime.",
                    }
                )

        if node["clients"] and not any(edge.get("from") == node["id"] for edge in edges):
            suggestions.append(
                {
                    "kind": "client_without_resolved_service",
                    "priority": "medium",
                    "target": node["id"],
                    "reason": "XPC client-like classes were found, but no service ownership edge was inferred.",
                    "next_step": f"Trace `{node['program']}` XPC setup with `ghidra_xpc_trace` or inspect `/strings/search` for service names.",
                }
            )

        for protocol in [item for item in node["protocols"] if _actionable_protocol_hint(item)][:10]:
            if protocol and not _protocol_has_listener(node_by_id.get(node["id"], {}), protocol):
                suggestions.append(
                    {
                        "kind": "protocol_without_listener_hint",
                        "priority": "low",
                        "target": node["id"],
                        "protocol": protocol,
                        "reason": "An XPC-like protocol was found without a nearby listener hint in this surface report.",
                        "next_step": f"Generate an XPC harness for `{protocol}` only after confirming the service endpoint.",
                    }
                )

    return sorted(
        _dedupe_suggestions(suggestions),
        key=lambda item: ({"high": 0, "medium": 1, "low": 2}.get(item["priority"], 3), item["kind"], item["target"]),
    )[:100]


def _protocol_has_listener(node: dict[str, Any], protocol: str) -> bool:
    lowered = protocol.lower()
    return any(lowered in listener.lower() or listener.lower() in lowered for listener in node.get("listeners", []))


def _actionable_protocol_hint(protocol: str) -> bool:
    if not protocol:
        return False
    if protocol.startswith(("+[", "-[", "_objc_msgSend", "_OBJC_CLASS", "__OBJC", "s_", "outlined$")):
        return False
    if protocol.endswith(":") or "MachServiceName" in protocol:
        return False
    if protocol in {"BSXPCSecureCoding", "NSXPCListenerDelegate"}:
        return False
    if protocol[:1].islower() or protocol.endswith("Connection"):
        return False
    return protocol.endswith("XPCInterface") or protocol.endswith("XPCProtocol") or protocol.endswith("Protocol")


def _dedupe_suggestions(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    result = []
    for item in items:
        marker = (
            item.get("kind"),
            item.get("target"),
            item.get("service"),
            item.get("protocol"),
        )
        if marker in seen:
            continue
        seen.add(marker)
        result.append(item)
    return result


def _best_owner(service: str, nodes: list[dict[str, Any]], owner_hints: dict[str, str] | None = None) -> dict[str, Any] | None:
    node_by_id = {node["id"]: node for node in nodes}
    hinted_owner = (owner_hints or {}).get(service)
    if hinted_owner and hinted_owner in node_by_id:
        return node_by_id[hinted_owner]
    scored = []
    for node in nodes:
        score = _owner_score(service, node["program"])
        if score:
            scored.append((score, node))
    if not scored:
        return None
    scored.sort(key=lambda item: (-item[0], item[1]["id"]))
    return scored[0][1]


def _owner_score(service: str, program: str) -> int:
    service_norm = _normalise(service)
    program_norm = _normalise(program)
    if program_norm and program_norm in service_norm:
        return 100
    tokens = [token for token in _tokens(program) if len(token) >= 4]
    if not tokens:
        return 0
    hits = sum(1 for token in tokens if token in service_norm)
    if hits == len(tokens):
        return 80 + hits
    return 0


def _tokens(value: str) -> list[str]:
    split = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", value)
    return [_normalise(part) for part in re.split(r"[^A-Za-z0-9]+", split) if part]


def _normalise(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def _dedupe_edges(edges: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    result = []
    for edge in edges:
        marker = (edge["from"], edge["to"], edge["relation"], edge["service"])
        if marker in seen:
            continue
        seen.add(marker)
        result.append(edge)
    return sorted(result, key=lambda edge: (edge["from"], edge["to"], edge["service"]))


def _render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# XPC Graph",
        "",
        "## Summary",
        "",
    ]
    for key, value in report["summary"].items():
        lines.append(f"- `{key}`: {value}")
    lines.extend(["", "## Edges", ""])
    if not report["edges"]:
        lines.append("- No cross-target service ownership edges inferred.")
    for edge in report["edges"]:
        lines.append(
            f"- `{edge['from']}` -> `{edge['to']}` via `{edge['service']}` ({edge['relation']})"
        )
    lines.extend(["", "## Follow-ups", ""])
    if not report.get("follow_ups"):
        lines.append("- No follow-up gaps inferred.")
    for item in report.get("follow_ups", []):
        subject = item.get("service") or item.get("protocol") or item.get("target")
        lines.append(
            f"- `{item['priority']}` `{item['kind']}` on `{subject}`: {item['next_step']}"
        )
    lines.extend(["", "## Nodes", ""])
    for node in report["nodes"]:
        lines.append(
            f"- `{node['id']}`: {len(node['services'])} services, "
            f"{len(node['listeners'])} listeners, {len(node['protocols'])} interfaces"
        )
    lines.append("")
    return "\n".join(lines)


def _load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise RuntimeError(f"missing XPC surface report: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError(f"failed to parse JSON at {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise RuntimeError(f"XPC surface report must be a JSON object: {path}")
    return data
