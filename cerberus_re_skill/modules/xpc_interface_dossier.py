"""Rank XPC interface candidates from surface and graph artifacts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cerberus_re_skill.core.config import cfg
from cerberus_re_skill.modules.xpc_graph import _actionable_protocol_hint


def build_xpc_interface_dossier(
    targets: list[str],
    *,
    xpc_graph_path: str | Path | None = None,
    output: str | Path | None = None,
    markdown_output: str | Path | None = None,
    limit: int = 25,
) -> dict[str, Any]:
    """Rank XPC interfaces for follow-up harness work."""
    if not targets:
        raise RuntimeError("at least one target is required")
    parsed = [_parse_target(target) for target in targets]
    surfaces = [_load_surface(project, program) for project, program in parsed]
    graph = _load_json(Path(xpc_graph_path)) if xpc_graph_path else {}
    edge_map = _edge_map(graph)
    candidates = _rank_candidates(surfaces, edge_map)
    selected = candidates[: max(1, limit)]

    out_path = Path(output) if output else cfg.exports_dir / "xpc_interface_dossier.json"
    md_path = Path(markdown_output) if markdown_output else cfg.exports_dir / "xpc_interface_dossier.md"
    report = {
        "ok": True,
        "schema": "ghidra-re.xpc-interface-dossier.v1",
        "targets": [{"project": project, "program": program} for project, program in parsed],
        "inputs": {
            "xpc_graph": str(xpc_graph_path) if xpc_graph_path else None,
            "surfaces": [surface["source_path"] for surface in surfaces],
        },
        "summary": {
            "candidate_count": len(candidates),
            "reported_candidate_count": len(selected),
            "target_count": len(parsed),
        },
        "candidates": selected,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    md_path.write_text(_render_markdown(report), encoding="utf-8")
    return {
        "ok": True,
        "output": str(out_path),
        "markdown_output": str(md_path),
        **report["summary"],
        "top_candidate": selected[0] if selected else None,
    }


def _parse_target(target: str) -> tuple[str, str]:
    if ":" not in target:
        raise RuntimeError(f"target must be formatted as project:program: {target}")
    project, program = target.split(":", 1)
    if not project or not program:
        raise RuntimeError(f"target must include both project and program: {target}")
    return project, program


def _load_surface(project: str, program: str) -> dict[str, Any]:
    path = cfg.export_dir(project, program) / "xpc_surface.json"
    data = _load_json(path)
    data["source_path"] = str(path)
    return data


def _load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise RuntimeError(f"missing JSON artifact: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError(f"failed to parse JSON at {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise RuntimeError(f"JSON artifact must be an object: {path}")
    return data


def _edge_map(graph: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    edges = graph.get("edges", []) if isinstance(graph, dict) else []
    result: dict[str, list[dict[str, Any]]] = {}
    if not isinstance(edges, list):
        return result
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        for key in ("from", "to"):
            node = edge.get(key)
            if node:
                result.setdefault(str(node), []).append(edge)
    return result


def _rank_candidates(
    surfaces: list[dict[str, Any]],
    edge_map: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    candidates: dict[tuple[str, str], dict[str, Any]] = {}
    for surface in surfaces:
        project = str(surface.get("project") or "")
        program = str(surface.get("program") or "")
        node_id = f"{project}:{program}"
        topology = surface.get("topology_hints") if isinstance(surface.get("topology_hints"), dict) else {}
        services = _service_values(topology.get("probable_services", []))
        listeners = _names(topology.get("probable_listeners", []))
        clients = _names(topology.get("probable_clients", []))
        classes = surface.get("xpc_classes", []) if isinstance(surface.get("xpc_classes"), list) else []
        edges = edge_map.get(node_id, [])
        for interface in _names(topology.get("probable_interfaces", [])):
            if not _actionable_protocol_hint(interface):
                continue
            key = (node_id, interface)
            score, reasons = _score_interface(interface, services, listeners, clients, edges)
            candidates[key] = {
                "target": node_id,
                "project": project,
                "program": program,
                "interface": interface,
                "score": score,
                "reasons": reasons,
                "services": services[:10],
                "owner_edges": _edge_summary(edges)[:10],
                "listener_hints": listeners[:10],
                "client_hints": clients[:10],
                "xpc_classes": [str(item) for item in classes[:10]],
            }
    return sorted(candidates.values(), key=lambda item: (-int(item["score"]), item["target"], item["interface"]))


def _score_interface(
    interface: str,
    services: list[str],
    listeners: list[str],
    clients: list[str],
    edges: list[dict[str, Any]],
) -> tuple[int, list[str]]:
    lowered = interface.lower()
    score = 10
    reasons = ["actionable_xpc_interface"]
    boosts = [
        ("automation", 45, "automation"),
        ("outofprocess", 32, "out_of_process_interface"),
        ("presenter", 28, "presenter"),
        ("status", 25, "status_interface"),
        ("dialog", 20, "dialog"),
        ("helper", 15, "helper_interface"),
        ("database", 12, "database_interface"),
    ]
    for needle, value, reason in boosts:
        if needle in lowered:
            score += value
            reasons.append(reason)
    if services:
        score += 8
        reasons.append("near_service_string")
    if listeners:
        score += 6
        reasons.append("near_listener_hint")
    if clients:
        score += 4
        reasons.append("near_client_hint")
    if edges:
        score += 6
        reasons.append("graph_edge_context")
    return score, reasons


def _service_values(items: Any) -> list[str]:
    if not isinstance(items, list):
        return []
    values = []
    for item in items:
        if isinstance(item, dict) and item.get("value"):
            values.append(str(item["value"]))
    return sorted(set(values), key=str.lower)


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


def _edge_summary(edges: list[dict[str, Any]]) -> list[dict[str, Any]]:
    summary = []
    for edge in edges:
        summary.append(
            {
                "from": edge.get("from"),
                "to": edge.get("to"),
                "relation": edge.get("relation"),
                "service": edge.get("service"),
            }
        )
    return summary


def _render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# XPC Interface Dossier",
        "",
        "## Summary",
        "",
    ]
    for key, value in report["summary"].items():
        lines.append(f"- `{key}`: {value}")
    lines.extend(["", "## Ranked Candidates", ""])
    for idx, item in enumerate(report["candidates"], start=1):
        lines.append(f"### {idx}. `{item['interface']}`")
        lines.append("")
        lines.append(f"- Target: `{item['target']}`")
        lines.append(f"- Score: `{item['score']}`")
        lines.append(f"- Reasons: {', '.join(f'`{reason}`' for reason in item['reasons'])}")
        if item["services"]:
            lines.append(f"- Nearby services: {', '.join(f'`{service}`' for service in item['services'][:5])}")
        if item["owner_edges"]:
            edge = item["owner_edges"][0]
            lines.append(
                "- Graph context: "
                f"`{edge.get('from')}` -> `{edge.get('to')}` "
                f"via `{edge.get('service')}`"
            )
        if item["listener_hints"]:
            lines.append(f"- Listener hint: `{item['listener_hints'][0]}`")
        lines.append("")
    return "\n".join(lines)
