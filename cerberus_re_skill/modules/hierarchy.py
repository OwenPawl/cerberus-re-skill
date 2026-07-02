"""Build class/type hierarchy from objc_layout.json + swift_layout.json.

Produces:
  class_hierarchy.json   — nodes + edges + protocol conformance maps
  class_hierarchy.mmd    — Mermaid diagram for dossiers / quick inspection

This module is pure Python; it post-processes the JSON files produced by
ExportObjCTypeLayout.java (1.2) and ExportSwiftTypeLayout.java (1.3).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cerberus_re_skill.core.config import cfg


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def build_class_hierarchy(
    project: str,
    program: str,
    objc_layout_path: str | Path | None = None,
    swift_layout_path: str | Path | None = None,
    output_json: str | Path | None = None,
    output_mmd: str | Path | None = None,
) -> dict[str, Any]:
    """Build class_hierarchy.json and class_hierarchy.mmd from layout exports.

    Parameters
    ----------
    project, program:
        Used to derive default input/output paths under
        ``exports/<project>/<program>/``.
    objc_layout_path, swift_layout_path:
        Override auto-derived input paths.
    output_json, output_mmd:
        Override auto-derived output paths.

    Returns a dict with ``ok``, ``output_json``, ``output_mmd``, and summary
    counts.
    """
    export_dir = cfg.export_dir(project, program)
    export_dir.mkdir(parents=True, exist_ok=True)

    objc_path  = Path(objc_layout_path)  if objc_layout_path  else export_dir / "objc_layout.json"
    swift_path = Path(swift_layout_path) if swift_layout_path else export_dir / "swift_layout.json"
    out_json   = Path(output_json)       if output_json       else export_dir / "class_hierarchy.json"
    out_mmd    = Path(output_mmd)        if output_mmd        else export_dir / "class_hierarchy.mmd"

    # -----------------------------------------------------------------------
    # Load inputs
    # -----------------------------------------------------------------------
    _ensure_layout_exports(project, program, objc_path, swift_path)
    objc_data  = _load_json(objc_path)
    swift_data = _load_json(swift_path)

    objc_classes = [cls for cls in objc_data.get("classes", []) if isinstance(cls, dict)]
    swift_types = [t for t in swift_data.get("types", []) if isinstance(t, dict)]
    if not objc_classes and not swift_types:
        raise RuntimeError(
            "No class/type layout data found. Expected populated objc_layout.json "
            f"or swift_layout.json under {export_dir}."
        )

    # -----------------------------------------------------------------------
    # Build node and edge sets
    # -----------------------------------------------------------------------
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []

    # name → node dict (for dedup and edge attachment)
    node_map: dict[str, dict[str, Any]] = {}

    # protocol → set of conformers (bidirectional map)
    conformers_of:  dict[str, list[str]] = {}
    conforms_to:    dict[str, list[str]] = {}

    # -----------------------------------------------------------------------
    # ObjC classes
    # -----------------------------------------------------------------------
    for cls in objc_classes:
        name = cls.get("class", "")
        if not name:
            continue
        node = _make_node(
            name=name,
            kind="objc_class",
            image=project,
            ivar_count=len(cls.get("ivars", [])),
            method_count=len(cls.get("instance_methods", [])) + len(cls.get("class_methods", [])),
        )
        node_map[name] = node
        nodes.append(node)

        # Inheritance edge
        superclass = cls.get("superclass", "")
        if superclass:
            edges.append({"child": name, "parent": superclass, "relation": "inherits"})

        # Protocol conformance edges
        for proto in cls.get("protocols", []):
            if proto:
                edges.append({"child": name, "parent": proto, "relation": "conforms"})
                conformers_of.setdefault(proto, [])
                if name not in conformers_of[proto]:
                    conformers_of[proto].append(name)
                conforms_to.setdefault(name, [])
                if proto not in conforms_to[name]:
                    conforms_to[name].append(proto)

    # ObjC categories create "extends" edges (not nodes)
    for cat in objc_data.get("categories", []):
        cls_name = cat.get("class", "")
        cat_name = cat.get("category", "")
        if cls_name and cat_name:
            edges.append({"child": cat.get("name", cat_name), "parent": cls_name, "relation": "extends"})

    # -----------------------------------------------------------------------
    # Swift types
    # -----------------------------------------------------------------------
    for t in swift_types:
        name = t.get("demangled", "") or t.get("mangled", "")
        if not name or name.startswith("$types:"):
            # Use the bare name from the synthetic key if available
            mangled = t.get("mangled", "")
            if mangled.startswith("$types:"):
                name = mangled[7:]
            else:
                continue
        kind = t.get("kind", "struct")

        node = _make_node(
            name=name,
            kind=f"swift_{kind}",
            image=project,
            ivar_count=len(t.get("fields", [])),
            method_count=0,
        )
        node_map[name] = node
        nodes.append(node)

        # Superclass (for Swift classes)
        superclass_mangled = t.get("superclass_mangled", "")
        if superclass_mangled:
            edges.append({"child": name, "parent": superclass_mangled, "relation": "inherits"})

        # Protocol conformances
        for conf in t.get("conformances", []):
            proto = conf.get("protocol", "")
            if proto:
                edges.append({"child": name, "parent": proto, "relation": "conforms"})
                conformers_of.setdefault(proto, [])
                if name not in conformers_of[proto]:
                    conformers_of[proto].append(name)
                conforms_to.setdefault(name, [])
                if proto not in conforms_to[name]:
                    conforms_to[name].append(proto)

    # -----------------------------------------------------------------------
    # Synthesise protocol nodes that are referenced but not defined locally
    # -----------------------------------------------------------------------
    referenced_parents = {e["parent"] for e in edges}
    for parent in referenced_parents:
        if parent and parent not in node_map:
            node = _make_node(name=parent, kind="protocol", image="external",
                              ivar_count=0, method_count=0)
            node_map[parent] = node
            nodes.append(node)

    # -----------------------------------------------------------------------
    # Assemble payload
    # -----------------------------------------------------------------------
    payload: dict[str, Any] = {
        "program_name": program,
        "project_name": project,
        "nodes": nodes,
        "edges": edges,
        "conformers_of":  {k: sorted(v) for k, v in conformers_of.items()},
        "conforms_to":    {k: sorted(v) for k, v in conforms_to.items()},
        "node_count":  len(nodes),
        "edge_count":  len(edges),
    }

    out_json.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    # -----------------------------------------------------------------------
    # Mermaid diagram (class diagram syntax, capped for readability)
    # -----------------------------------------------------------------------
    mmd = _to_mermaid(nodes, edges)
    out_mmd.write_text(mmd, encoding="utf-8")

    return {
        "ok": True,
        "output_json": str(out_json),
        "output_mmd":  str(out_mmd),
        "node_count":  len(nodes),
        "edge_count":  len(edges),
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_node(
    name: str,
    kind: str,
    image: str,
    ivar_count: int,
    method_count: int,
) -> dict[str, Any]:
    return {
        "name":         name,
        "kind":         kind,
        "image":        image,
        "ivar_count":   ivar_count,
        "method_count": method_count,
    }


def _ensure_layout_exports(project: str, program: str, objc_path: Path, swift_path: Path) -> None:
    from cerberus_re_skill.modules.exporter import export_objc_layout, export_swift_layout

    if not objc_path.exists():
        export_objc_layout(project=project, program=program, output=str(objc_path))
    if not swift_path.exists():
        export_swift_layout(project=project, program=program, output=str(swift_path))


def _load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _sanitize_mermaid(name: str) -> str:
    """Strip characters that break Mermaid identifiers."""
    return (
        name
        .replace(".", "_")
        .replace("-", "_")
        .replace("+", "_")
        .replace(" ", "_")
        .replace("(", "_")
        .replace(")", "_")
        .replace("<", "_")
        .replace(">", "_")
        .replace(",", "_")
        .replace(":", "_")
        .replace("/", "_")
        .replace("*", "_")
    )


def _to_mermaid(nodes: list[dict], edges: list[dict], max_nodes: int = 120) -> str:
    """Render a Mermaid classDiagram from nodes and edges.

    Caps at *max_nodes* to keep diagrams usable.  Inherits / conforms / extends
    are rendered as Mermaid inheritance arrows.
    """
    lines = ["classDiagram"]

    # Only include local (non-external) nodes, capped at max_nodes
    local_nodes = [n for n in nodes if n.get("image") != "external"][:max_nodes]
    local_names = {n["name"] for n in local_nodes}

    for node in local_nodes:
        safe = _sanitize_mermaid(node["name"])
        label = node["name"].split(".")[-1]  # short name for display
        lines.append(f"    class {safe}[\"{label}\"]")

    for edge in edges:
        child  = edge.get("child", "")
        parent = edge.get("parent", "")
        if child not in local_names:
            continue
        safe_child  = _sanitize_mermaid(child)
        safe_parent = _sanitize_mermaid(parent)
        rel = edge.get("relation", "inherits")
        if rel == "inherits":
            lines.append(f"    {safe_parent} <|-- {safe_child}")
        elif rel == "conforms":
            lines.append(f"    {safe_parent} <|.. {safe_child}")
        elif rel == "extends":
            lines.append(f"    {safe_parent} <-- {safe_child} : extends")

    return "\n".join(lines) + "\n"
