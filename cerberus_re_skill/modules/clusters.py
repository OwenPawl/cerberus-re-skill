"""Group functions into subsystem clusters from function_inventory.json.

Produces:
  subsystem_clusters.json   — clusters labelled by common prefix, framework
                               affinity, or xref community

Strategy (in order, additive):
  1. Name-prefix grouping: functions sharing a common CamelCase prefix
     (e.g. ABC*, SVS*, CF*) are grouped.  Minimum cluster size = 3.
  2. ObjC class grouping: functions whose Ghidra symbol puts them in a
     known ObjC class (e.g. -[TargetAction ...]) are grouped under that class.
  3. Xref community (optional, uses NetworkX if available): builds a call
     graph from function_inventory xrefs and applies a greedy community
     detection algorithm.  Falls back gracefully if NetworkX is absent.

This module is pure Python and requires only the standard library (+ optional
NetworkX for community detection in strategy 3).
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from cerberus_re_skill.core.config import cfg

# Regex to extract CamelCase prefix (first component, 2+ uppercase letters or
# one uppercase + at least one lowercase of at least 2 chars total)
_CAMEL_PREFIX_RE = re.compile(r"^([A-Z]{2,}[a-z]*|[A-Z][a-z]+)(?=[A-Z_]|$)")
# ObjC method: +/-[ClassName selectorPart:]
_OBJC_METHOD_RE  = re.compile(r"^[+\-]\[([A-Za-z_][A-Za-z0-9_]*(?:\([^)]+\))?) ")


def build_subsystem_clusters(
    project: str,
    program: str,
    function_inventory_path: str | Path | None = None,
    objc_layout_path: str | Path | None = None,
    output: str | Path | None = None,
    min_prefix_size: int = 3,
    use_xref_communities: bool = True,
) -> dict[str, Any]:
    """Build subsystem_clusters.json from function_inventory.json.

    Parameters
    ----------
    project, program:
        Used to derive default I/O paths.
    function_inventory_path, objc_layout_path:
        Override auto-derived input paths.
    output:
        Override output path.
    min_prefix_size:
        Minimum number of functions sharing a prefix to form a cluster.
    use_xref_communities:
        Whether to attempt NetworkX-based community detection (strategy 3).
    """
    export_dir = cfg.export_dir(project, program)
    export_dir.mkdir(parents=True, exist_ok=True)

    inv_path  = (Path(function_inventory_path) if function_inventory_path
                 else export_dir / "function_inventory.json")
    objc_path = (Path(objc_layout_path) if objc_layout_path
                 else export_dir / "objc_layout.json")
    out_path  = (Path(output) if output
                 else export_dir / "subsystem_clusters.json")

    # -----------------------------------------------------------------------
    # Load inputs
    # -----------------------------------------------------------------------
    inv  = _load_json(inv_path)
    objc = _load_json(objc_path)

    functions: list[dict[str, Any]] = inv.get("functions", [])
    if not functions:
        raise RuntimeError(
            "function_inventory.json is required to build subsystem clusters. "
            f"Expected populated data at {inv_path}."
        )

    # -----------------------------------------------------------------------
    # Strategy 1: ObjC class membership (from function name)
    # -----------------------------------------------------------------------
    class_clusters: dict[str, list[str]] = defaultdict(list)
    unclassed: list[dict[str, Any]] = []

    for func in functions:
        name = func.get("name", "") or func.get("full_name", "")
        addr = func.get("address", "")
        m = _OBJC_METHOD_RE.match(name)
        if m:
            cls_name = m.group(1)
            class_clusters[cls_name].append(addr)
        else:
            unclassed.append(func)

    # Also add ObjC layout class names as authoritative sources
    for cls in objc.get("classes", []):
        cls_name = cls.get("class", "")
        if cls_name and cls_name not in class_clusters:
            class_clusters[cls_name]  # ensure entry exists

    # -----------------------------------------------------------------------
    # Strategy 2: CamelCase name-prefix grouping for non-ObjC functions
    # -----------------------------------------------------------------------
    prefix_clusters: dict[str, list[str]] = defaultdict(list)
    unmatched: list[dict[str, Any]] = []

    for func in unclassed:
        name = func.get("name", "") or func.get("full_name", "")
        addr = func.get("address", "")
        m = _CAMEL_PREFIX_RE.match(name)
        if m:
            prefix = m.group(1)
            prefix_clusters[prefix].append(addr)
        else:
            unmatched.append(func)

    # Filter prefix clusters by minimum size
    prefix_clusters = {
        p: addrs for p, addrs in prefix_clusters.items()
        if len(addrs) >= min_prefix_size
    }

    # -----------------------------------------------------------------------
    # Strategy 3: Xref community detection (optional, NetworkX)
    # -----------------------------------------------------------------------
    community_clusters: dict[str, list[str]] = {}
    if use_xref_communities:
        community_clusters = _xref_communities(functions)

    # -----------------------------------------------------------------------
    # Merge: ObjC class > prefix > community
    # (Prefer class assignment; prefix is secondary; community fills rest)
    # -----------------------------------------------------------------------
    assigned: set[str] = set()
    clusters: list[dict[str, Any]] = []

    for cls_name, addrs in sorted(class_clusters.items()):
        if not addrs:
            continue
        for a in addrs:
            assigned.add(a)
        clusters.append({
            "label":    cls_name,
            "strategy": "objc_class",
            "size":     len(addrs),
            "functions": addrs,
        })

    for prefix, addrs in sorted(prefix_clusters.items()):
        remaining = [a for a in addrs if a not in assigned]
        if not remaining:
            continue
        for a in remaining:
            assigned.add(a)
        clusters.append({
            "label":    prefix,
            "strategy": "name_prefix",
            "size":     len(remaining),
            "functions": remaining,
        })

    for label, addrs in sorted(community_clusters.items()):
        remaining = [a for a in addrs if a not in assigned]
        if not remaining:
            continue
        for a in remaining:
            assigned.add(a)
        clusters.append({
            "label":    label,
            "strategy": "xref_community",
            "size":     len(remaining),
            "functions": remaining,
        })

    # Unclustered remainder
    all_addrs = {f.get("address", "") for f in functions}
    unclustered = sorted(all_addrs - assigned)
    if unclustered:
        clusters.append({
            "label":    "__unclustered__",
            "strategy": "none",
            "size":     len(unclustered),
            "functions": unclustered,
        })

    payload: dict[str, Any] = {
        "program_name":   program,
        "project_name":   project,
        "total_functions": len(functions),
        "cluster_count":   len(clusters),
        "clusters":        sorted(clusters, key=lambda c: -c["size"]),
    }
    out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    return {
        "ok":            True,
        "output":        str(out_path),
        "cluster_count": len(clusters),
        "total_functions": len(functions),
    }


# ---------------------------------------------------------------------------
# Xref community helpers
# ---------------------------------------------------------------------------


def _xref_communities(functions: list[dict[str, Any]]) -> dict[str, list[str]]:
    """Run greedy Louvain-style community detection via NetworkX.

    Falls back to an empty dict if NetworkX is not available or the graph
    is too small to be interesting.
    """
    try:
        import networkx as nx  # type: ignore
    except ImportError:
        return {}

    G = nx.DiGraph()
    for func in functions:
        addr = func.get("address", "")
        if not addr:
            continue
        G.add_node(addr)
        for xref in func.get("xrefs_to", []):
            G.add_edge(xref, addr)
        for xref in func.get("xrefs_from", []):
            G.add_edge(addr, xref)

    if len(G) < 10:
        return {}

    try:
        # Use greedy modularity communities on undirected version
        communities = nx.community.greedy_modularity_communities(G.to_undirected())
        result: dict[str, list[str]] = {}
        for i, community in enumerate(communities):
            if len(community) >= 3:
                result[f"community_{i}"] = list(community)
        return result
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
