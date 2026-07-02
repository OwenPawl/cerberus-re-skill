"""Build framework dependency graph from macho_structure.json + symbols.json.

Produces:
  framework_graph.json   — per-binary import/reexport/weak/upward graph
  framework_graph_global.json — aggregated across all programs in the project
  (global file is written to exports/<project>/ without a program subdirectory)

This module is pure Python; it post-processes the JSON files produced by
ExportMachOStructure.java (1.1) and ExportAppleBundle.java's symbols.json.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from cerberus_re_skill.core.config import cfg


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def build_framework_graph(
    project: str,
    program: str,
    macho_structure_path: str | Path | None = None,
    symbols_path: str | Path | None = None,
    output: str | Path | None = None,
    output_global: str | Path | None = None,
) -> dict[str, Any]:
    """Build framework_graph.json from macho_structure.json and symbols.json.

    Parameters
    ----------
    project, program:
        Used to derive default I/O paths.
    macho_structure_path, symbols_path:
        Override auto-derived input paths.
    output:
        Override per-program output path.
    output_global:
        Override the global (aggregated) output path at the project level.
    """
    export_dir = cfg.export_dir(project, program)
    export_dir.mkdir(parents=True, exist_ok=True)

    macho_path = Path(macho_structure_path) if macho_structure_path else export_dir / "macho_structure.json"
    sym_path   = Path(symbols_path)         if symbols_path         else export_dir / "symbols.json"
    out_path   = Path(output)               if output               else export_dir / "framework_graph.json"

    # Global path lives one level up (project-level)
    project_export_dir = cfg.exports_dir / project
    project_export_dir.mkdir(parents=True, exist_ok=True)
    global_path = (
        Path(output_global) if output_global
        else project_export_dir / "framework_graph_global.json"
    )

    if not macho_path.exists():
        from cerberus_re_skill.modules.exporter import export_macho_structure

        export_macho_structure(project=project, program=program, output=str(macho_path))
    if not sym_path.exists():
        raise RuntimeError(
            "symbols.json is required to build the framework graph. "
            f"Expected {sym_path}. Generate the Apple bundle first."
        )

    # -----------------------------------------------------------------------
    # Load inputs
    # -----------------------------------------------------------------------
    macho = _load_json(macho_path)
    syms  = _load_json(sym_path)
    if not macho.get("dylibs") and not macho.get("rpaths"):
        raise RuntimeError(f"macho_structure.json appears empty: {macho_path}")

    # -----------------------------------------------------------------------
    # Build per-binary framework entry
    # -----------------------------------------------------------------------
    imports:  list[dict[str, Any]] = []
    reexports: list[str] = []
    weak:      list[str] = []
    upward:    list[str] = []
    rpaths:    list[str] = list(macho.get("rpaths", []))

    # Categorise dylibs from macho_structure
    for dylib in macho.get("dylibs", []):
        name = dylib.get("name", "")
        kind = dylib.get("kind", "load")
        if not name:
            continue
        if kind == "reexport":
            reexports.append(name)
        elif kind == "weak":
            weak.append(name)
        elif kind == "upward":
            upward.append(name)
        else:
            imports.append({
                "install_name": name,
                "ordinal": dylib.get("ordinal"),
                "current_version": dylib.get("current_version", ""),
                "compatibility_version": dylib.get("compatibility_version", ""),
                "symbols_used": [],  # enriched below from symbols.json
            })

    # Enrich with symbol usage counts from symbols.json
    # symbols.json has top-level "imports": [{name, category, ...}]
    # Build a map: install_name → symbols used
    sym_usage: dict[str, list[str]] = defaultdict(list)
    for sym in syms.get("imports", []):
        lib = sym.get("library", "") or sym.get("external_library", "")
        sym_name = sym.get("name", "")
        if lib and sym_name:
            sym_usage[lib].append(sym_name)

    # Attach symbol counts to import entries
    for entry in imports:
        install_name = entry["install_name"]
        # Try exact match, then basename match
        used = sym_usage.get(install_name)
        if not used:
            base = install_name.split("/")[-1]
            used = sym_usage.get(base, [])
        entry["symbols_used"] = used[:200]  # cap for output size

    # -----------------------------------------------------------------------
    # Per-binary graph
    # -----------------------------------------------------------------------
    graph: dict[str, Any] = {
        "binary":    program,
        "project":   project,
        "imports":   imports,
        "reexports": reexports,
        "weak":      weak,
        "upward":    upward,
        "runtime_search_paths": rpaths,
        "sub_framework": macho.get("sub_framework", ""),
    }
    out_path.write_text(json.dumps(graph, indent=2, ensure_ascii=False), encoding="utf-8")

    # -----------------------------------------------------------------------
    # Global aggregation: merge this program into the project-level file
    # -----------------------------------------------------------------------
    global_data = _load_json(global_path)
    programs: dict[str, Any] = global_data.get("programs", {})
    programs[program] = graph
    global_data["programs"] = programs

    # Summary: all unique install_names across all programs
    all_imports: set[str] = set()
    for prog_graph in programs.values():
        for imp in prog_graph.get("imports", []):
            n = imp.get("install_name", "")
            if n:
                all_imports.add(n)
        all_imports.update(prog_graph.get("reexports", []))
        all_imports.update(prog_graph.get("weak", []))
        all_imports.update(prog_graph.get("upward", []))
    global_data["all_frameworks"] = sorted(all_imports)
    global_path.write_text(json.dumps(global_data, indent=2, ensure_ascii=False), encoding="utf-8")

    return {
        "ok": True,
        "output":        str(out_path),
        "output_global": str(global_path),
        "import_count":  len(imports),
        "reexport_count": len(reexports),
    }


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
