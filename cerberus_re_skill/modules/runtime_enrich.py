"""Enrich shared runtime-hit bundles with static export context."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from cerberus_re_skill.core.config import cfg
from cerberus_re_skill.modules.function_identity import normalize_function_identity
from cerberus_re_skill.modules.lldb_enrich import (
    _FunctionIndex,
    _annotate_address_boundary,
    _build_function_symbol_index,
    _build_symbol_index,
    _compute_slide,
    _decompile_function,
    _function_summary,
    _hex,
    _load_json,
    _load_required_json,
    _name_keys,
    _normalise_functions,
    _parse_int,
    _same_function_entry,
    _static_match_status,
    _symbol_resolution_context,
    _xref_context,
)


RUNTIME_ENRICH_SCHEMA = "ghidra-re.runtime-hit-enrichment.v1"


def enrich_runtime_hits(
    project: str,
    program: str,
    runtime_hits_path: str | Path,
    *,
    function_inventory_path: str | Path | None = None,
    lldb_symbols_path: str | Path | None = None,
    output: str | Path | None = None,
    known_runtime_pc: str | None = None,
    known_static_addr: str | None = None,
    include_decompile: bool = False,
    decompile_timeout: int = 60,
) -> dict[str, Any]:
    """Annotate shared runtime hits with Ghidra export function context."""
    export_dir = cfg.export_dir(project, program)
    runtime_file = Path(runtime_hits_path)
    inv_path = Path(function_inventory_path) if function_inventory_path else export_dir / "function_inventory.json"
    symbols_path = Path(lldb_symbols_path) if lldb_symbols_path else export_dir / "lldb_symbols.json"
    out_path = Path(output) if output else runtime_file.with_name(f"{runtime_file.stem}_enriched.json")

    bundle = _load_required_json(runtime_file, "runtime hits")
    inventory = _load_required_json(inv_path, "function inventory")
    program_summary = _load_program_summary(inv_path, export_dir)
    image_base = _program_image_base(program_summary)
    if lldb_symbols_path and not symbols_path.exists():
        raise RuntimeError(f"missing LLDB symbols: {symbols_path}")
    lldb_symbols = _load_json(symbols_path)
    hits = bundle.get("hits", [])
    if not isinstance(hits, list):
        raise RuntimeError(f"runtime hits must contain a hits list: {runtime_file}")

    functions = _normalise_functions(inventory.get("functions", []))
    function_index = _FunctionIndex(functions)
    symbol_index = _build_symbol_index(lldb_symbols)
    function_symbol_index = _build_function_symbol_index(functions)
    slide_hits = [_slide_hit(hit) for hit in hits]
    slide_info = _compute_slide(
        hits=slide_hits,
        symbol_index=symbol_index,
        function_symbol_index=function_symbol_index,
        function_index=function_index,
        known_runtime_pc=known_runtime_pc,
        known_static_addr=known_static_addr,
    )
    module_slide_info = _compute_module_slide(
        hits=hits,
        image_base=image_base,
        function_index=function_index,
        program=program,
    )
    if slide_info.get("slide") is None and module_slide_info.get("slide") is not None:
        slide_info = module_slide_info
    slide = slide_info.get("slide")

    enriched_hits: list[dict[str, Any]] = []
    matched_functions = 0
    address_mapped_functions = 0
    symbol_resolved_function_count = 0
    symbol_mismatch_count = 0
    symbol_resolved_mismatch_count = 0
    symbol_resolved_conflicts: list[dict[str, Any]] = []
    interior_boundary_mismatch_count = 0
    cross_image_runtime_hit_count = 0
    cross_image_runtime_modules: dict[str, dict[str, Any]] = {}
    decompile_cache: dict[str, dict[str, Any]] = {}
    for hit_index, hit in enumerate(hits):
        enriched = dict(hit)
        image_status = _runtime_image_status(hit, program)
        if image_status:
            enriched["runtime_image"] = image_status["runtime_image"]
            enriched["runtime_image_match_status"] = image_status["status"]
            if image_status["status"] == "cross_image_runtime_hit":
                cross_image_runtime_hit_count += 1
                module_key = image_status["runtime_image"].get("module_name") or image_status["key"]
                cross_image_runtime_modules.setdefault(module_key, image_status["runtime_image"])
        runtime_pc = _runtime_pc(hit)
        static_addr = _static_addr(hit)
        if static_addr is None and runtime_pc is not None and isinstance(slide, int):
            static_addr = runtime_pc - slide
        match_source = ""
        symbol_func = _find_by_symbol(hit, function_symbol_index, functions)
        if symbol_func is not None:
            symbol_resolved_function_count += 1
        func = function_index.find(static_addr) if static_addr is not None else None
        if func is not None:
            match_source = "address"
        if func is None:
            func = symbol_func
            if func is not None:
                match_source = "symbol"
                static_addr = _parse_int(func.get("entry") or func.get("address"))
        if runtime_pc is not None:
            enriched["runtime_pc"] = _hex(runtime_pc)
        if static_addr is not None:
            enriched["ghidra_addr"] = _hex(static_addr)
            runtime = dict(enriched.get("runtime") or {})
            runtime.setdefault("static_address", _hex(static_addr))
            enriched["runtime"] = runtime
        if func is not None:
            static_match = _static_match_status(hit, func)
            static_match["match_source"] = match_source or "unknown"
            if match_source == "address":
                if static_addr is not None:
                    _annotate_address_boundary(static_match, func, static_addr)
                address_mapped_functions += 1
                if static_match["status"] == "symbol_mismatch":
                    symbol_mismatch_count += 1
                    if symbol_func is not None and not _same_function_entry(symbol_func, func):
                        symbol_resolved_mismatch_count += 1
                        resolution = _symbol_resolution_context(
                            symbol_func,
                            func,
                            hit_index=hit_index,
                            runtime_symbol=_symbol(hit),
                            runtime_pc=runtime_pc,
                            address_mapped_static_address=static_addr,
                        )
                        symbol_resolved_conflicts.append(resolution)
                        enriched["symbol_resolved_function"] = _runtime_function_summary(
                            symbol_func,
                            project=project,
                            program=program,
                        )
                        if resolution.get("symbol_resolved_static_address"):
                            enriched["symbol_resolved_static_address"] = resolution[
                                "symbol_resolved_static_address"
                            ]
                        static_match["symbol_resolution_status"] = "symbol_disagrees_with_address"
                        static_match["symbol_resolution"] = resolution
                    if static_match.get("boundary_status") == "interior_symbol_mismatch":
                        interior_boundary_mismatch_count += 1
                else:
                    matched_functions += 1
            else:
                matched_functions += 1
                if static_match["status"] == "symbol_mismatch":
                    static_match["status"] = "symbol_fallback"
                    static_match["notes"] = "Matched by runtime symbol, categoryless symbol, or unique selector fallback."
            enriched["static_match_status"] = static_match["status"]
            enriched["static_match"] = static_match
            enriched["ghidra_function"] = _runtime_function_summary(func, project=project, program=program)
            enriched["xref_context"] = _xref_context(func)
            entry = str(func.get("entry") or func.get("address") or enriched.get("ghidra_addr") or "")
            if include_decompile and entry:
                decompile = decompile_cache.get(entry)
                if decompile is None:
                    decompile = _decompile_function(
                        project=project,
                        program=program,
                        func=func,
                        export_dir=export_dir,
                        timeout=decompile_timeout,
                    )
                    decompile_cache[entry] = decompile
                enriched["decompile"] = decompile
        enriched_hits.append(enriched)

    result = dict(bundle)
    result.update(
        {
            "enriched": True,
            "enrichment": {
                "schema": RUNTIME_ENRICH_SCHEMA,
                "project": project,
                "program": program,
                "runtime_hits": str(runtime_file),
                "function_inventory": str(inv_path),
                "program_summary": str(_program_summary_path(inv_path, export_dir)),
                "lldb_symbols": str(symbols_path) if symbols_path.exists() else None,
                "slide": _hex(slide) if isinstance(slide, int) else None,
                "slide_confidence": slide_info.get("confidence", "none"),
                "slide_evidence": slide_info.get("evidence", []),
                "slide_conflict": slide_info.get("conflict", False),
                "slide_candidates": slide_info.get("candidates", []),
                "hit_count": len(hits),
                "matched_function_count": matched_functions,
                "address_mapped_function_count": address_mapped_functions,
                "symbol_resolved_function_count": symbol_resolved_function_count,
                "address_or_symbol_evidence_count": matched_functions
                + symbol_resolved_mismatch_count,
                "symbol_mismatch_count": symbol_mismatch_count,
                "symbol_resolved_mismatch_count": symbol_resolved_mismatch_count,
                "symbol_resolved_conflict_count": len(symbol_resolved_conflicts),
                "symbol_resolved_conflicts": symbol_resolved_conflicts[:50],
                "interior_boundary_mismatch_count": interior_boundary_mismatch_count,
                "cross_image_runtime_hit_count": cross_image_runtime_hit_count,
                "cross_image_runtime_modules": list(cross_image_runtime_modules.values())[:25],
                "runtime_image_guidance": _runtime_image_guidance(
                    cross_image_runtime_hit_count,
                    cross_image_runtime_modules,
                    program,
                ),
                "decompile_count": len(decompile_cache),
            },
            "hits": enriched_hits,
        }
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return {
        "ok": True,
        "output": str(out_path),
        "hit_count": len(hits),
        "matched_function_count": matched_functions,
        "address_mapped_function_count": address_mapped_functions,
        "symbol_resolved_function_count": symbol_resolved_function_count,
        "address_or_symbol_evidence_count": matched_functions + symbol_resolved_mismatch_count,
        "symbol_mismatch_count": symbol_mismatch_count,
        "symbol_resolved_mismatch_count": symbol_resolved_mismatch_count,
        "symbol_resolved_conflict_count": len(symbol_resolved_conflicts),
        "interior_boundary_mismatch_count": interior_boundary_mismatch_count,
        "cross_image_runtime_hit_count": cross_image_runtime_hit_count,
        "cross_image_runtime_modules": list(cross_image_runtime_modules.values())[:25],
        "decompile_count": len(decompile_cache),
        "slide": _hex(slide) if isinstance(slide, int) else None,
        "slide_confidence": slide_info.get("confidence", "none"),
        "slide_conflict": slide_info.get("conflict", False),
        "slide_candidates": slide_info.get("candidates", []),
    }


def _slide_hit(hit: dict[str, Any]) -> dict[str, Any]:
    return {
        "pc": _hex(pc) if (pc := _runtime_pc(hit)) is not None else "",
        "symbol": _symbol(hit),
    }


def _load_program_summary(inv_path: Path, export_dir: Path) -> dict[str, Any]:
    return _load_json(_program_summary_path(inv_path, export_dir))


def _program_summary_path(inv_path: Path, export_dir: Path) -> Path:
    inventory_sibling = inv_path.with_name("program_summary.json")
    if inventory_sibling.exists():
        return inventory_sibling
    return export_dir / "program_summary.json"


def _program_image_base(program_summary: dict[str, Any]) -> int | None:
    metadata = program_summary.get("metadata") if isinstance(program_summary.get("metadata"), dict) else {}
    return _parse_int(
        program_summary.get("image_base")
        or program_summary.get("min_address")
        or metadata.get("Minimum Address")
    )


def _compute_module_slide(
    *,
    hits: list[dict[str, Any]],
    image_base: int | None,
    function_index: _FunctionIndex,
    program: str,
) -> dict[str, Any]:
    if image_base is None:
        return {"slide": None, "confidence": "none", "evidence": [], "conflict": False, "candidates": []}
    candidates: dict[int, list[dict[str, Any]]] = {}
    for hit in hits:
        pc = _runtime_pc(hit)
        module_base = _runtime_module_base(hit)
        if pc is None or module_base is None:
            continue
        if not _runtime_module_matches_program(hit, program):
            continue
        slide = module_base - image_base
        static_addr = pc - slide
        evidence = {
            "source": "frida_module_base",
            "runtime_pc": _hex(pc),
            "module_name": _runtime_module_name(hit),
            "module_path": _runtime_module_path(hit),
            "module_base": _hex(module_base),
            "image_base": _hex(image_base),
            "slide": _hex(slide),
            "static_address": _hex(static_addr),
            "symbol": _symbol(hit),
            "maps_to_function": function_index.find(static_addr) is not None,
        }
        candidates.setdefault(slide, []).append(evidence)
    if not candidates:
        return {"slide": None, "confidence": "none", "evidence": [], "conflict": False, "candidates": []}
    ranked = sorted(
        candidates.items(),
        key=lambda item: (
            sum(1 for evidence in item[1] if evidence["maps_to_function"]),
            len(item[1]),
            item[0],
        ),
        reverse=True,
    )
    selected_slide, selected_evidence = ranked[0]
    candidate_summary = [
        {
            "slide": _hex(slide),
            "evidence_count": len(items),
            "mapped_hit_count": sum(1 for evidence in items if evidence["maps_to_function"]),
            "sample_evidence": items[:3],
        }
        for slide, items in ranked
    ]
    return {
        "slide": selected_slide,
        "confidence": "module_base" if len(candidates) == 1 else "conflicting",
        "evidence": selected_evidence[:10],
        "conflict": len(candidates) > 1,
        "candidates": candidate_summary,
    }


def _runtime_function_summary(func: dict[str, Any], *, project: str, program: str) -> dict[str, Any]:
    summary = _function_summary(func)
    summary["function_identity"] = normalize_function_identity(
        func,
        source="headless",
        project=project,
        program=program,
    )
    return summary


def _runtime_pc(hit: dict[str, Any]) -> int | None:
    runtime = hit.get("runtime") if isinstance(hit.get("runtime"), dict) else {}
    return _parse_int(runtime.get("pc") or hit.get("pc") or hit.get("runtime_pc"))


def _runtime_module_base(hit: dict[str, Any]) -> int | None:
    runtime = hit.get("runtime") if isinstance(hit.get("runtime"), dict) else {}
    module = runtime.get("module") if isinstance(runtime.get("module"), dict) else {}
    target = hit.get("target") if isinstance(hit.get("target"), dict) else {}
    return _parse_int(
        module.get("base")
        or hit.get("module_base")
        or target.get("module_base")
    )


def _runtime_module_name(hit: dict[str, Any]) -> str:
    runtime = hit.get("runtime") if isinstance(hit.get("runtime"), dict) else {}
    module = runtime.get("module") if isinstance(runtime.get("module"), dict) else {}
    target = hit.get("target") if isinstance(hit.get("target"), dict) else {}
    return str(module.get("name") or hit.get("module_name") or hit.get("module") or target.get("module") or "")


def _runtime_module_path(hit: dict[str, Any]) -> str:
    runtime = hit.get("runtime") if isinstance(hit.get("runtime"), dict) else {}
    module = runtime.get("module") if isinstance(runtime.get("module"), dict) else {}
    target = hit.get("target") if isinstance(hit.get("target"), dict) else {}
    return str(module.get("path") or hit.get("module_path") or target.get("module_path") or "")


def _runtime_module_matches_program(hit: dict[str, Any], program: str) -> bool:
    expected = str(program or "").strip().lower()
    if not expected:
        return True
    module_name = _runtime_module_name(hit).lower()
    module_path = _runtime_module_path(hit)
    names = {module_name}
    if module_name.endswith(".dylib"):
        names.add(module_name[:-6])
    if module_path:
        path = Path(module_path)
        names.add(path.name.lower())
        names.add(path.stem.lower())
    return expected in names


def _runtime_image_status(hit: dict[str, Any], program: str) -> dict[str, Any] | None:
    module_name = _runtime_module_name(hit)
    module_path = _runtime_module_path(hit)
    module_base = _runtime_module_base(hit)
    if not (module_name or module_path or module_base is not None):
        return None
    matches = _runtime_module_matches_program(hit, program)
    runtime_image = {
        "module_name": module_name,
        "module_path": module_path,
        "module_base": _hex(module_base) if module_base is not None else "",
        "expected_program": program,
    }
    return {
        "status": "same_image_runtime_hit" if matches else "cross_image_runtime_hit",
        "runtime_image": runtime_image,
        "key": module_path or module_name or runtime_image["module_base"],
    }


def _runtime_image_guidance(
    cross_image_runtime_hit_count: int,
    cross_image_runtime_modules: dict[str, dict[str, Any]],
    program: str,
) -> list[str]:
    if cross_image_runtime_hit_count <= 0:
        return []
    modules = ", ".join(
        str(item.get("module_name") or item.get("module_path") or item.get("module_base") or "unknown")
        for item in list(cross_image_runtime_modules.values())[:5]
    )
    return [
        (
            f"{cross_image_runtime_hit_count} runtime hits came from module(s) that do not match static program "
            f"{program!r}: {modules}."
        ),
        (
            "Treat address/slide function mappings for these hits as cross-image evidence; import or materialize the "
            "callee image before trusting function-body correlation."
        ),
    ]


def _static_addr(hit: dict[str, Any]) -> int | None:
    runtime = hit.get("runtime") if isinstance(hit.get("runtime"), dict) else {}
    return _parse_int(runtime.get("static_address") or hit.get("ghidra_addr") or hit.get("static_address"))


def _symbol(hit: dict[str, Any]) -> str:
    target = hit.get("target") if isinstance(hit.get("target"), dict) else {}
    return str(hit.get("symbol") or target.get("symbol") or "")


def _find_by_symbol(
    hit: dict[str, Any],
    function_symbol_index: dict[str, list[dict[str, Any]]],
    functions: list[dict[str, Any]],
) -> dict[str, Any] | None:
    symbol = _symbol(hit)
    if not symbol and not hit.get("selector"):
        return None
    search_keys = set(_name_keys(symbol))
    for key in search_keys:
        matches = function_symbol_index.get(key)
        if matches:
            return matches[0]
    for key, matches in function_symbol_index.items():
        if matches and _objc_categoryless_symbol_key(key) in search_keys:
            return matches[0]
    return _find_by_unique_objc_selector(hit, functions)


def _find_by_unique_objc_selector(hit: dict[str, Any], functions: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Match selector-wide Frida hits when class names differ from the owner.

    Some runtime hits report a proxy class while the exported static owner is
    the runner implementation. If slide matching is unavailable, use the
    selector only when exactly one non-block function owns that selector.
    """

    selector = str(hit.get("selector") or "").strip() or _selector_from_objc_symbol(_symbol(hit))
    if not selector:
        return None
    matches: list[dict[str, Any]] = []
    for func in functions:
        if _function_has_selector(func, selector):
            matches.append(func)
    if len(matches) == 1:
        return matches[0]
    return None


def _objc_categoryless_symbol_key(symbol: str) -> str:
    """Map ObjC category method symbols to the runtime class selector form.

    Frida observes category methods as `-[Class selector:]`, while Ghidra exports
    often preserve the category as `-[Class(Category)_selector:]`.
    """
    match = re.match(r"^([+-])\[([^\]\s(]+)\([^)]+\)[ _](.+)\]$", symbol)
    if not match:
        return ""
    return f"{match.group(1)}[{match.group(2)} {match.group(3)}]"


def _selector_from_objc_symbol(symbol: str) -> str:
    match = re.match(r"^[+-]\[[^\]\s]+ (.+)\]$", str(symbol or ""))
    if match:
        return match.group(1)
    return ""


def _function_has_selector(func: dict[str, Any], selector: str) -> bool:
    name = str(func.get("name") or "")
    if "block_invoke" in name:
        return False
    if name == selector:
        return True
    if name.endswith(f" {selector}]") or name.endswith(f"_{selector}]"):
        return True
    return False
