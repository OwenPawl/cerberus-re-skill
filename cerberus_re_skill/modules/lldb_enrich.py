"""Enrich LLDB runtime traces with static Ghidra export context."""

from __future__ import annotations

import bisect
import json
import subprocess
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cerberus_re_skill.core.config import cfg
from cerberus_re_skill.modules.function_identity import normalize_function_identity


def enrich_lldb_trace(
    project: str,
    program: str,
    trace_path: str | Path,
    function_inventory_path: str | Path | None = None,
    lldb_symbols_path: str | Path | None = None,
    output: str | Path | None = None,
    known_runtime_pc: str | None = None,
    known_static_addr: str | None = None,
    include_decompile: bool = False,
    decompile_timeout: int = 60,
    auto_apply: bool = False,
) -> dict[str, Any]:
    """Annotate an LLDB trace with Ghidra addresses and function metadata."""
    export_dir = cfg.export_dir(project, program)
    trace_file = Path(trace_path)
    inv_path = (
        Path(function_inventory_path)
        if function_inventory_path
        else export_dir / "function_inventory.json"
    )
    symbols_path = (
        Path(lldb_symbols_path)
        if lldb_symbols_path
        else export_dir / "lldb_symbols.json"
    )
    out_path = Path(output) if output else trace_file.with_name(f"{trace_file.stem}_enriched.json")

    trace = _load_required_json(trace_file, "LLDB trace")
    inventory = _load_required_json(inv_path, "function inventory")
    if lldb_symbols_path and not symbols_path.exists():
        raise RuntimeError(f"missing LLDB symbols: {symbols_path}")
    lldb_symbols = _load_json(symbols_path)

    hits = trace.get("hits", [])
    if not isinstance(hits, list):
        raise RuntimeError(f"trace hits must be a list: {trace_file}")

    functions = _normalise_functions(inventory.get("functions", []))
    function_index = _FunctionIndex(functions)
    symbol_index = _build_symbol_index(lldb_symbols)
    function_symbol_index = _build_function_symbol_index(functions)

    slide_info = _compute_slide(
        hits=hits,
        symbol_index=symbol_index,
        function_symbol_index=function_symbol_index,
        function_index=function_index,
        known_runtime_pc=known_runtime_pc,
        known_static_addr=known_static_addr,
    )
    slide = slide_info.get("slide")

    enriched_hits = []
    matched_functions = 0
    address_mapped_functions = 0
    symbol_resolved_function_count = 0
    symbol_mismatch_count = 0
    symbol_resolved_mismatch_count = 0
    symbol_resolved_conflicts: list[dict[str, Any]] = []
    interior_boundary_mismatch_count = 0
    decompile_cache: dict[str, dict[str, Any]] = {}
    observed_by_function: dict[str, dict[str, Any]] = {}
    for hit_index, hit in enumerate(hits):
        enriched = dict(hit)
        runtime_pc = _parse_int(hit.get("pc"))
        symbol_func = _symbol_function_for_hit(hit, function_symbol_index)
        if symbol_func is not None:
            symbol_resolved_function_count += 1
        if runtime_pc is not None:
            enriched["runtime_pc"] = _hex(runtime_pc)
        if runtime_pc is not None and isinstance(slide, int):
            ghidra_addr = runtime_pc - slide
            enriched["ghidra_addr"] = _hex(ghidra_addr)
            func = function_index.find(ghidra_addr)
            if func:
                address_mapped_functions += 1
                static_match = _static_match_status(hit, func)
                _annotate_address_boundary(static_match, func, ghidra_addr)
                enriched["static_match_status"] = static_match["status"]
                enriched["static_match"] = static_match
                if static_match["status"] == "symbol_mismatch":
                    symbol_mismatch_count += 1
                    if symbol_func is not None and not _same_function_entry(symbol_func, func):
                        symbol_resolved_mismatch_count += 1
                        resolution = _symbol_resolution_context(
                            symbol_func,
                            func,
                            hit_index=hit_index,
                            runtime_symbol=str(hit.get("symbol") or ""),
                            runtime_pc=runtime_pc,
                            address_mapped_static_address=ghidra_addr,
                        )
                        symbol_resolved_conflicts.append(resolution)
                        enriched["symbol_resolved_function"] = _function_summary(symbol_func)
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
                enriched["ghidra_function"] = _function_summary(func)
                enriched["xref_context"] = _xref_context(func)
                entry = str(func.get("entry") or func.get("address") or enriched.get("ghidra_addr"))
                if entry:
                    observed = observed_by_function.setdefault(
                        entry,
                        {"function": func, "hit_count": 0, "classes": set()},
                    )
                    observed["hit_count"] += 1
                    if hit.get("self_class"):
                        observed["classes"].add(str(hit.get("self_class")))
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

    applied_findings = []
    if auto_apply and observed_by_function:
        for entry, observed in observed_by_function.items():
            func = observed["function"]
            classes = sorted(observed["classes"])
            comment = f"Observed at runtime in LLDB trace {trace_file.name}; hits={observed['hit_count']}"
            if classes:
                comment += "; classes=" + ",".join(classes[:8])
            applied_findings.append(
                _apply_runtime_finding(
                    project=project,
                    program=program,
                    entry=entry,
                    function_name=str(func.get("name") or ""),
                    comment=comment,
                    export_dir=export_dir,
                )
            )

    result = dict(trace)
    result.update(
        {
            "enriched": True,
            "enrichment": {
                "project": project,
                "program": program,
                "trace": str(trace_file),
                "function_inventory": str(inv_path),
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
                "decompile_count": len(decompile_cache),
                "auto_apply_count": len(applied_findings),
            },
            "hits": enriched_hits,
        }
    )
    if applied_findings:
        result["applied_findings"] = applied_findings

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
        "decompile_count": len(decompile_cache),
        "auto_apply_count": len(applied_findings),
        "slide": _hex(slide) if isinstance(slide, int) else None,
        "slide_confidence": slide_info.get("confidence", "none"),
        "slide_conflict": slide_info.get("conflict", False),
        "slide_candidates": slide_info.get("candidates", []),
    }


def _decompile_function(
    project: str,
    program: str,
    func: dict[str, Any],
    export_dir: Path,
    timeout: int,
) -> dict[str, Any]:
    from cerberus_re_skill.modules.importer import run_script

    entry = str(func.get("entry") or func.get("address") or "")
    safe_entry = entry.replace("0x", "").replace(":", "_") or "unknown"
    out_path = export_dir / "decompile_cache" / f"{safe_entry}.c"
    meta_path = out_path.with_suffix(out_path.suffix + ".meta.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    command = [
        "ghidra-re",
        "import",
        "run-script",
        "DecompileFunction.java",
        project,
        program,
        f"address={entry}",
        f"output={out_path}",
        f"timeout={timeout}",
    ]
    if not out_path.exists():
        run_script(
            script_name="DecompileFunction.java",
            project_name=project,
            program_name=program,
            script_args=[f"address={entry}", f"output={out_path}", f"timeout={timeout}"],
        )
    text = out_path.read_text(encoding="utf-8", errors="replace") if out_path.exists() else ""
    provenance = {
        "schema": "ghidra-re.decompile-cache-provenance.v1",
        "generated_at": _utc_now(),
        "project": project,
        "program": program,
        "function_identity": normalize_function_identity(
            func,
            source="headless",
            project=project,
            program=program,
        ),
        "source_command": command,
        "path": str(out_path),
    }
    meta_path.write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")
    return {
        "path": str(out_path),
        "provenance_path": str(meta_path),
        "provenance": provenance,
        "function": func.get("name"),
        "entry": entry,
        "pseudocode": text,
    }


def _apply_runtime_finding(
    project: str,
    program: str,
    entry: str,
    function_name: str,
    comment: str,
    export_dir: Path,
) -> dict[str, Any]:
    output_dir = export_dir / "findings"
    output_dir.mkdir(parents=True, exist_ok=True)
    safe_entry = entry.replace("0x", "").replace(":", "_") or "unknown"
    output = output_dir / f"runtime-observed-{safe_entry}.json"
    if output.exists():
        return {
            "ok": True,
            "entry": entry,
            "function": function_name,
            "output": str(output),
            "skipped": True,
            "reason": "runtime finding output already exists",
        }
    script = cfg.skill_root / "scripts" / "ghidra_apply_finding"
    if not script.exists():
        return {"ok": False, "entry": entry, "error": f"missing {script}"}
    cmd = [
        str(script),
        project,
        program,
        f"address={entry}",
        "title=Observed at runtime",
        f"comment={comment}",
        "bookmark_category=runtime",
        f"output={output}",
    ]
    proc = subprocess.run(cmd, check=False, capture_output=True, text=True)
    return {
        "ok": proc.returncode == 0,
        "entry": entry,
        "function": function_name,
        "output": str(output),
        "stdout": proc.stdout[-4000:],
        "stderr": proc.stderr[-4000:],
    }


class _FunctionIndex:
    def __init__(self, functions: list[dict[str, Any]]) -> None:
        self.functions = sorted(functions, key=lambda f: f["_entry_int"])
        self.entries = [f["_entry_int"] for f in self.functions]

    def find(self, addr: int) -> dict[str, Any] | None:
        idx = bisect.bisect_right(self.entries, addr) - 1
        if idx < 0:
            return None
        func = self.functions[idx]
        entry = func["_entry_int"]
        size = max(int(func.get("body_size") or 0), 1)
        if entry <= addr < entry + size:
            return func
        if addr == entry:
            return func
        return None


def _compute_slide(
    hits: list[dict[str, Any]],
    symbol_index: dict[str, list[dict[str, Any]]],
    function_symbol_index: dict[str, list[dict[str, Any]]],
    function_index: _FunctionIndex,
    known_runtime_pc: str | None,
    known_static_addr: str | None,
) -> dict[str, Any]:
    if known_runtime_pc and known_static_addr:
        runtime = _parse_int(known_runtime_pc)
        static = _parse_int(known_static_addr)
        if runtime is None or static is None:
            raise RuntimeError("known runtime/static addresses must be hex or decimal integers")
        return {
            "slide": runtime - static,
            "confidence": "manual",
            "evidence": [{"runtime_pc": _hex(runtime), "static_addr": _hex(static), "source": "manual"}],
        }

    candidates: list[tuple[int, dict[str, Any]]] = []
    seen_candidates: set[tuple[int, int, str, str]] = set()
    for hit in hits:
        runtime_pc = _parse_int(hit.get("pc"))
        symbol = hit.get("symbol")
        if runtime_pc is None or not symbol:
            continue
        for entry in symbol_index.get(str(symbol), []):
            static_addr = _parse_int(entry.get("address"))
            if static_addr is None:
                continue
            candidate_key = (runtime_pc, static_addr, str(symbol), "lldb_symbols")
            if candidate_key in seen_candidates:
                continue
            seen_candidates.add(candidate_key)
            candidates.append(
                (
                    runtime_pc - static_addr,
                    {
                        "symbol": symbol,
                        "runtime_pc": _hex(runtime_pc),
                        "static_addr": _hex(static_addr),
                        "source": "lldb_symbols",
                    },
                )
            )
        for key in _name_keys(str(symbol)):
            for entry in function_symbol_index.get(key, []):
                static_addr = _parse_int(entry.get("entry") or entry.get("address"))
                if static_addr is None:
                    continue
                candidate_key = (runtime_pc, static_addr, str(symbol), "function_inventory")
                if candidate_key in seen_candidates:
                    continue
                seen_candidates.add(candidate_key)
                candidates.append(
                    (
                        runtime_pc - static_addr,
                        {
                            "symbol": symbol,
                            "runtime_pc": _hex(runtime_pc),
                            "static_addr": _hex(static_addr),
                            "source": "function_inventory",
                        },
                    )
                )

    if not candidates:
        return {"slide": None, "confidence": "none", "evidence": [], "conflict": False, "candidates": []}

    counts = Counter(slide for slide, _ in candidates)
    slide_scores = []
    runtime_pcs = [_parse_int(hit.get("pc")) for hit in hits]
    runtime_pcs = [pc for pc in runtime_pcs if pc is not None]
    for candidate_slide, count in counts.items():
        mapped = sum(
            1 for pc in runtime_pcs
            if function_index.find(pc - candidate_slide) is not None
        )
        slide_scores.append((mapped, count, candidate_slide))
    mapped_count, count, slide = max(slide_scores)
    evidence = [item for candidate_slide, item in candidates if candidate_slide == slide][:10]
    candidate_summaries = []
    for candidate_slide, candidate_count in counts.items():
        items = [item for possible_slide, item in candidates if possible_slide == candidate_slide]
        candidate_summaries.append(
            {
                "slide": _hex(candidate_slide),
                "evidence_count": candidate_count,
                "runtime_hit_count": len({str(item.get("runtime_pc") or "") for item in items}),
                "mapped_hit_count": sum(
                    1 for pc in runtime_pcs
                    if function_index.find(pc - candidate_slide) is not None
                ),
                "symbols": sorted({str(item.get("symbol") or "") for item in items if item.get("symbol")}),
            }
        )
    candidate_summaries.sort(
        key=lambda item: (int(item["mapped_hit_count"]), int(item["evidence_count"]), str(item["slide"])),
        reverse=True,
    )
    conflict = len(candidate_summaries) > 1
    confidence = "conflicting" if conflict else ("high" if mapped_count >= 2 else "medium" if count >= 1 else "low")
    return {
        "slide": slide,
        "confidence": confidence,
        "evidence": evidence,
        "mapped_hit_count": mapped_count,
        "conflict": conflict,
        "candidates": candidate_summaries,
    }


def _build_symbol_index(payload: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    index: dict[str, list[dict[str, Any]]] = {}
    for bucket in (
        "objc_methods",
        "trampolines",
        "outlined",
        "swift",
        "other_code",
        "data",
        "objc_classes",
    ):
        for item in payload.get(bucket, []) if isinstance(payload.get(bucket), list) else []:
            name = item.get("name")
            if name:
                index.setdefault(str(name), []).append(item)
    return index


def _build_function_symbol_index(functions: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    index: dict[str, list[dict[str, Any]]] = {}
    for func in functions:
        for candidate in _function_symbol_names(func):
            for key in _name_keys(candidate):
                index.setdefault(key, []).append(func)
    return index


def _function_symbol_names(func: dict[str, Any]) -> set[str]:
    names = {str(func.get("name") or "")}
    namespace = str(func.get("namespace") or "")
    name = str(func.get("name") or "")
    if namespace and name and namespace not in {"/", "Global", "stub"}:
        # Ghidra inventories ObjC methods as namespace + selector, while
        # LLDB reports method symbols in the canonical -[Class selector] form.
        names.add(f"-[{namespace} {name}]")
        names.add(f"+[{namespace} {name}]")
    return {name for name in names if name}


def _static_match_status(hit: dict[str, Any], func: dict[str, Any]) -> dict[str, Any]:
    runtime_symbol = str(hit.get("symbol") or "")
    expected = sorted({key for name in _function_symbol_names(func) for key in _name_keys(name)})
    if not runtime_symbol:
        return {
            "status": "symbol_unavailable",
            "runtime_symbol": "",
            "function_name": func.get("name"),
            "expected_symbols": expected,
        }
    status = "verified" if runtime_symbol in expected else "symbol_mismatch"
    return {
        "status": status,
        "runtime_symbol": runtime_symbol,
        "function_name": func.get("name"),
        "expected_symbols": expected,
    }


def _symbol_resolved_function(
    hit: dict[str, Any],
    function_symbol_index: dict[str, list[dict[str, Any]]],
    address_func: dict[str, Any],
) -> dict[str, Any] | None:
    """Recover the symbol-resolved identity when address boundaries disagree."""
    runtime_symbol = str(hit.get("symbol") or "")
    if not runtime_symbol:
        return None
    for key in _name_keys(runtime_symbol):
        for candidate in function_symbol_index.get(key, []):
            if not _same_function_entry(candidate, address_func):
                return candidate
    return None


def _symbol_function_for_hit(
    hit: dict[str, Any],
    function_symbol_index: dict[str, list[dict[str, Any]]],
) -> dict[str, Any] | None:
    """Resolve a runtime symbol to a static function without using address evidence."""
    runtime_symbol = str(hit.get("symbol") or "")
    if not runtime_symbol:
        return None
    for key in _name_keys(runtime_symbol):
        matches = function_symbol_index.get(key)
        if matches:
            return matches[0]
    return None


def _symbol_resolution_context(
    symbol_func: dict[str, Any],
    address_func: dict[str, Any],
    *,
    hit_index: int | None = None,
    runtime_symbol: str = "",
    runtime_pc: int | None = None,
    address_mapped_static_address: int | None = None,
) -> dict[str, Any]:
    """Describe a symbol identity that disagrees with address-derived mapping."""
    symbol_entry = _parse_int(symbol_func.get("entry") or symbol_func.get("address"))
    address_entry = _parse_int(address_func.get("entry") or address_func.get("address"))
    context: dict[str, Any] = {
        "status": "symbol_disagrees_with_address",
        "symbol_resolved_function_name": symbol_func.get("name"),
        "symbol_resolved_function_entry": _hex(symbol_entry),
        "symbol_resolved_static_address": _hex(symbol_entry),
        "address_mapped_function_name": address_func.get("name"),
        "address_mapped_function_entry": _hex(address_entry),
        "address_mapped_function_kind": _boundary_function_kind(address_func),
    }
    if hit_index is not None:
        context["hit_index"] = hit_index
    if runtime_symbol:
        context["runtime_symbol"] = runtime_symbol
    if runtime_pc is not None:
        context["runtime_pc"] = _hex(runtime_pc)
    if address_mapped_static_address is not None:
        context["address_mapped_static_address"] = _hex(address_mapped_static_address)
    _annotate_symbol_boundary_drift(context, symbol_entry, address_mapped_static_address)
    return context


def _annotate_symbol_boundary_drift(
    context: dict[str, Any],
    symbol_entry: int | None,
    address_mapped_static_address: int | None,
) -> None:
    if symbol_entry is None or address_mapped_static_address is None:
        return
    delta = symbol_entry - address_mapped_static_address
    context["symbol_boundary_delta"] = _signed_hex(delta)
    context["symbol_boundary_abs_delta"] = _hex(abs(delta))
    if abs(delta) <= 0x80:
        context["symbol_boundary_status"] = "neighboring_symbol_boundary_drift"
        if delta > 0:
            context["symbol_boundary_direction"] = "runtime_before_symbol_entry"
        elif delta < 0:
            context["symbol_boundary_direction"] = "runtime_after_symbol_entry"
        else:
            context["symbol_boundary_direction"] = "runtime_at_symbol_entry"
        context["boundary_recovery_hint"] = (
            "Runtime symbol identity is close to the symbol-resolved static entry; "
            "inspect nearby function boundaries, cold fragments, or entry labels before trusting the decompile."
        )
    else:
        context["symbol_boundary_status"] = "distant_symbol_address_conflict"


def _boundary_function_kind(func: dict[str, Any]) -> str:
    name = str(func.get("name") or "")
    lowered = name.lower()
    if ".cold" in lowered:
        return "cold"
    if "block_invoke" in lowered:
        return "block"
    return "function"


def _signed_hex(value: int) -> str:
    if value < 0:
        return f"-0x{-value:x}"
    return _hex(value) or "0x0"


def _same_function_entry(left: dict[str, Any], right: dict[str, Any]) -> bool:
    left_entry = _parse_int(left.get("entry") or left.get("address"))
    right_entry = _parse_int(right.get("entry") or right.get("address"))
    return left_entry is not None and left_entry == right_entry


def _annotate_address_boundary(static_match: dict[str, Any], func: dict[str, Any], static_addr: int) -> None:
    """Mark runtime addresses that land inside a conflicting static function."""
    entry = _parse_int(func.get("entry") or func.get("address"))
    if entry is None:
        return
    offset = static_addr - entry
    static_match["function_entry"] = _hex(entry)
    static_match["address_offset_from_entry"] = _hex(offset)
    static_match["at_function_entry"] = offset == 0
    if offset > 0 and static_match.get("status") == "symbol_mismatch":
        static_match["boundary_status"] = "interior_symbol_mismatch"
        static_match["boundary_recovery_candidate"] = True
        static_match["boundary_note"] = (
            "The runtime-observed symbol maps inside a differently named static function; "
            "recover or verify function boundaries before trusting its decompile."
        )


def _name_keys(name: str) -> set[str]:
    keys = {name}
    if name.startswith(("-[", "+[")) and " " in name:
        prefix, rest = name.split(" ", 1)
        keys.add(f"{prefix}_{rest}")
    if name.startswith(("-[", "+[")) and "_" in name and " " not in name:
        marker = name.find("_")
        if marker > 0:
            keys.add(name[:marker] + " " + name[marker + 1:])
    if name and not name.startswith(("-[", "+[")):
        # Mach-O inventories retain the linker underscore that LLDB/runtime
        # symbol lookup omits for exported C and Swift-facing entry points.
        keys.add(name[1:] if name.startswith("_") else f"_{name}")
    return {key for key in keys if key}


def _normalise_functions(functions: Any) -> list[dict[str, Any]]:
    normalised = []
    if not isinstance(functions, list):
        return normalised
    for func in functions:
        if not isinstance(func, dict):
            continue
        entry = _parse_int(func.get("entry") or func.get("address"))
        if entry is None:
            continue
        item = dict(func)
        item["_entry_int"] = entry
        normalised.append(item)
    return normalised


def _function_summary(func: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "name",
        "entry",
        "namespace",
        "signature",
        "body_size",
        "caller_count",
        "callee_count",
        "artifact_type",
        "block",
        "is_thunk",
        "is_external",
        "is_inline",
    )
    summary = {key: func.get(key) for key in keys if key in func}
    summary["function_identity"] = normalize_function_identity(func, source="headless")
    return summary


def _xref_context(func: dict[str, Any]) -> dict[str, Any]:
    refs = func.get("sample_xrefs", [])
    if not isinstance(refs, list):
        refs = []
    callers = []
    references = []
    for ref in refs[:20]:
        if not isinstance(ref, dict):
            continue
        ref_summary = {
            "from_address": ref.get("from_address"),
            "from_function": ref.get("from_function"),
            "ref_type": ref.get("ref_type"),
        }
        references.append(ref_summary)
        if ref.get("from_function"):
            callers.append(ref_summary)
    return {
        "caller_count": func.get("caller_count", 0),
        "callee_count": func.get("callee_count", 0),
        "sample_callers": callers[:5],
        "sample_references": references[:5],
    }


def _load_required_json(path: Path, label: str) -> dict[str, Any]:
    if not path.exists():
        raise RuntimeError(f"missing {label}: {path}")
    return _load_json(path)


def _load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError(f"failed to parse JSON at {path}: {exc}") from exc


def _parse_int(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if not text:
        return None
    if text.startswith("0x") or text.startswith("0X"):
        try:
            return int(text, 16)
        except ValueError:
            return None
    try:
        return int(text, 16)
    except ValueError:
        try:
            return int(text, 10)
        except ValueError:
            return None


def _hex(value: int | None) -> str | None:
    return None if value is None else f"0x{value:x}"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
