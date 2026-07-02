"""Preflight LLDB breakpoint plans against static and live evidence."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from cerberus_re_skill.core.config import cfg
from cerberus_re_skill.core.utils import utc_now


BREAKPOINT_PLAN_PREFLIGHT_SCHEMA = "ghidra-re.breakpoint-plan-preflight.v1"


def build_breakpoint_plan_preflight(
    *,
    plan: str | Path,
    function_inventory: str | Path | None = None,
    lldb_symbols: str | Path | None = None,
    program_summary: str | Path | None = None,
    lldb_trace: str | Path | None = None,
    output: str | Path | None = None,
    markdown_output: str | Path | None = None,
) -> dict[str, Any]:
    """Classify planned breakpoints before or after a bounded LLDB run."""
    plan_path = Path(plan)
    plan_payload = _load_json(plan_path, "breakpoint plan")
    requested = _planned_symbols(plan_payload)
    if not requested:
        raise RuntimeError(f"breakpoint plan has no symbols: {plan_path}")

    inventory_path = Path(function_inventory) if function_inventory else None
    lldb_symbols_path = Path(lldb_symbols) if lldb_symbols else None
    program_summary_path = Path(program_summary) if program_summary else None
    trace_path = Path(lldb_trace) if lldb_trace else None

    inventory_payload = _load_json(inventory_path, "function inventory") if inventory_path else {}
    lldb_symbols_payload = _load_json(lldb_symbols_path, "LLDB symbols") if lldb_symbols_path else {}
    program_summary_payload = _load_json(program_summary_path, "program summary") if program_summary_path else {}
    trace_payload = _load_json(trace_path, "LLDB trace") if trace_path else {}

    inventory_index = _function_inventory_index(inventory_payload)
    lldb_symbol_index = _lldb_symbol_index(lldb_symbols_payload)
    trace_index = _lldb_trace_index(trace_payload)
    sidecar_provenance = _sidecar_provenance(program_summary_payload, lldb_symbols_payload)

    symbols = [
        _classify_symbol(
            item,
            inventory_index=inventory_index,
            lldb_symbol_index=lldb_symbol_index,
            trace_index=trace_index,
            lldb_symbols_payload=lldb_symbols_payload,
            sidecar_provenance=sidecar_provenance,
        )
        for item in requested
    ]
    summary = _summary(symbols, trace_payload, sidecar_provenance)
    report = {
        "schema": BREAKPOINT_PLAN_PREFLIGHT_SCHEMA,
        "ok": True,
        "created_at": utc_now(),
        "plan": str(plan_path),
        "inputs": {
            "function_inventory": str(inventory_path or ""),
            "lldb_symbols": str(lldb_symbols_path or ""),
            "program_summary": str(program_summary_path or ""),
            "lldb_trace": str(trace_path or ""),
            "lldb_symbols_binary_path": str(lldb_symbols_payload.get("binary_path") or ""),
            "program_summary_executable_path": str(
                program_summary_payload.get("executable_path")
                or program_summary_payload.get("source_image_path")
                or ""
            ),
        },
        "sidecar_provenance": sidecar_provenance,
        "summary": summary,
        "symbols": symbols,
        "recommendations": _recommendations(summary, symbols, sidecar_provenance),
    }

    out_path = Path(output) if output else cfg.exports_dir / "breakpoint_plan_preflight.json"
    md_path = Path(markdown_output) if markdown_output else cfg.exports_dir / "breakpoint_plan_preflight.md"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(_render_markdown(report), encoding="utf-8")
    return {
        "ok": True,
        "output": str(out_path),
        "markdown_output": str(md_path),
        **summary,
    }


def _load_json(path: Path | None, label: str) -> dict[str, Any]:
    if not path:
        return {}
    if not path.exists():
        raise RuntimeError(f"{label} does not exist: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError(f"{label} must be a JSON object: {path}")
    return payload


def _planned_symbols(plan_payload: dict[str, Any]) -> list[dict[str, Any]]:
    raw_symbols = plan_payload.get("symbols") if isinstance(plan_payload.get("symbols"), list) else []
    symbols: list[dict[str, Any]] = []
    for index, item in enumerate(raw_symbols):
        if isinstance(item, dict):
            symbol = str(item.get("symbol") or "").strip()
            if symbol:
                symbols.append(
                    {
                        "index": index,
                        "symbol": symbol,
                        "group": str(item.get("group") or ""),
                        "reason": str(item.get("reason") or ""),
                    }
                )
        elif isinstance(item, str) and item.strip():
            symbols.append({"index": index, "symbol": item.strip(), "group": "", "reason": ""})
    return symbols


def _function_inventory_index(payload: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    items = payload.get("functions") if isinstance(payload.get("functions"), list) else []
    index: dict[str, list[dict[str, Any]]] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "")
        if not name:
            continue
        for key in {name, _normalize_objc_symbol(name), _ghidra_objc_name(name)}:
            index.setdefault(key, []).append(item)
    return index


def _lldb_symbol_index(payload: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    index: dict[str, list[dict[str, Any]]] = {}
    for key, value in payload.items():
        if not isinstance(value, list):
            continue
        for item in value:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "")
            if not name:
                continue
            enriched = dict(item)
            enriched["section"] = key
            for name_key in {name, _normalize_objc_symbol(name), _ghidra_objc_name(name)}:
                index.setdefault(name_key, []).append(enriched)
    return index


def _lldb_trace_index(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    symbols = payload.get("symbols_requested") if isinstance(payload.get("symbols_requested"), list) else []
    breakpoints = payload.get("breakpoints") if isinstance(payload.get("breakpoints"), list) else []
    index: dict[str, dict[str, Any]] = {}
    for position, symbol in enumerate(symbols):
        if not isinstance(symbol, str) or not symbol:
            continue
        bp = breakpoints[position] if position < len(breakpoints) and isinstance(breakpoints[position], dict) else {}
        entry = {
            "requested_index": position,
            "breakpoint_id": bp.get("id"),
            "locations": _int(bp.get("locs")),
            "hits": _int(bp.get("hits")),
            "raw": str(bp.get("raw") or ""),
        }
        for key in {symbol, _normalize_objc_symbol(symbol), _ghidra_objc_name(symbol)}:
            index[key] = entry
    return index


def _classify_symbol(
    item: dict[str, Any],
    *,
    inventory_index: dict[str, list[dict[str, Any]]],
    lldb_symbol_index: dict[str, list[dict[str, Any]]],
    trace_index: dict[str, dict[str, Any]],
    lldb_symbols_payload: dict[str, Any],
    sidecar_provenance: dict[str, Any],
) -> dict[str, Any]:
    symbol = item["symbol"]
    keys = {symbol, _normalize_objc_symbol(symbol), _ghidra_objc_name(symbol)}
    inventory_matches = _matches(inventory_index, keys)
    lldb_matches = _matches(lldb_symbol_index, keys)
    trace = _first_trace(trace_index, keys)
    live_status = _live_status(trace)
    static_status = _static_status(inventory_matches, lldb_matches)
    warnings: list[str] = []
    if static_status == "lldb_sidecar_only" and live_status == "pending_live":
        warnings.append("sidecar_only_symbol_pending_in_live_process")
    if lldb_matches and not inventory_matches and _looks_stale_sidecar(lldb_symbols_payload):
        warnings.append("lldb_symbol_sidecar_source_may_be_stale")
    if lldb_matches and sidecar_provenance.get("status") == "mismatch":
        warnings.append("lldb_symbol_sidecar_path_mismatch")
    if inventory_matches and live_status == "resolved_live" and not int(trace.get("hits") or 0):
        warnings.append("resolved_no_hits_keep_symbol_improve_trigger")

    return {
        **item,
        "static_status": static_status,
        "live_status": live_status,
        "function_inventory_match_count": len(inventory_matches),
        "lldb_symbol_match_count": len(lldb_matches),
        "function_inventory_matches": [_source_summary(match) for match in inventory_matches[:6]],
        "lldb_symbol_matches": [_source_summary(match) for match in lldb_matches[:6]],
        "lldb_trace": trace,
        "warnings": warnings,
    }


def _matches(index: dict[str, list[dict[str, Any]]], keys: set[str]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str]] = set()
    matches: list[dict[str, Any]] = []
    for key in keys:
        for item in index.get(key, []):
            identity = (str(item.get("name") or ""), str(item.get("address") or item.get("entry") or item.get("id") or ""))
            if identity in seen:
                continue
            seen.add(identity)
            matches.append(item)
    return matches


def _first_trace(index: dict[str, dict[str, Any]], keys: set[str]) -> dict[str, Any]:
    for key in keys:
        if key in index:
            return dict(index[key])
    return {}


def _live_status(trace: dict[str, Any]) -> str:
    if not trace:
        return "not_replayed"
    return "resolved_live" if int(trace.get("locations") or 0) > 0 else "pending_live"


def _static_status(inventory_matches: list[dict[str, Any]], lldb_matches: list[dict[str, Any]]) -> str:
    if inventory_matches and lldb_matches:
        return "function_inventory_and_lldb_symbol"
    if inventory_matches:
        return "function_inventory_only"
    if lldb_matches:
        return "lldb_sidecar_only"
    return "missing_static"


def _summary(
    symbols: list[dict[str, Any]],
    trace_payload: dict[str, Any],
    sidecar_provenance: dict[str, Any],
) -> dict[str, Any]:
    resolved_live = sum(1 for item in symbols if item["live_status"] == "resolved_live")
    pending_live = sum(1 for item in symbols if item["live_status"] == "pending_live")
    hit_count = int(trace_payload.get("hit_count") or 0)
    return {
        "symbol_count": len(symbols),
        "function_inventory_match_count": sum(1 for item in symbols if item["function_inventory_match_count"]),
        "lldb_symbol_match_count": sum(1 for item in symbols if item["lldb_symbol_match_count"]),
        "missing_static_count": sum(1 for item in symbols if item["static_status"] == "missing_static"),
        "sidecar_only_count": sum(1 for item in symbols if item["static_status"] == "lldb_sidecar_only"),
        "sidecar_only_live_pending_count": sum(
            1
            for item in symbols
            if item["static_status"] == "lldb_sidecar_only" and item["live_status"] == "pending_live"
        ),
        "resolved_live_count": resolved_live,
        "pending_live_count": pending_live,
        "not_replayed_count": sum(1 for item in symbols if item["live_status"] == "not_replayed"),
        "hit_count": hit_count,
        "resolved_no_hit_count": resolved_live if resolved_live and hit_count == 0 else 0,
        "warning_count": sum(len(item["warnings"]) for item in symbols),
        "sidecar_provenance_mismatch_count": 1 if sidecar_provenance.get("status") == "mismatch" else 0,
        "sidecar_provenance_warning_count": len(sidecar_provenance.get("warnings") or []),
    }


def _recommendations(
    summary: dict[str, Any],
    symbols: list[dict[str, Any]],
    sidecar_provenance: dict[str, Any],
) -> list[str]:
    recommendations: list[str] = []
    if sidecar_provenance.get("status") == "mismatch":
        recommendations.append(
            "Regenerate LLDB symbols from the same executable path recorded in program_summary.json before trusting sidecar-backed matches."
        )
    if summary["sidecar_only_live_pending_count"]:
        recommendations.append(
            "Regenerate or qualify LLDB symbol sidecars against the current dyld-backed image before trusting sidecar-only breakpoint names."
        )
    if summary["pending_live_count"]:
        pending = [item["symbol"] for item in symbols if item["live_status"] == "pending_live"][:6]
        recommendations.append("Drop, gate, or replace live-pending breakpoints before classifying trigger depth: " + ", ".join(pending))
    if summary["resolved_no_hit_count"]:
        recommendations.append(
            "Keep resolved live breakpoints and invest in the owning subsystem trigger; the setup is good but the trigger source was insufficient."
        )
    if summary["missing_static_count"]:
        recommendations.append("Review missing-static symbols before replay; they may be typos, stale selectors, or framework-version drift.")
    if not recommendations:
        recommendations.append("Breakpoint plan preflight is clean; proceed with bounded LLDB validation.")
    return recommendations


def _render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# Breakpoint Plan Preflight",
        "",
        f"- Plan: `{report['plan']}`",
        f"- Symbols: {summary['symbol_count']}",
        f"- Function-inventory matches: {summary['function_inventory_match_count']}",
        f"- LLDB sidecar matches: {summary['lldb_symbol_match_count']}",
        f"- Resolved live: {summary['resolved_live_count']}",
        f"- Pending live: {summary['pending_live_count']}",
        f"- Resolved/no-hit count: {summary['resolved_no_hit_count']}",
        f"- Sidecar-only live-pending: {summary['sidecar_only_live_pending_count']}",
        f"- Sidecar provenance: {report['sidecar_provenance'].get('status', 'unknown')}",
        "",
        "## Recommendations",
        "",
    ]
    lines.extend(f"- {item}" for item in report["recommendations"])
    lines.extend(["", "## Symbols", ""])
    for item in report["symbols"]:
        warnings = ", ".join(item["warnings"]) if item["warnings"] else "none"
        lines.append(
            f"- `{item['symbol']}`: static=`{item['static_status']}`, "
            f"live=`{item['live_status']}`, warnings={warnings}"
        )
    return "\n".join(lines).rstrip() + "\n"


def _source_summary(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": item.get("name"),
        "address": item.get("address") or item.get("entry") or item.get("id"),
        "section": item.get("section"),
        "namespace": item.get("namespace"),
    }


def _looks_stale_sidecar(payload: dict[str, Any]) -> bool:
    binary_path = str(payload.get("binary_path") or "")
    return "/sources/mac-image/" in binary_path or "/ghidra-projects/sources/" in binary_path


def _sidecar_provenance(program_summary: dict[str, Any], lldb_symbols: dict[str, Any]) -> dict[str, Any]:
    summary_path = str(program_summary.get("executable_path") or program_summary.get("source_image_path") or "")
    lldb_path = str(lldb_symbols.get("binary_path") or "")
    warnings: list[str] = []
    if not summary_path or not lldb_path:
        missing = []
        if not summary_path:
            missing.append("program_summary_executable_path")
        if not lldb_path:
            missing.append("lldb_symbols_binary_path")
        return {
            "status": "not_checked",
            "program_summary_executable_path": summary_path,
            "lldb_symbols_binary_path": lldb_path,
            "warnings": [f"missing_{item}" for item in missing],
        }

    summary_canonical = _canonical_path(summary_path)
    lldb_canonical = _canonical_path(lldb_path)
    status = "match" if summary_canonical == lldb_canonical else "mismatch"
    if status == "mismatch":
        warnings.append("lldb_symbols_binary_path_differs_from_program_summary")
    if _looks_stale_sidecar(lldb_symbols):
        warnings.append("lldb_symbols_binary_path_looks_like_sources_cache")
    return {
        "status": status,
        "program_summary_executable_path": summary_path,
        "lldb_symbols_binary_path": lldb_path,
        "program_summary_canonical_path": summary_canonical,
        "lldb_symbols_canonical_path": lldb_canonical,
        "warnings": warnings,
    }


def _canonical_path(value: str) -> str:
    try:
        return str(Path(value).expanduser().resolve(strict=False))
    except (OSError, RuntimeError):
        return value


_OBJC_METHOD_RE = re.compile(r"^([+-]\[[^ ]+) (.+)\]$")
_GHIDRA_OBJC_RE = re.compile(r"^([+-]\[[^_]+)_(.+)\]$")


def _ghidra_objc_name(symbol: str) -> str:
    match = _OBJC_METHOD_RE.match(symbol)
    if not match:
        return symbol
    return f"{match.group(1)}_{match.group(2)}]"


def _normalize_objc_symbol(symbol: str) -> str:
    match = _GHIDRA_OBJC_RE.match(symbol)
    if not match:
        return symbol
    return f"{match.group(1)} {match.group(2)}]"


def _int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0
