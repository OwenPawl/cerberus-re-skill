"""Shared runtime-hit schema for LLDB and Frida observations."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cerberus_re_skill.core.utils import utc_now


RUNTIME_HIT_SCHEMA = "ghidra-re.runtime-hit.v1"
RUNTIME_HITS_BUNDLE_SCHEMA = "ghidra-re.runtime-hits.v1"


def normalize_lldb_trace_hits(
    trace: dict[str, Any],
    *,
    project: str,
    program: str,
    source_artifact: str | Path = "",
) -> list[dict[str, Any]]:
    """Convert a raw ``ghidra_lldb_trace`` payload into shared runtime hits."""
    raw_hits = trace.get("hits", [])
    if not isinstance(raw_hits, list):
        return []
    hits: list[dict[str, Any]] = []
    for index, raw in enumerate(raw_hits):
        if not isinstance(raw, dict):
            continue
        registers = _dict(raw.get("registers"))
        args = _extract_lldb_args(raw, registers)
        symbol = _str(raw.get("symbol") or raw.get("breakpoint") or raw.get("target"))
        objc = {
            "self_ptr": _str(raw.get("self_ptr") or args.get("x0", "")),
            "self_class": _str(raw.get("self_class") or raw.get("objc_isa") or ""),
            "selector": _str(raw.get("selector") or raw.get("objc_selector") or ""),
        }
        hits.append(
            {
                "schema": RUNTIME_HIT_SCHEMA,
                "tool": "lldb",
                "event_type": "breakpoint-hit",
                "hit_index": _int(raw.get("hit_index"), index),
                "timestamp": _str(raw.get("timestamp") or raw.get("created_at") or ""),
                "target": {
                    "project_name": project,
                    "program_name": program,
                    "symbol": symbol,
                    "module": _str(raw.get("module") or raw.get("image") or ""),
                },
                "runtime": {
                    "pc": _str(raw.get("pc") or raw.get("runtime_pc") or ""),
                    "static_address": _str(raw.get("ghidra_addr") or raw.get("static_address") or ""),
                    "slide": _str(raw.get("slide") or trace.get("slide") or ""),
                    "return_address": _str(raw.get("return_address") or ""),
                },
                "args": args,
                "objc": objc,
                "registers": registers,
                "backtrace": raw.get("backtrace", []) if isinstance(raw.get("backtrace"), list) else [],
                "source": {"artifact": str(source_artifact), "raw_index": index},
                "raw": raw,
            }
        )
    return hits


def normalize_frida_console_hits(
    text: str,
    *,
    project: str = "",
    program: str = "",
    source_artifact: str | Path = "",
) -> list[dict[str, Any]]:
    """Parse generated Frida console events into shared runtime hits."""
    prefixes = {
        "GHIDRA_FRIDA_HIT": "objc-call",
        "GHIDRA_FRIDA_RETURN": "objc-return",
        "GHIDRA_FRIDA_HEAP_OBJECT": "objc-heap-object",
    }
    hits: list[dict[str, Any]] = []
    for line_index, raw_line in enumerate(str(text or "").splitlines()):
        line = raw_line.strip()
        for prefix, event_type in prefixes.items():
            marker = prefix + " "
            if not line.startswith(marker):
                continue
            try:
                payload = json.loads(line[len(marker):])
            except json.JSONDecodeError:
                continue
            if not isinstance(payload, dict):
                continue
            hit = dict(payload)
            hit.setdefault("schema", RUNTIME_HIT_SCHEMA)
            hit.setdefault("tool", "frida")
            hit.setdefault("event_type", event_type)
            target = _dict(hit.get("target"))
            if project:
                target.setdefault("project_name", project)
            if program:
                target.setdefault("program_name", program)
            if target:
                hit["target"] = target
            runtime = _dict(hit.get("runtime"))
            if hit.get("pc"):
                runtime.setdefault("pc", _str(hit.get("pc")))
            if hit.get("return_address"):
                runtime.setdefault("return_address", _str(hit.get("return_address")))
            if runtime:
                hit["runtime"] = runtime
            hit["source"] = {"artifact": str(source_artifact), "raw_line": line_index, "prefix": prefix}
            hits.append(hit)
            break
    return hits


def write_runtime_hits_artifact(
    path: str | Path,
    *,
    project: str,
    program: str,
    hits: list[dict[str, Any]],
    source: str | Path = "",
) -> dict[str, Any]:
    """Write a runtime-hit bundle and return the payload."""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema": RUNTIME_HITS_BUNDLE_SCHEMA,
        "created_at": utc_now(),
        "project_name": project,
        "program_name": program,
        "source": str(source),
        "hit_count": len(hits),
        "tools": sorted({str(hit.get("tool", "")) for hit in hits if hit.get("tool")}),
        "hits": hits,
    }
    out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return payload


def _extract_lldb_args(raw: dict[str, Any], registers: dict[str, Any]) -> dict[str, str]:
    explicit = _dict(raw.get("args"))
    args: dict[str, str] = {str(k): _str(v) for k, v in explicit.items()}
    for index in range(8):
        reg = f"x{index}"
        value = raw.get(reg, registers.get(reg, ""))
        if value not in (None, ""):
            args.setdefault(reg, _str(value))
    return args


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _str(value: Any) -> str:
    return "" if value is None else str(value)


def _int(value: Any, default: int) -> int:
    return value if isinstance(value, int) else default
