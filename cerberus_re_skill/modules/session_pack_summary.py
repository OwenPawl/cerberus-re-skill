"""Generic artifact summary extraction for session-pack reports."""

from __future__ import annotations

from pathlib import Path
from typing import Any


def _artifact_summary(path: Path, payload: Any, *, kind: str) -> dict[str, Any]:
    if isinstance(payload, dict):
        summary: dict[str, Any] = {
            "keys": sorted(str(k) for k in payload.keys())[:16],
            "ok": payload.get("ok"),
            "status": payload.get("status"),
        }
        if payload.get("schema") == "ghidra-re.runtime-hits.v1":
            hits = payload.get("hits") if isinstance(payload.get("hits"), list) else []
            symbols = sorted({_hit_symbol(hit) for hit in hits if _hit_symbol(hit)})
            enrichment = payload.get("enrichment") if isinstance(payload.get("enrichment"), dict) else {}
            summary.update(
                {
                    "hit_count": payload.get("hit_count", len(hits)),
                    "tools": payload.get("tools", sorted({str(hit.get("tool")) for hit in hits if isinstance(hit, dict) and hit.get("tool")})),
                    "enriched": bool(payload.get("enriched")),
                    "matched_function_count": enrichment.get("matched_function_count"),
                    "slide_confidence": enrichment.get("slide_confidence"),
                    "private_api_symbols": [s for s in symbols if _looks_private_api_symbol(s)],
                    "symbols": symbols[:12],
                }
            )
        elif kind == "instrumentation":
            event_summary = payload.get("frida_event_summary") if isinstance(payload.get("frida_event_summary"), dict) else {}
            symbol = str(payload.get("symbol") or "")
            selectors = payload.get("selectors") if isinstance(payload.get("selectors"), list) else []
            class_name = str(payload.get("class_name") or "")
            selector_installed = [
                str(value)
                for value in event_summary.get("selector_installed", [])
                if isinstance(value, str) and value
            ]
            symbols = [symbol] if symbol else [f"-[{class_name} {selector}]" for selector in selectors if class_name and selector]
            symbols.extend(selector_installed)
            summary.update(
                {
                    "symbol": symbol,
                    "hook_mode": payload.get("hook_mode"),
                    "attach_pid": payload.get("attach_pid"),
                    "runtime_hit_count": payload.get("runtime_hit_count", payload.get("hit_count")),
                    "runtime_hits_json": payload.get("runtime_hits_json"),
                    "readiness_observed": payload.get("readiness_observed"),
                    "frida_event_summary": event_summary,
                    "installed_hook_count": _frida_installed_hook_count(event_summary, payload.get("installed_hook_count")),
                    "missing_hook_count": payload.get("missing_hook_count"),
                    "private_api_symbols": [s for s in symbols if _looks_private_api_symbol(s)],
                    "friction": _frida_friction(payload),
                }
            )
        elif kind == "runtime-status":
            trace = payload.get("trace") if isinstance(payload.get("trace"), dict) else {}
            symbols = [str(value) for value in trace.get("symbols_requested", []) if isinstance(value, str) and value]
            summary.update(
                {
                    "trace_status": payload.get("trace_status"),
                    "hit_count": payload.get("hit_count"),
                    "runtime_hit_count": payload.get("runtime_hit_count"),
                    "matched_function_count": payload.get("matched_function_count"),
                    "breakpoint_count": trace.get("breakpoint_count"),
                    "resolved_breakpoint_locations": trace.get("resolved_breakpoint_locations"),
                    "private_api_symbols": [s for s in symbols if _looks_private_api_symbol(s)],
                    "friction": _lldb_status_friction(payload),
                }
            )
        elif kind == "xpc-graph":
            edges = payload.get("edges", [])
            summary_obj = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
            summary.update({"edge_count": summary_obj.get("edge_count", len(edges) if isinstance(edges, list) else None)})
        elif kind == "xpc-surface":
            summary_obj = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
            services = payload.get("service_names") if isinstance(payload.get("service_names"), list) else []
            summary.update(
                {
                    "service_count": summary_obj.get("service_count", len(services)),
                    "method_count": summary_obj.get("method_count"),
                    "missing_input_count": payload.get("missing_input_count"),
                }
            )
        elif kind in {
            "xpc-interface-dossier",
            "xpc-interface-factory",
            "xpc-method-inventory",
            "xpc-safe-read-dossier",
            "xpc-allowed-class-focus",
            "xpc-completion-shapes",
            "nsxpc-interface-config",
            "xpc-connection-evidence",
        }:
            summary.update(_generic_counts(payload))
        elif kind == "frida-capture-plan":
            recommended = payload.get("recommended_capture_path")
            plans = payload.get("plans") if isinstance(payload.get("plans"), list) else []
            summary.update(
                {
                    "recommended_capture_path": recommended,
                    "plan_count": len(plans),
                    "friction": _frida_friction(payload),
                }
            )
        elif kind == "frida-diagnostics":
            blockers = payload.get("blockers") if isinstance(payload.get("blockers"), list) else []
            summary.update(
                {
                    "blocker_count": len(blockers),
                    "friction": [{"kind": "frida_blocker", **item} for item in blockers if isinstance(item, dict)],
                }
            )
        elif kind == "static":
            summary.update(_generic_counts(payload))
        return {k: v for k, v in summary.items() if v is not None}
    text = str(payload)
    return {
        "line_count": text.count("\n") + (1 if text else 0),
        "heading_count": sum(1 for line in text.splitlines() if line.startswith("#")),
        "mentions_friction": "friction" in text.lower() or "blocked" in text.lower(),
        "private_api_symbols": sorted({symbol for symbol in _extract_symbol_like_tokens(text) if _looks_private_api_symbol(symbol)}),
    }


def _generic_counts(payload: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key in (
        "function_count",
        "function_inventory_count",
        "class_count",
        "selector_count",
        "method_count",
        "interface_count",
        "service_count",
        "connection_count",
        "completion_method_count",
        "reply_shape_count",
        "allowed_class_count",
        "compile_ok_count",
        "run_ok_count",
        "blocked_count",
    ):
        if key in payload:
            result[key] = payload[key]
    for list_key, count_key in (
        ("functions", "function_count"),
        ("classes", "class_count"),
        ("selectors", "selector_count"),
        ("methods", "method_count"),
        ("interfaces", "interface_count"),
        ("connections", "connection_count"),
        ("reply_shapes", "reply_shape_count"),
    ):
        value = payload.get(list_key)
        if isinstance(value, list):
            result.setdefault(count_key, len(value))
    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    for key, value in summary.items():
        if key.endswith("_count") or key in {"top_interface", "top_service", "top_selector"}:
            result.setdefault(str(key), value)
    return result


def _hit_symbol(hit: Any) -> str:
    if not isinstance(hit, dict):
        return ""
    for key in ("symbol", "requested_symbol", "target_symbol", "selector"):
        value = hit.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def _frida_installed_hook_count(event_summary: dict[str, Any], fallback: Any = None) -> int:
    explicit = int(fallback or 0)
    installed = _event_count(event_summary, "installed_count", "installed_symbols")
    native_installed = _event_count(event_summary, "native_installed_count", "native_installed")
    selector_installed = _event_count(event_summary, "selector_installed_count", "selector_installed")
    return explicit + installed + native_installed + selector_installed


def _event_count(event_summary: dict[str, Any], count_key: str, list_key: str) -> int:
    values = event_summary.get(list_key)
    if isinstance(values, list) and values:
        return len(values)
    return int(event_summary.get(count_key) or 0)


def _frida_friction(payload: dict[str, Any]) -> list[dict[str, Any]]:
    friction: list[dict[str, Any]] = []
    status = str(payload.get("status") or "")
    if "blocked" in status or "failed" in status:
        friction.append({"kind": "frida_status", "status": status})
    event_summary = payload.get("frida_event_summary") if isinstance(payload.get("frida_event_summary"), dict) else {}
    for key in ("missing_class_count", "missing_method_count", "native_missing_count"):
        count = int(event_summary.get(key) or 0)
        if count:
            friction.append({"kind": key, "count": count})
    return friction


def _lldb_status_friction(payload: dict[str, Any]) -> list[dict[str, Any]]:
    trace_status = str(payload.get("trace_status") or "")
    if trace_status and trace_status not in {"ok", "passed"}:
        return [{"kind": "lldb_trace_status", "status": trace_status}]
    return []


def _looks_private_api_symbol(symbol: str) -> bool:
    text = str(symbol)
    if not text:
        return False
    if text.startswith("_") and not text.startswith("__"):
        return True
    return text.startswith("-[") or text.startswith("+[")


def _extract_symbol_like_tokens(text: str) -> set[str]:
    tokens: set[str] = set()
    for raw in text.replace("`", " ").replace(",", " ").split():
        token = raw.strip()
        if token.startswith(("-[", "+[", "_")):
            tokens.add(token)
    return tokens
