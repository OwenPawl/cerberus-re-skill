"""Rank Frida capture paths when daemon attach is protected."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cerberus_re_skill.core.config import cfg
from cerberus_re_skill.core.utils import utc_now


FRIDA_CAPTURE_PLAN_SCHEMA = "ghidra-re.frida-capture-plan.v1"
BLOCKED_LIVE_ATTACH_CLASSIFICATIONS = {
    "protected_daemon_attach_blocked",
    "daemon_attach_timeout_or_blocked",
}
ACTION_INVOCATION_DOMAIN = "action_invocation_path"
XPC_SETUP_DOMAIN = "xpc_setup_path"
METADATA_REFRESH_DOMAIN = "metadata_refresh"
CONTROLLED_FRAMEWORK_DOMAIN = "controlled_private_framework"


def build_frida_capture_plan(
    *,
    live_attach: list[str] | None = None,
    runtime_recheck: list[str] | None = None,
    diagnostics: list[str] | None = None,
    enriched_runtime: list[str] | None = None,
    output: str | Path | None = None,
    markdown_output: str | Path | None = None,
) -> dict[str, Any]:
    """Merge Frida evidence and choose the least-surprising next capture path."""
    live_items = [_summarize_live_attach(item) for item in _load_mapped_items(live_attach or [], "live-attach")]
    runtime_items = [_summarize_runtime_recheck(item) for item in _load_mapped_items(runtime_recheck or [], "runtime-recheck")]
    diagnostic_items = [_summarize_diagnostics(item) for item in _load_mapped_items(diagnostics or [], "diagnostics")]
    enriched_items = [_summarize_enriched_runtime(item) for item in _load_mapped_items(enriched_runtime or [], "enriched-runtime")]

    if not any([live_items, runtime_items, diagnostic_items, enriched_items]):
        raise RuntimeError("at least one Frida evidence artifact is required")

    recommendation = _recommend(live_items, runtime_items, diagnostic_items)
    summary = {
        "live_attach_count": len(live_items),
        "protected_daemon_count": sum(
            1 for item in live_items if item["classification"] in BLOCKED_LIVE_ATTACH_CLASSIFICATIONS
        ),
        "controlled_recheck_count": len(runtime_items),
        "controlled_passed_count": sum(1 for item in runtime_items if item["classification"] == "controlled_runtime_capture_available"),
        "controlled_runtime_hit_count": sum(int(item.get("runtime_hit_count") or 0) for item in runtime_items),
        "controlled_action_invocation_count": sum(
            1
            for item in runtime_items
            if item["classification"] == "controlled_runtime_capture_available"
            and item.get("controlled_domain") == ACTION_INVOCATION_DOMAIN
        ),
        "controlled_xpc_setup_count": sum(
            1
            for item in runtime_items
            if item["classification"] == "controlled_runtime_capture_available"
            and item.get("controlled_domain") == XPC_SETUP_DOMAIN
        ),
        "readiness_observed_count": sum(1 for item in runtime_items if item.get("readiness_observed")),
        "delayed_helper_count": sum(1 for item in runtime_items if item.get("delayed_helper")),
        "timing_guard_count": sum(1 for item in runtime_items if item.get("timing_guard")),
        "controlled_domains": sorted({str(item.get("controlled_domain")) for item in runtime_items if item.get("controlled_domain")}),
        "controlled_symbols": sorted({str(item.get("symbol")) for item in runtime_items if item.get("symbol")}),
        "diagnostic_count": len(diagnostic_items),
        "host_runtime_attach_blocked_count": sum(1 for item in diagnostic_items if item.get("runtime_attach_blocked")),
        "enriched_runtime_count": len(enriched_items),
        "enriched_matched_function_count": sum(int(item.get("matched_function_count") or 0) for item in enriched_items),
        "recommended_capture_path": recommendation["path"],
        "recommended_controlled_domain": recommendation.get("controlled_domain", ""),
    }
    summary["controlled_run_path_count"] = summary["controlled_action_invocation_count"]
    report = {
        "schema": FRIDA_CAPTURE_PLAN_SCHEMA,
        "ok": True,
        "created_at": utc_now(),
        "summary": summary,
        "recommendation": recommendation,
        "live_attach": live_items,
        "runtime_recheck": runtime_items,
        "diagnostics": diagnostic_items,
        "enriched_runtime": enriched_items,
        "friction": _friction(live_items, runtime_items, diagnostic_items),
    }

    out_path = Path(output) if output else cfg.exports_dir / "frida_capture_plan.json"
    md_path = Path(markdown_output) if markdown_output else cfg.exports_dir / "frida_capture_plan.md"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    md_path.write_text(_render_markdown(report), encoding="utf-8")
    return {
        "ok": True,
        "output": str(out_path),
        "markdown_output": str(md_path),
        **summary,
    }


def _load_mapped_items(specs: list[str], label: str) -> list[dict[str, Any]]:
    items = []
    for spec in specs:
        item_id, path_text = _split_mapping(spec, label)
        path = Path(path_text)
        items.append({"id": item_id, "path": str(path), "payload": _load_json(path, label)})
    return items


def _split_mapping(spec: str, label: str) -> tuple[str, str]:
    if "=" not in spec:
        raise RuntimeError(f"{label} must be formatted as id=path: {spec}")
    left, right = spec.split("=", 1)
    left = left.strip()
    right = right.strip()
    if not left or not right:
        raise RuntimeError(f"{label} must include id and path: {spec}")
    return left, right


def _summarize_live_attach(item: dict[str, Any]) -> dict[str, Any]:
    payload = item["payload"]
    errors = [str(error) for error in payload.get("errors", []) if error]
    error_text = "\n".join(errors).lower()
    protection_blocked = "protection failure" in error_text or "thread_create" in error_text
    status_text = str(payload.get("status") or "").lower()
    timeout_blocked = "timeout" in error_text or "timed out" in error_text or "attach_timeout" in status_text
    classification = "protected_daemon_attach_blocked" if protection_blocked else "live_attach_available"
    if not payload.get("ok") and timeout_blocked and not protection_blocked:
        classification = "daemon_attach_timeout_or_blocked"
    elif not payload.get("ok") and not protection_blocked:
        classification = "live_attach_failed"
    selectors = [str(selector) for selector in payload.get("selectors", []) if selector]
    class_name = str(payload.get("class_name") or "")
    symbols = [f"-[{class_name} {selector}]" for selector in selectors if class_name]
    if payload.get("symbol"):
        symbols.append(str(payload["symbol"]))
    return {
        "id": item["id"],
        "path": item["path"],
        "classification": classification,
        "ok": bool(payload.get("ok")),
        "status": str(payload.get("status") or ""),
        "target_pid": payload.get("target_pid"),
        "target_name": payload.get("target_name") or payload.get("process_name") or "",
        "symbols": sorted(set(symbols)),
        "hit_count": int(payload.get("hit_count") or 0),
        "installed_hook_count": int(payload.get("installed_hook_count") or 0),
        "missing_hook_count": int(payload.get("missing_hook_count") or 0),
        "errors": errors,
    }


def _summarize_runtime_recheck(item: dict[str, Any]) -> dict[str, Any]:
    payload = item["payload"]
    hit_count = int(payload.get("runtime_hit_count") or payload.get("hit_count") or 0)
    status = str(payload.get("status") or "")
    symbol = str(payload.get("symbol") or "")
    target = str(payload.get("target") or "")
    target_args = payload.get("target_args", []) if isinstance(payload.get("target_args"), list) else []
    event_summary = payload.get("frida_event_summary", {}) if isinstance(payload.get("frida_event_summary"), dict) else {}
    delayed_helper = _has_delay_arg(target_args)
    readiness_observed = bool(payload.get("readiness_observed"))
    installed_count = int(event_summary.get("installed_count") or payload.get("installed_hook_count") or 0)
    if status == "passed" and hit_count > 0:
        classification = "controlled_runtime_capture_available"
    elif status == "passed":
        classification = "controlled_runtime_no_hits"
    else:
        classification = "controlled_runtime_blocked"
    return {
        "id": item["id"],
        "path": item["path"],
        "classification": classification,
        "ok": bool(payload.get("ok")),
        "status": status,
        "target": target,
        "target_args": target_args,
        "symbol": symbol,
        "controlled_domain": _controlled_domain(symbol=symbol, target=target, target_args=target_args),
        "runtime_hit_count": hit_count,
        "runtime_hits_json": str(payload.get("runtime_hits_json") or ""),
        "readiness_observed": readiness_observed,
        "delayed_helper": delayed_helper,
        "timing_guard": readiness_observed or delayed_helper or installed_count > 0,
        "frida_helper_crashed": bool(payload.get("frida_helper_crashed")),
        "frida_event_summary": event_summary,
    }


def _summarize_diagnostics(item: dict[str, Any]) -> dict[str, Any]:
    payload = item["payload"]
    return {
        "id": item["id"],
        "path": item["path"],
        "ok": bool(payload.get("ok")),
        "status": str(payload.get("status") or ""),
        "target": str(payload.get("target") or ""),
        "runtime_attach_blocked": bool(payload.get("runtime_attach_blocked")),
        "boot_args": payload.get("boot_args", {}) if isinstance(payload.get("boot_args"), dict) else {},
    }


def _summarize_enriched_runtime(item: dict[str, Any]) -> dict[str, Any]:
    payload = item["payload"]
    enrichment = payload.get("enrichment", {}) if isinstance(payload.get("enrichment"), dict) else {}
    return {
        "id": item["id"],
        "path": item["path"],
        "hit_count": int(payload.get("hit_count") or 0),
        "enriched": bool(payload.get("enriched")),
        "project": enrichment.get("project"),
        "program": enrichment.get("program"),
        "matched_function_count": int(enrichment.get("matched_function_count") or 0),
        "slide_confidence": enrichment.get("slide_confidence"),
    }


def _recommend(
    live_items: list[dict[str, Any]],
    runtime_items: list[dict[str, Any]],
    diagnostic_items: list[dict[str, Any]],
) -> dict[str, Any]:
    protected = any(item["classification"] in BLOCKED_LIVE_ATTACH_CLASSIFICATIONS for item in live_items)
    controlled = [item for item in runtime_items if item["classification"] == "controlled_runtime_capture_available"]
    controlled_action_invocation = [item for item in controlled if item.get("controlled_domain") == ACTION_INVOCATION_DOMAIN]
    host_blocked = any(item.get("runtime_attach_blocked") for item in diagnostic_items)
    if protected and controlled_action_invocation:
        return {
            "path": "controlled_helper_runtime_recheck",
            "controlled_domain": ACTION_INVOCATION_DOMAIN,
            "confidence": "high",
            "rationale": [
                "The live daemon attach is protected by host policy.",
                "A controlled helper captured Frida call/return hits on an action invocation path.",
            ],
            "next_steps": [
                "Use controlled invocation-path helpers for Frida evidence on invocation surfaces.",
                "Keep LLDB for protected daemon observe-only breakpoints.",
                "Do not retry daemon Frida attach unless host policy or target signing changes.",
            ],
        }
    if protected and controlled:
        return {
            "path": "controlled_helper_runtime_recheck",
            "controlled_domain": controlled[0].get("controlled_domain", CONTROLLED_FRAMEWORK_DOMAIN),
            "confidence": "high",
            "rationale": [
                "The live daemon attach is protected by host policy.",
                "A controlled helper captured Frida runtime hits for the same private-framework setup path.",
            ],
            "next_steps": [
                "Use the controlled helper for Frida call/return evidence.",
                "Keep LLDB for protected daemon observe-only breakpoints.",
                "Do not retry daemon Frida attach unless host policy or target signing changes.",
            ],
        }
    if controlled:
        return {
            "path": "controlled_helper_runtime_recheck",
            "controlled_domain": controlled[0].get("controlled_domain", CONTROLLED_FRAMEWORK_DOMAIN),
            "confidence": "medium",
            "rationale": ["A controlled helper captured Frida runtime hits."],
            "next_steps": ["Prefer the controlled helper when live attach is flaky or unnecessary."],
        }
    if host_blocked or protected:
        return {
            "path": "diagnose_host_policy_before_runtime_attach",
            "confidence": "medium",
            "rationale": ["Frida attach is blocked and no controlled runtime fallback has produced hits yet."],
            "next_steps": ["Run Frida diagnostics and build a controlled helper before more live attach attempts."],
        }
    return {
        "path": "retry_live_attach_with_bounded_timeout",
        "controlled_domain": "",
        "confidence": "low",
        "rationale": ["No protected-daemon blocker or successful controlled fallback was present."],
        "next_steps": ["Retry only with bounded timeouts and preserve raw attach errors."],
    }


def _controlled_domain(*, symbol: str, target: str, target_args: list[Any]) -> str:
    text = " ".join([symbol, target, *[str(arg) for arg in target_args]]).lower()
    if any(
        token in text
        for token in ["invokeaction", "performaction", "executeaction", "startaction", "runwithinput"]
    ):
        return ACTION_INVOCATION_DOMAIN
    if "unsafesetupxpcconnection" in text or "xpc" in text:
        return XPC_SETUP_DOMAIN
    if any(token in text for token in ["updatecatalog", "reindex", "spotlight", "metadata"]):
        return METADATA_REFRESH_DOMAIN
    return CONTROLLED_FRAMEWORK_DOMAIN


def _has_delay_arg(target_args: list[Any]) -> bool:
    for arg in target_args:
        text = str(arg).lower()
        if "delay" in text or "readiness" in text:
            return True
    return False


def _friction(
    live_items: list[dict[str, Any]],
    runtime_items: list[dict[str, Any]],
    diagnostic_items: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for item in live_items:
        if item["classification"] in BLOCKED_LIVE_ATTACH_CLASSIFICATIONS:
            items.append({"kind": "frida_attach_protection", "id": item["id"], "errors": item["errors"]})
        elif item["classification"] == "live_attach_failed":
            items.append({"kind": "frida_live_attach_failed", "id": item["id"], "errors": item["errors"]})
    for item in runtime_items:
        if item.get("frida_helper_crashed"):
            items.append({"kind": "frida_helper_crashed", "id": item["id"]})
        if item["classification"] == "controlled_runtime_no_hits":
            items.append({"kind": "controlled_runtime_no_hits", "id": item["id"], "symbol": item.get("symbol")})
    for item in diagnostic_items:
        if item.get("runtime_attach_blocked"):
            items.append({"kind": "frida_host_policy_blocked", "id": item["id"], "status": item.get("status")})
    return items


def _render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# Frida Capture Plan",
        "",
        f"- Schema: `{report['schema']}`",
        f"- Live attach artifacts: {summary['live_attach_count']}",
        f"- Protected daemon artifacts: {summary['protected_daemon_count']}",
        f"- Controlled rechecks: {summary['controlled_recheck_count']}",
        f"- Controlled runtime hits: {summary['controlled_runtime_hit_count']}",
        f"- Controlled action invocation helpers: {summary.get('controlled_action_invocation_count', 0)}",
        f"- Timing guards: {summary.get('timing_guard_count', 0)}",
        f"- Recommended path: `{summary['recommended_capture_path']}`",
        f"- Recommended controlled domain: `{summary.get('recommended_controlled_domain', '')}`",
        "",
        "## Recommendation",
        "",
        f"- Path: `{report['recommendation']['path']}`",
        f"- Confidence: `{report['recommendation']['confidence']}`",
    ]
    for item in report["recommendation"].get("rationale", []):
        lines.append(f"- Rationale: {item}")
    for item in report["recommendation"].get("next_steps", []):
        lines.append(f"- Next: {item}")
    lines += ["", "## Evidence", ""]
    for item in report["live_attach"]:
        lines.append(f"- Live `{item['id']}`: `{item['classification']}`, hits={item['hit_count']}, pid={item.get('target_pid')}")
    for item in report["runtime_recheck"]:
        lines.append(
            f"- Controlled `{item['id']}`: `{item['classification']}`, hits={item['runtime_hit_count']}, "
            f"domain=`{item.get('controlled_domain')}`, timing_guard={item.get('timing_guard')}, "
            f"symbol=`{item.get('symbol')}`"
        )
    for item in report["enriched_runtime"]:
        lines.append(
            f"- Enriched `{item['id']}`: matched={item['matched_function_count']}/{item['hit_count']}, "
            f"target={item.get('project')}:{item.get('program')}, confidence={item.get('slide_confidence')}"
        )
    return "\n".join(lines).rstrip() + "\n"


def _load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RuntimeError(f"{label} not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{label} is not valid JSON: {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"{label} must be a JSON object: {path}")
    return payload
