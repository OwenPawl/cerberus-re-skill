"""Session-pack report section builders."""

from __future__ import annotations

from pathlib import Path
from typing import Any

def _target_inventory(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    inventory: list[dict[str, Any]] = []
    for target in manifest.get("targets", []):
        if not isinstance(target, dict):
            continue
        candidates = []
        for candidate in target.get("path_candidates", []):
            candidate_text = str(candidate)
            if candidate_text.startswith("run-dir:"):
                exists = None
            else:
                exists = Path(candidate_text).expanduser().exists()
            candidates.append({"path": candidate_text, "exists": exists})
        inventory.append(
            {
                "id": target.get("id"),
                "kind": target.get("kind"),
                "project": target.get("project"),
                "program": target.get("program"),
                "path_candidates": candidates,
                "static_checks": target.get("static_checks", []),
                "runtime_checks": target.get("runtime_checks", []),
            }
        )
    return inventory


def _finding_summaries(sections: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for item in sections.get("private_api_invocation_evidence", []):
        summary = item.get("summary", {})
        symbols = summary.get("private_api_symbols") or summary.get("symbols") or []
        if symbols:
            findings.append(
                {
                    "target_id": item.get("target_id"),
                    "finding": "private API invocation evidence captured",
                    "symbols": symbols,
                    "artifact": item.get("path"),
                }
            )
    for item in sections.get("instrumentation_evidence", []):
        if item.get("kind") == "frida-capture-plan":
            findings.append(
                {
                    "target_id": item.get("target_id"),
                    "finding": "Frida capture fallback ranking available",
                    "classification": item.get("summary", {}).get("recommended_capture_path"),
                    "artifact": item.get("path"),
                }
            )
        if _has_classified_private_api_runtime_evidence(
            {"kind": item.get("kind"), "summary": item.get("summary", {})}
        ):
            findings.append(
                {
                    "target_id": item.get("target_id"),
                    "finding": "private API observe-only hook readiness captured",
                    "symbols": item.get("summary", {}).get("private_api_symbols", []),
                    "runtime_hit_count": item.get("summary", {}).get("runtime_hit_count"),
                    "artifact": item.get("path"),
                }
            )
    for item in sections.get("static_evidence", []):
        if item.get("kind") == "xpc-graph" and item.get("summary", {}).get("edge_count", 0):
            findings.append(
                {
                    "target_id": item.get("target_id"),
                    "finding": "XPC graph contains resolved cross-target edges",
                    "edge_count": item["summary"].get("edge_count"),
                    "artifact": item.get("path"),
                }
            )
    for item in sections.get("runtime_evidence", []):
        if item.get("kind") == "trigger-attempt":
            findings.append(
                {
                    "target_id": item.get("target_id"),
                    "finding": "bounded trigger attempt classified",
                    "classification": item.get("summary", {}).get("classification"),
                    "hit_count": item.get("summary", {}).get("hit_count"),
                    "artifact": item.get("path"),
                }
            )
        if item.get("kind") == "trigger-attempt-index":
            findings.append(
                {
                    "target_id": item.get("target_id"),
                    "finding": "trigger source ranking available",
                    "classification": item.get("summary", {}).get("recommended_trigger"),
                    "hit_count": item.get("summary", {}).get("hit_observed_count"),
                    "artifact": item.get("path"),
                }
            )
        if item.get("kind") == "nil-selector-triage":
            findings.append(
                {
                    "target_id": item.get("target_id"),
                    "finding": "nil-selector triage available",
                    "top_candidate": item.get("summary", {}).get("top_candidate"),
                    "storage_backed_count": item.get("summary", {}).get("nil_until_initialized_storage_backed_count"),
                    "scalar_storage_backed_count": item.get("summary", {}).get("scalar_default_integer_storage_backed_count"),
                    "artifact": item.get("path"),
                }
            )
        if item.get("kind") == "xpc-safe-read-dossier":
            findings.append(
                {
                    "target_id": item.get("target_id"),
                    "finding": "XPC safe-read no-call dossier available",
                    "safe_read_candidate_count": item.get("summary", {}).get("safe_read_candidate_count"),
                    "connection_no_call_ok_count": item.get("summary", {}).get("connection_no_call_ok_count"),
                    "artifact": item.get("path"),
                }
            )
        if _has_classified_private_api_runtime_evidence(
            {"kind": item.get("kind"), "summary": item.get("summary", {})}
        ):
            findings.append(
                {
                    "target_id": item.get("target_id"),
                    "finding": "private API observe-only runtime evidence captured",
                    "symbols": item.get("summary", {}).get("private_api_symbols", []),
                    "artifact": item.get("path"),
                }
            )
    return findings


def _next_work(validation: dict[str, Any], sections: dict[str, Any]) -> list[str]:
    work: list[str] = []
    if validation["warnings"]:
        work.append("Resolve or explicitly classify session-pack validation warnings.")
    if not sections.get("runtime_evidence") and not sections.get("instrumentation_evidence"):
        work.append("Add guarded runtime-status or instrumentation evidence when a safe owned target is available.")
    if not any(item.get("kind") == "xpc-graph" for item in sections.get("static_evidence", [])):
        work.append("Rebuild any relevant XPC graph with owner-resolution evidence when the target exposes XPC surfaces.")
    if not sections.get("private_api_invocation_evidence") and not _sections_have_classified_private_api_runtime_evidence(sections):
        work.append("Capture or link at least one controlled private API invocation or observe-only runtime artifact.")
    return work


def _friction(kind: str, path: str, target_id: str) -> dict[str, str]:
    return {"kind": kind, "target_id": target_id, "path": path}


def _has_private_api_invocation_evidence(artifact: dict[str, Any]) -> bool:
    summary = artifact.get("summary", {})
    if not summary.get("private_api_symbols"):
        return False
    kind = artifact.get("kind")
    if kind == "private-api":
        return True
    if kind == "runtime":
        return int(summary.get("hit_count") or 0) > 0
    if kind == "instrumentation":
        return int(summary.get("runtime_hit_count") or 0) > 0 and summary.get("status") in {"passed", "ok", None}
    return False


def _has_classified_private_api_runtime_evidence(artifact: dict[str, Any]) -> bool:
    summary = artifact.get("summary", {})
    if not summary.get("private_api_symbols"):
        return False
    kind = artifact.get("kind")
    if kind == "trigger-attempt":
        classification = str(summary.get("classification") or "")
        trace_status = str(summary.get("trace_status") or "")
        return "resolved_breakpoints_no_hits" in classification or trace_status == "breakpoints_no_hits"
    if kind == "trigger-attempt-index":
        return int(summary.get("resolved_no_hit_count") or 0) > 0
    if kind == "runtime-status":
        if (
            summary.get("live_validation_status") == "hook_ready_no_hits"
            and int(summary.get("frida_ready_hook_count") or 0) > 0
            and int(summary.get("frida_runtime_hit_count") or 0) == 0
        ):
            return True
        if (
            summary.get("lldb_trace_status") == "breakpoints_no_hits"
            and int(summary.get("lldb_resolved_breakpoint_locations") or 0) > 0
        ):
            return True
        if (
            summary.get("trace_status") == "breakpoints_no_hits"
            and int(summary.get("hit_count") or 0) == 0
            and int(summary.get("resolved_breakpoint_locations") or 0) > 0
        ):
            return True
        return summary.get("access_policy_live_status") == "bounded_observe_only_no_hit"
    if kind == "breakpoint-plan-preflight":
        return int(summary.get("resolved_no_hit_count") or 0) > 0 or int(summary.get("resolved_live_count") or 0) > 0
    if kind == "nil-selector-triage":
        return int(summary.get("candidate_count") or 0) > 0
    if kind == "objc-method-shape":
        return (
            int(summary.get("present_method_count") or 0) > 0
            and summary.get("remote_invocation_status") == "blocked_no_remote_call"
        )
    if kind == "instrumentation":
        event_summary = summary.get("frida_event_summary") if isinstance(summary.get("frida_event_summary"), dict) else {}
        installed_count = (
            int(event_summary.get("installed_count") or 0)
            + int(event_summary.get("native_installed_count") or 0)
            + int(event_summary.get("selector_installed_count") or 0)
            + int(summary.get("installed_hook_count") or 0)
        )
        readiness_ok = summary.get("readiness_observed") is True or summary.get("attach_pid") is not None
        return (
            summary.get("status") in {"passed", "ok", None}
            and readiness_ok
            and int(summary.get("runtime_hit_count") or 0) == 0
            and installed_count > 0
            and int(event_summary.get("missing_class_count") or 0) == 0
            and int(event_summary.get("missing_method_count") or 0) == 0
        )
    if kind == "xpc-allowed-class-focus":
        return (
            summary.get("remote_methods_invoked") is False
            and str(summary.get("lldb_trace_status") or "") == "ok"
            and int(summary.get("lldb_hit_count") or 0) > 0
        )
    return False


def _sections_have_classified_private_api_runtime_evidence(sections: dict[str, Any]) -> bool:
    for item in sections.get("runtime_evidence", []) + sections.get("instrumentation_evidence", []):
        if _has_classified_private_api_runtime_evidence(
            {"kind": item.get("kind"), "summary": item.get("summary", {})}
        ):
            return True
    return False
