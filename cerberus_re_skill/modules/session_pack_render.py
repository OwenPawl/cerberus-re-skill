"""Markdown and small utility helpers for session-pack reports."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

def _load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as e:
        raise RuntimeError(f"{label} not found: {path}") from e
    except json.JSONDecodeError as e:
        raise RuntimeError(f"{label} is not valid JSON: {path}: {e}") from e
    if not isinstance(payload, dict):
        raise RuntimeError(f"{label} must be a JSON object: {path}")
    return payload


def _render_markdown(report: dict[str, Any]) -> str:
    lines = [
        f"# {report['session_pack'].get('name') or 'Session Pack Report'}",
        "",
        f"- Schema: `{report['schema']}`",
        f"- Manifest: `{report['manifest']}`",
        f"- Goal: {report['session_pack'].get('goal') or ''}",
        f"- Validation: {'passed' if report['validation']['ok'] else 'failed'} ({len(report['validation']['errors'])} errors, {len(report['validation']['warnings'])} warnings)",
        "",
    ]
    if report["validation"]["errors"]:
        lines.extend(["## Validation Errors", ""])
        lines.extend(f"- {item}" for item in report["validation"]["errors"])
        lines.append("")
    if report["validation"]["warnings"]:
        lines.extend(["## Validation Warnings", ""])
        lines.extend(f"- {item}" for item in report["validation"]["warnings"])
        lines.append("")

    section_titles = {
        "target_inventory": "Target Inventory",
        "static_evidence": "Static Evidence",
        "runtime_evidence": "Runtime Evidence",
        "instrumentation_evidence": "Instrumentation Evidence",
        "private_api_invocation_evidence": "Private API Invocation Evidence",
        "framework_friction": "Framework Friction",
        "analysis_findings": "Analysis Findings",
        "next_framework_work": "Next Framework Work",
    }
    for key, title in section_titles.items():
        lines.extend([f"## {title}", ""])
        value = report["sections"].get(key, [])
        if not value:
            lines.extend(["- None.", ""])
            continue
        for item in value:
            if isinstance(item, str):
                lines.append(f"- {item}")
            elif key == "target_inventory":
                lines.append(f"- `{item.get('id')}` ({item.get('kind')}): {item.get('project') or '-'} / {item.get('program') or '-'}")
            elif "finding" in item:
                detail = ", ".join(str(s) for s in item.get("symbols", [])) or item.get("edge_count") or item.get("classification") or ""
                lines.append(f"- `{item.get('target_id')}`: {item.get('finding')} ({detail})")
            elif "items" in item:
                lines.append(f"- `{item.get('target_id')}`: {json.dumps(item.get('items'), sort_keys=True)}")
            else:
                summary = item.get("summary", {})
                bits = _summary_bits(summary)
                lines.append(f"- `{item.get('target_id')}` `{item.get('kind')}`: `{item.get('path')}`{bits}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _truthy_json_bool(value: Any) -> bool:
    return value is True or value == 1


def _method_type_encoding_count(method_type_encodings: dict[str, Any]) -> int:
    total = 0
    for items in method_type_encodings.values():
        if isinstance(items, list):
            total += len(items)
    return total


def _summary_bits(summary: dict[str, Any]) -> str:
    keys = [
        "hit_count",
        "matched_function_count",
        "runtime_hit_count",
        "status",
        "trace_status",
        "breakpoint_count",
        "resolved_breakpoint_locations",
        "trigger_guidance_count",
        "attempt_count",
        "resolved_no_hit_count",
        "hit_observed_count",
        "frida_attach_blocker_count",
        "trigger_source_insufficient_count",
        "missing_breakpoint_setup_count",
        "missing_static_count",
        "sidecar_only_count",
        "sidecar_only_live_pending_count",
        "resolved_live_count",
        "pending_live_count",
        "warning_count",
        "protected_instrumentation_count",
        "controlled_helper_available_count",
        "controlled_run_path_available_count",
        "ranked_trigger_count",
        "recommended_trigger",
        "top_trigger",
        "top_score",
        "replay_ready_count",
        "replay_blocked_count",
        "candidate_count",
        "nil_until_initialized_storage_backed_count",
        "scalar_default_integer_storage_backed_count",
        "present_nil_needs_context_or_parameter_count",
        "scalar_default_or_probe_shape_mismatch_count",
        "recommended_capture_path",
        "recommended_controlled_domain",
        "protected_daemon_count",
        "controlled_run_path_count",
        "controlled_xpc_setup_count",
        "attachable",
        "blocker_count",
        "controlled_runtime_hit_count",
        "enriched_matched_function_count",
        "method_count",
        "present_method_count",
        "run_intent_method_count",
        "completion_backed_method_count",
        "block_signature_count",
        "block_signature_match_count",
        "selector_blocker_count",
        "manager_selector_blocker_count",
        "local_generation_completed",
        "dlopen_ok",
        "input_shape",
        "completion_shape",
        "workflow_object_provenance",
        "remote_invocation_status",
        "lldb_trace_status",
        "lldb_resolved_breakpoint_locations",
        "lldb_hit_count",
        "service_lldb_hit_count",
        "service_lldb_resolved_no_hit_count",
        "frida_status",
        "frida_readiness_observed_count",
        "frida_delayed_installed_count",
        "frida_initial_installed_count",
        "frida_runtime_hit_count",
        "frida_service_hit_count",
        "next_safe_step",
        "entry_count",
        "instrumented_count",
        "top_identifier",
        "action_identifier",
        "action_class",
        "workflow_mode",
        "variable_source_mode",
        "selector_result_count",
        "method_type_encoding_count",
        "choose_menu_state_probe_count",
        "choose_menu_state_selector_count",
        "latest_menu_choice",
        "show_alert_invocation_skipped",
        "context_slot_count",
        "interface_count",
        "interfaces_with_method_candidates",
        "method_candidate_count",
        "completion_method_count",
        "verified_shape_count",
        "top_selector",
        "ready_for_bounded_probe_count",
        "needs_input_shape_count",
        "needs_entitlement_count",
        "unsafe_or_state_changing_count",
        "harness_stub_count",
        "installed_hook_count",
        "missing_hook_count",
        "target_pid",
        "edge_count",
        "service_name_count",
        "function_count",
        "class_count",
        "xref_count",
        "static_finding_count",
        "dossier_count",
    ]
    bits = [f"{key}={summary[key]}" for key in keys if key in summary]
    symbols = summary.get("private_api_symbols") or []
    if symbols:
        bits.append("private_api=" + ",".join(str(s) for s in symbols[:4]))
    return " (" + "; ".join(bits) + ")" if bits else ""
