"""Build ranked indexes for bounded trigger attempts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cerberus_re_skill.core.config import cfg
from cerberus_re_skill.core.utils import utc_now


TRIGGER_ATTEMPT_INDEX_SCHEMA = "ghidra-re.trigger-attempt-index.v1"


def build_trigger_attempt_index(
    *,
    attempts: list[str] | None = None,
    checklists: list[str] | None = None,
    runtime_statuses: list[str] | None = None,
    instrumentation: list[str] | None = None,
    frida_capture_plans: list[str] | None = None,
    session_pack: str | Path | None = None,
    output: str | Path | None = None,
    markdown_output: str | Path | None = None,
) -> dict[str, Any]:
    """Merge trigger-attempt artifacts and rank likely next trigger sources."""
    attempt_items = _load_mapped_items(attempts or [], "attempt")
    checklist_items = {item["id"]: item for item in _load_mapped_items(checklists or [], "checklist")}
    runtime_items = {item["id"]: item for item in _load_mapped_items(runtime_statuses or [], "runtime-status")}
    instrumentation_items = {item["id"]: item for item in _load_mapped_items(instrumentation or [], "instrumentation")}
    capture_plan_items = _load_mapped_items(frida_capture_plans or [], "frida-capture-plan")
    session_payload = _load_json(Path(session_pack), "session pack report") if session_pack else {}

    if not attempt_items:
        raise RuntimeError("at least one trigger attempt is required")

    indexed_attempts = [
        _summarize_attempt(
            item,
            checklist=checklist_items.get(item["id"], {}),
            runtime_status=runtime_items.get(item["id"], {}),
            instrumentation=instrumentation_items.get(item["id"], {}),
        )
        for item in attempt_items
    ]
    capture_summary = _capture_plan_summary(capture_plan_items)
    ranked = _rank_trigger_sources(indexed_attempts, session_payload, capture_summary)
    report = {
        "schema": TRIGGER_ATTEMPT_INDEX_SCHEMA,
        "ok": True,
        "created_at": utc_now(),
        "summary": {
            "attempt_count": len(indexed_attempts),
            "resolved_no_hit_count": sum(
                1 for item in indexed_attempts if _is_resolved_no_hit_classification(item.get("classification"))
            ),
            "hit_observed_count": sum(1 for item in indexed_attempts if int(item.get("hit_count") or 0) > 0),
            "frida_attach_blocker_count": sum(1 for item in indexed_attempts if item.get("frida_attach_blocked")),
            "trigger_source_insufficient_count": sum(1 for item in indexed_attempts if item.get("depth_classification") == "trigger_source_insufficient"),
            "missing_breakpoint_setup_count": sum(1 for item in indexed_attempts if item.get("depth_classification") == "missing_breakpoint_setup"),
            "partial_breakpoint_setup_count": sum(1 for item in indexed_attempts if item.get("breakpoint_setup_status") == "partial"),
            "protected_instrumentation_count": sum(
                1 for item in indexed_attempts for blocker in item.get("blocker_taxonomy", []) if blocker.get("kind") == "protected_instrumentation"
            ),
            "controlled_helper_available_count": capture_summary["controlled_helper_available_count"],
            "controlled_run_path_available_count": capture_summary["controlled_run_path_available_count"],
            "recommended_trigger": ranked[0]["id"] if ranked else "",
        },
        "attempts": indexed_attempts,
        "ranked_trigger_sources": ranked,
        "frida_capture_plan_summary": capture_summary,
        "session_pack_validation": _session_pack_validation(session_payload),
    }

    out_path = Path(output) if output else cfg.exports_dir / "trigger_attempt_index.json"
    md_path = Path(markdown_output) if markdown_output else cfg.exports_dir / "trigger_attempt_index.md"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    md_path.write_text(_render_markdown(report), encoding="utf-8")
    return {
        "ok": True,
        "output": str(out_path),
        "markdown_output": str(md_path),
        **report["summary"],
    }


def _load_mapped_items(specs: list[str], label: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
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


def _summarize_attempt(
    item: dict[str, Any],
    *,
    checklist: dict[str, Any],
    runtime_status: dict[str, Any],
    instrumentation: dict[str, Any],
) -> dict[str, Any]:
    payload = item["payload"]
    checklist_payload = checklist.get("payload") if isinstance(checklist.get("payload"), dict) else {}
    runtime_payload = runtime_status.get("payload") if isinstance(runtime_status.get("payload"), dict) else {}
    instrumentation_payload = instrumentation.get("payload") if isinstance(instrumentation.get("payload"), dict) else {}
    lldb = payload.get("lldb_validation") if isinstance(payload.get("lldb_validation"), dict) else {}
    if not lldb and runtime_payload:
        lldb = _lldb_summary(runtime_payload)
    selected = payload.get("selected_breakpoints") if isinstance(payload.get("selected_breakpoints"), list) else []
    if not selected:
        selected = checklist_payload.get("selected_breakpoints") if isinstance(checklist_payload.get("selected_breakpoints"), list) else []
    frida_blockers = _frida_blockers(payload, instrumentation_payload)
    depth_classification = _depth_classification(payload, lldb, frida_blockers)
    breakpoint_count = _int_value(lldb.get("breakpoint_count"))
    resolved_breakpoint_locations = _int_value(lldb.get("resolved_breakpoint_locations"))
    unresolved_breakpoint_count = _unresolved_breakpoint_count(lldb)
    return {
        "id": item["id"],
        "path": item["path"],
        "classification": str(payload.get("classification") or lldb.get("trace_status") or ""),
        "depth_classification": depth_classification,
        "blocker_taxonomy": _blocker_taxonomy(depth_classification, lldb, frida_blockers, payload.get("safety_result", [])),
        "trigger_name": (payload.get("trigger") or {}).get("name") if isinstance(payload.get("trigger"), dict) else "",
        "target_process": payload.get("target_process") or checklist_payload.get("selected_process") or {},
        "selected_symbols": _selected_symbols(selected),
        "selected_breakpoint_count": len(selected),
        "hit_count": lldb.get("hit_count"),
        "runtime_hit_count": lldb.get("runtime_hit_count"),
        "breakpoint_count": breakpoint_count,
        "resolved_breakpoint_locations": resolved_breakpoint_locations,
        "unresolved_breakpoint_count": unresolved_breakpoint_count,
        "breakpoint_setup_status": _breakpoint_setup_status(breakpoint_count, resolved_breakpoint_locations, unresolved_breakpoint_count),
        "breakpoints_hit": lldb.get("breakpoints_hit"),
        "frida_attach_blocked": bool(frida_blockers),
        "frida_blockers": frida_blockers,
        "safety_result": payload.get("safety_result", []),
        "next_recommendation": payload.get("next_step") or "rank additional non-mutating owning-subsystem triggers",
    }


def _lldb_summary(payload: dict[str, Any]) -> dict[str, Any]:
    trace = payload.get("trace") if isinstance(payload.get("trace"), dict) else {}
    preflight = trace.get("breakpoint_preflight") if isinstance(trace.get("breakpoint_preflight"), dict) else {}
    return {
        "trace_status": payload.get("trace_status"),
        "hit_count": payload.get("hit_count"),
        "runtime_hit_count": payload.get("runtime_hit_count"),
        "breakpoint_count": trace.get("breakpoint_count"),
        "resolved_breakpoint_locations": trace.get("resolved_breakpoint_locations"),
        "unresolved_breakpoint_count": preflight.get("unresolved_breakpoint_count"),
        "breakpoints_hit": trace.get("breakpoints_hit"),
    }


def _selected_symbols(selected: list[Any]) -> list[str]:
    symbols = []
    for item in selected:
        if isinstance(item, dict) and item.get("symbol"):
            symbols.append(str(item["symbol"]))
        elif isinstance(item, str):
            symbols.append(item)
    return symbols


def _frida_blockers(payload: dict[str, Any], instrumentation_payload: dict[str, Any]) -> list[str]:
    blockers: list[str] = []
    frida = payload.get("frida_side_evidence") if isinstance(payload.get("frida_side_evidence"), dict) else {}
    previous = frida.get("previous_live_attach_blocker") if isinstance(frida.get("previous_live_attach_blocker"), dict) else {}
    for error in previous.get("errors", []) if isinstance(previous.get("errors"), list) else []:
        blockers.append(str(error))
    for error in instrumentation_payload.get("errors", []) if isinstance(instrumentation_payload.get("errors"), list) else []:
        if str(error) not in blockers:
            blockers.append(str(error))
    return blockers


def _depth_classification(payload: dict[str, Any], lldb: dict[str, Any], frida_blockers: list[str]) -> str:
    classification = str(payload.get("classification") or lldb.get("trace_status") or "")
    hit_count = int(lldb.get("hit_count") or payload.get("hit_count") or 0)
    resolved = int(lldb.get("resolved_breakpoint_locations") or 0)
    breakpoint_count = int(lldb.get("breakpoint_count") or 0)
    if hit_count > 0:
        return "trigger_hit_observed"
    if _is_resolved_no_hit_classification(classification) or (classification == "breakpoints_no_hits" and resolved > 0):
        return "trigger_source_insufficient"
    if classification in {"no_breakpoints", "no_resolved_breakpoints"} or (breakpoint_count > 0 and resolved == 0):
        return "missing_breakpoint_setup"
    if frida_blockers:
        return "instrumentation_blocked"
    return "unclassified_trigger_depth"


def _blocker_taxonomy(
    depth_classification: str,
    lldb: dict[str, Any],
    frida_blockers: list[str],
    safety_result: Any,
) -> list[dict[str, Any]]:
    blockers: list[dict[str, Any]] = []
    breakpoint_count = _int_value(lldb.get("breakpoint_count"))
    resolved_breakpoint_locations = _int_value(lldb.get("resolved_breakpoint_locations"))
    unresolved_breakpoint_count = _unresolved_breakpoint_count(lldb)
    if depth_classification == "trigger_source_insufficient":
        blockers.append(
            {
                "kind": "trigger_source_insufficient",
                "resolved_breakpoint_locations": resolved_breakpoint_locations,
                "breakpoint_count": breakpoint_count,
            }
        )
    elif depth_classification == "missing_breakpoint_setup":
        blockers.append(
            {
                "kind": "missing_breakpoint_setup",
                "resolved_breakpoint_locations": lldb.get("resolved_breakpoint_locations"),
                "breakpoint_count": lldb.get("breakpoint_count"),
            }
        )
    if breakpoint_count > 0 and resolved_breakpoint_locations > 0 and unresolved_breakpoint_count > 0:
        blockers.append(
            {
                "kind": "partial_breakpoint_setup",
                "resolved_breakpoint_locations": resolved_breakpoint_locations,
                "unresolved_breakpoint_count": unresolved_breakpoint_count,
                "breakpoint_count": breakpoint_count,
            }
        )
    for error in frida_blockers:
        kind = "protected_instrumentation" if "protection failure" in error or "thread_create" in error else "instrumentation_blocked"
        blockers.append({"kind": kind, "error": error})
    for item in safety_result if isinstance(safety_result, list) else []:
        text = str(item)
        if "direct" in text.lower() and "private" in text.lower() and "not" in text.lower():
            blockers.append({"kind": "direct_private_call_avoided", "evidence": text})
    return blockers


def _capture_plan_summary(items: list[dict[str, Any]]) -> dict[str, Any]:
    plans = [item["payload"] for item in items]
    controlled = 0
    controlled_run_path = 0
    protected = 0
    recommended_paths = []
    controlled_domains = []
    for payload in plans:
        summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
        controlled += int(summary.get("controlled_passed_count") or 0)
        controlled_run_path += int(summary.get("controlled_run_path_count") or 0)
        protected += int(summary.get("protected_daemon_count") or 0)
        path = summary.get("recommended_capture_path")
        if path:
            recommended_paths.append(str(path))
        domains = summary.get("controlled_domains")
        if isinstance(domains, list):
            controlled_domains.extend(str(domain) for domain in domains if domain)
        domain = summary.get("recommended_controlled_domain")
        if domain:
            controlled_domains.append(str(domain))
    return {
        "plan_count": len(plans),
        "protected_daemon_count": protected,
        "controlled_helper_available_count": controlled,
        "controlled_run_path_available_count": controlled_run_path,
        "controlled_domains": sorted(set(controlled_domains)),
        "recommended_capture_paths": sorted(set(recommended_paths)),
    }


def _rank_trigger_sources(
    attempts: list[dict[str, Any]],
    session_pack: dict[str, Any],
    capture_plan_summary: dict[str, Any],
) -> list[dict[str, Any]]:
    resolved_no_hit = any(_is_resolved_no_hit_classification(item.get("classification")) for item in attempts)
    frida_blocked = any(item.get("frida_attach_blocked") for item in attempts)
    safe_read_blocked = _safe_read_entitlement_blocked(session_pack)
    controlled_helper_available = int(capture_plan_summary.get("controlled_helper_available_count") or 0) > 0
    controlled_run_path_available = int(capture_plan_summary.get("controlled_run_path_available_count") or 0) > 0
    candidates = [
        {
            "id": "app_metadata_refresh_observation",
            "score": 88 if resolved_no_hit else 78,
            "safety": "observe_only_likely_non_mutating",
            "expected_coverage": [
                "-[TargetManager updateMetadataWithCompletion:]",
                "-[TargetManager requestSearchIndexRefresh]",
                "-[TargetManagerAccessWrapper getItemsWithCompletion:]",
            ],
            "rationale": [
                "Prior LLDB guidance named app metadata changes as the owning subsystem trigger.",
                "Resolved/no-hit evidence means the next work should change the trigger source rather than symbol selection.",
            ],
            "replay_plan": [
                "Attach LLDB to the live target process with the resolved safe-read and observe-only breakpoints.",
                "Trigger an app metadata refresh source without creating, editing, deleting, or running user data.",
                "Detach after a bounded timeout and preserve hit/no-hit classification.",
            ],
            "replay_commands": _lldb_replay_commands(
                trigger_commands=[
                    "/usr/bin/open -g -a <TargetApp>",
                    "<public-cli> list >/tmp/cerberus-re-target-list-count.txt",
                ],
                note="Use these commands as a safe observation scaffold; metadata refresh should be induced only by opening/read-only system surfaces, not by forcing a private reindex.",
            ),
        },
        {
            "id": "controlled_helper_run_path_recheck",
            "score": 92 if controlled_run_path_available else 52,
            "safety": "controlled_helper_local_run_no_user_data",
            "expected_coverage": [
                "-[TargetAction runWithInput:error:]",
                "-[TargetAction runWithInput:context:completionHandler:]",
            ],
            "rationale": [
                "When daemon Frida attach is protected, a controlled helper can still capture invocation-path evidence.",
                "This validates the local run layer without creating, editing, deleting, or running user data.",
            ],
            "replay_plan": [
                "Spawn the deterministic helper under Frida.",
                "Capture call/return evidence for the selected run selector and enrich it against the static export.",
                "Keep daemon-trigger run selectors as static/LLDB follow-ups until input and safety shape are stronger.",
            ],
            "replay_commands": {
                "status": "ready" if controlled_run_path_available else "needs_controlled_run_helper",
                "commands": [
                    "python3 -m cerberus_re_skill frida recheck-attach --target <controlled-helper> --target-arg '<input>' --symbol '<selected run selector>' --capture-returns --allow-runtime",
                    "python3 -m cerberus_re_skill export runtime-enrich <project> <program> <runtime_hits.json>",
                ],
                "non_mutating_controls": [
                    *_non_mutating_controls(),
                    "controlled helper may invoke only the selected deterministic local run path",
                    "do not use this as proof that a full user workflow was run",
                ],
            },
        },
        {
            "id": "controlled_helper_private_framework_recheck",
            "score": 86 if controlled_helper_available else 48,
            "safety": "controlled_helper_non_daemon",
            "expected_coverage": [
                "-[TargetClient unsafeSetupXPCConnection]",
                "TargetClient NSXPCInterface setup path",
            ],
            "rationale": [
                "Use a controlled helper when daemon Frida attach is protected but private-framework setup evidence is still needed.",
                "Keep this separate from trigger-source replay because it validates instrumentation viability, not daemon trigger coverage.",
            ],
            "replay_plan": [
                "Spawn the no-call client helper with Frida.",
                "Capture call/return evidence and enrich runtime hits against the static client export.",
            ],
            "replay_commands": {
                "status": "ready" if controlled_helper_available else "needs_controlled_helper",
                "commands": [
                    "python3 -m cerberus_re_skill frida recheck-attach --target <helper> --symbol '-[TargetClient unsafeSetupXPCConnection]' --capture-returns --allow-runtime",
                    "python3 -m cerberus_re_skill export runtime-enrich <client-project> <client-program> <runtime_hits.json>",
                ],
                "non_mutating_controls": _non_mutating_controls(),
            },
        },
        {
            "id": "ui_open_read_refresh",
            "score": 72,
            "safety": "non_mutating_read_refresh",
            "expected_coverage": [
                "-[TargetManagerAccessWrapper getItemCountWithCompletion:]",
                "-[TargetManagerAccessWrapper getItemsWithCompletion:]",
            ],
            "rationale": [
                "UI-open/read-refresh is safe and reproducible, but the baseline public CLI read-refresh already produced no hits.",
                "Use as a control trigger when comparing stronger metadata-refresh attempts.",
            ],
            "replay_plan": [
                "Attach LLDB, open the target app in the foreground, navigate only read-only surfaces, then wait.",
                "Do not run or modify user data.",
            ],
            "replay_commands": _lldb_replay_commands(
                trigger_commands=[
                    "/usr/bin/open -a <TargetApp>",
                    "<public-cli> list >/tmp/cerberus-re-target-list-count.txt",
                ],
                note="Baseline replay for read-only UI/CLI refresh. It already produced resolved/no-hit once.",
            ),
        },
        {
            "id": "search_index_refresh_observation",
            "score": 66,
            "safety": "observe_only_do_not_force_reindex",
            "expected_coverage": [
                "-[TargetManager requestSearchIndexRefresh]",
            ],
            "rationale": [
                "The search-index refresh selector resolved live in multiple runs.",
                "Forcing a full reindex is avoided; this remains an observation target around natural or metadata-driven refresh events.",
            ],
            "replay_plan": [
                "Set the reindex breakpoint as observe-only while testing a separate metadata/UI trigger.",
                "Do not directly call the refresh selector.",
            ],
            "replay_commands": _lldb_replay_commands(
                symbols="-[TargetManager requestSearchIndexRefresh]",
                trigger_commands=[
                    "/usr/bin/open -g -a <TargetApp>",
                ],
                note="Observe natural or metadata-driven reindex behavior only; do not force a full reindex.",
            ),
        },
        {
            "id": "public_cli_read_activation",
            "score": 42 if resolved_no_hit else 58,
            "safety": "non_mutating_baseline",
            "expected_coverage": [
                "-[TargetManagerAccessWrapper getItemCountWithCompletion:]",
                "-[TargetManagerAccessWrapper getItemsWithCompletion:]",
            ],
            "rationale": [
                "Already attempted as the Phase 9.4 baseline and classified resolved/no-hit.",
                "Keep as regression baseline, not as the next best trigger.",
            ],
            "replay_plan": [
                "Repeat only when validating harness reproducibility or comparing a changed selector set.",
            ],
            "replay_commands": _lldb_replay_commands(
                trigger_commands=[
                    "/usr/bin/open -g -a <TargetApp>",
                    "<public-cli> list >/tmp/cerberus-re-target-list-count.txt",
                ],
                note="Regression baseline; not recommended as the next exploratory trigger.",
            ),
        },
        {
            "id": "direct_xpc_safe_read",
            "score": 12 if safe_read_blocked else 35,
            "safety": "blocked_pending_entitlement_and_input_shape",
            "expected_coverage": [
                "TargetManagerXPCInterface safe-read selectors",
            ],
            "rationale": [
                "Prior readiness kept safe-read remote calls blocked pending entitlement and input-shape evidence.",
                "Do not use as a live trigger until argument and entitlement shape are recovered.",
            ],
            "replay_plan": [
                "No replay command generated yet; recover static input shape first.",
            ],
            "replay_commands": {
                "status": "blocked",
                "reason": "pending entitlement and input-shape recovery",
                "commands": [],
                "non_mutating_controls": _non_mutating_controls(),
            },
        },
    ]
    if frida_blocked:
        for candidate in candidates:
            candidate.setdefault("constraints", []).append("prefer LLDB/live observation because Frida attach to the target process is protected")
    return sorted(candidates, key=lambda item: (-int(item["score"]), item["id"]))


def _is_resolved_no_hit_classification(value: Any) -> bool:
    """Treat specific trigger-source no-hit labels as the same resolved-breakpoint outcome."""
    return "resolved_breakpoints_no_hits" in str(value or "")


def _int_value(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _unresolved_breakpoint_count(lldb: dict[str, Any]) -> int:
    explicit = lldb.get("unresolved_breakpoint_count")
    if explicit is not None:
        return _int_value(explicit)
    preflight = lldb.get("breakpoint_preflight") if isinstance(lldb.get("breakpoint_preflight"), dict) else {}
    if preflight.get("unresolved_breakpoint_count") is not None:
        return _int_value(preflight.get("unresolved_breakpoint_count"))
    breakpoint_count = _int_value(lldb.get("breakpoint_count"))
    resolved = _int_value(lldb.get("resolved_breakpoint_locations"))
    return max(0, breakpoint_count - resolved)


def _breakpoint_setup_status(breakpoint_count: int, resolved_breakpoint_locations: int, unresolved_breakpoint_count: int) -> str:
    if breakpoint_count <= 0:
        return "not_recorded"
    if resolved_breakpoint_locations <= 0:
        return "missing"
    if unresolved_breakpoint_count > 0:
        return "partial"
    return "complete"


def _lldb_replay_commands(
    *,
    symbols: str | None = None,
    trigger_commands: list[str],
    note: str,
) -> dict[str, Any]:
    selected_symbols = symbols or ",".join(
        [
            "-[TargetManagerAccessWrapper getItemCountWithCompletion:]",
            "-[TargetManagerAccessWrapper getItemsWithCompletion:]",
            "-[TargetManager getItemsWithAccessSpecifier:completion:]",
            "-[TargetManager requestSearchIndexRefresh]",
        ]
    )
    return {
        "status": "ready",
        "note": note,
        "commands": [
            (
                "python3 -m cerberus_re_skill validate lldb-trace <project> <program> "
                "--attach-name <target-process> "
                f"--symbols '{selected_symbols}' "
                "--timeout 20 --max-hits 8 --capture-objc-args --capture-backtrace "
                "--output-dir <run-dir>/lldb-<trigger-id>"
            ),
            *trigger_commands,
        ],
        "non_mutating_controls": _non_mutating_controls(),
    }


def _non_mutating_controls() -> list[str]:
    return [
        "do not directly invoke protected target selectors",
        "do not create, edit, delete, or run user data",
        "treat refresh selectors as observe-only",
        "preserve no-hit results as evidence when breakpoints resolve",
    ]


def _safe_read_entitlement_blocked(session_pack: dict[str, Any]) -> bool:
    for artifact in session_pack.get("validation", {}).get("artifacts", []) if isinstance(session_pack, dict) else []:
        summary = artifact.get("summary") if isinstance(artifact, dict) and isinstance(artifact.get("summary"), dict) else {}
        if summary.get("needs_entitlement_count"):
            return True
    return False


def _session_pack_validation(payload: dict[str, Any]) -> dict[str, int]:
    validation = payload.get("validation") if isinstance(payload.get("validation"), dict) else {}
    return {
        "artifact_count": len(validation.get("artifacts", [])) if isinstance(validation.get("artifacts"), list) else 0,
        "error_count": len(validation.get("errors", [])) if isinstance(validation.get("errors"), list) else 0,
        "warning_count": len(validation.get("warnings", [])) if isinstance(validation.get("warnings"), list) else 0,
    }


def _render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Trigger Attempt Index",
        "",
        f"- Schema: `{report['schema']}`",
        f"- Attempts: {report['summary']['attempt_count']}",
        f"- Resolved/no-hit attempts: {report['summary']['resolved_no_hit_count']}",
        f"- Frida attach blockers: {report['summary']['frida_attach_blocker_count']}",
        f"- Trigger-source insufficient: {report['summary'].get('trigger_source_insufficient_count', 0)}",
        f"- Missing breakpoint setup: {report['summary'].get('missing_breakpoint_setup_count', 0)}",
        f"- Partial breakpoint setup: {report['summary'].get('partial_breakpoint_setup_count', 0)}",
        f"- Protected instrumentation blockers: {report['summary'].get('protected_instrumentation_count', 0)}",
        f"- Controlled helper paths available: {report['summary'].get('controlled_helper_available_count', 0)}",
        f"- Controlled run-path helpers available: {report['summary'].get('controlled_run_path_available_count', 0)}",
        f"- Recommended trigger: `{report['summary']['recommended_trigger']}`",
        "",
        "## Attempts",
        "",
    ]
    for attempt in report["attempts"]:
        blocker_kinds = [
            str(blocker.get("kind"))
            for blocker in attempt.get("blocker_taxonomy", [])
            if isinstance(blocker, dict) and blocker.get("kind")
        ]
        lines.append(
            f"- `{attempt['id']}`: classification=`{attempt['classification']}`, "
            f"depth=`{attempt.get('depth_classification') or ''}`, "
            f"breakpoint_setup=`{attempt.get('breakpoint_setup_status') or ''}`, "
            f"trigger=`{attempt.get('trigger_name') or ''}`, "
            f"hits={attempt.get('hit_count')}, resolved={attempt.get('resolved_breakpoint_locations')}/{attempt.get('breakpoint_count')}, "
            f"unresolved={attempt.get('unresolved_breakpoint_count')}, "
            f"blockers={', '.join(blocker_kinds) if blocker_kinds else 'none'}"
        )
    capture_summary = report.get("frida_capture_plan_summary")
    if isinstance(capture_summary, dict) and capture_summary.get("plan_count"):
        paths = capture_summary.get("recommended_capture_paths")
        lines += [
            "",
            "## Frida Capture Plan Summary",
            "",
            f"- Plans: {capture_summary.get('plan_count', 0)}",
            f"- Protected daemons: {capture_summary.get('protected_daemon_count', 0)}",
            f"- Controlled helpers available: {capture_summary.get('controlled_helper_available_count', 0)}",
            f"- Controlled run-path helpers available: {capture_summary.get('controlled_run_path_available_count', 0)}",
            f"- Controlled domains: {', '.join(capture_summary.get('controlled_domains', [])) if isinstance(capture_summary.get('controlled_domains'), list) and capture_summary.get('controlled_domains') else 'none'}",
            f"- Recommended capture paths: {', '.join(paths) if isinstance(paths, list) and paths else 'none'}",
        ]
    lines += ["", "## Ranked Trigger Sources", ""]
    for candidate in report["ranked_trigger_sources"]:
        lines.append(
            f"- `{candidate['id']}`: score={candidate['score']}; safety={candidate['safety']}; "
            f"coverage={', '.join(candidate['expected_coverage'])}"
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
