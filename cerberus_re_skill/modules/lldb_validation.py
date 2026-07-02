"""Guarded LLDB live trace validation and enrichment."""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

from cerberus_re_skill.core.config import cfg
from cerberus_re_skill.core.utils import timestamp, utc_now
from cerberus_re_skill.modules.lldb_enrich import enrich_lldb_trace
from cerberus_re_skill.modules.runtime_hits import normalize_lldb_trace_hits, write_runtime_hits_artifact


@dataclass(frozen=True)
class ProcessResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


Runner = Callable[[Sequence[str], Path, float], ProcessResult]


def validate_lldb_trace(
    *,
    project: str,
    program: str,
    launch_cmd: str = "",
    attach_pid: str = "",
    attach_name: str = "",
    symbols: str | Sequence[str] = "",
    addresses: str | Sequence[str] = "",
    binary: str = "",
    function_inventory: str | Path | None = None,
    output_dir: str | Path | None = None,
    timeout: float = 30.0,
    max_hits: int = 10,
    capture_objc_args: bool = False,
    objc_description_registers: str = "",
    capture_backtrace: bool = False,
    include_decompile: bool = False,
    decompile_timeout: int = 60,
    runner: Runner | None = None,
) -> dict:
    """Run LLDB trace, classify policy blockers, and enrich hits when possible."""
    symbols = _normalize_csv_values(symbols)
    addresses = _normalize_csv_values(addresses)
    if not (launch_cmd or attach_pid or attach_name):
        raise RuntimeError("one of launch_cmd, attach_pid, or attach_name is required")
    if not (symbols or addresses):
        raise RuntimeError("one of symbols or addresses is required")
    objc_description_registers = _validate_objc_description_registers(objc_description_registers)
    if objc_description_registers:
        capture_objc_args = True

    report_dir = Path(output_dir) if output_dir else cfg.logs_dir / "lldb" / f"lldb-trace-{timestamp()}"
    report_dir.mkdir(parents=True, exist_ok=True)
    run = runner or _run

    steps: list[dict] = []
    if binary:
        symbols_result = _run_step(
            "lldb symbols",
            [str(cfg.skill_root / "scripts" / "ghidra_lldb_symbols"), binary, project, program],
            report_dir,
            run,
            timeout,
        )
        steps.append(symbols_result)

    trace_json = report_dir / "lldb_trace.json"
    trace_cmd = [
        str(cfg.skill_root / "scripts" / "ghidra_lldb_trace"),
        project,
        program,
        f"symbols={symbols}",
        f"addresses={addresses}",
        f"max_hits={max_hits}",
        f"timeout={int(timeout)}",
        f"capture_objc_args={_bool_arg(capture_objc_args)}",
        f"capture_backtrace={_bool_arg(capture_backtrace)}",
        f"output={trace_json}",
    ]
    if objc_description_registers:
        trace_cmd.append(f"objc_description_registers={objc_description_registers}")
    if launch_cmd:
        trace_cmd.append(f"launch_cmd={launch_cmd}")
    if attach_pid:
        trace_cmd.append(f"attach_pid={attach_pid}")
    if attach_name:
        trace_cmd.append(f"attach_name={attach_name}")

    trace_step = _run_step("lldb trace", trace_cmd, report_dir, run, timeout + 15)
    steps.append(trace_step)

    trace_payload = _load_json(trace_json)
    trace_payload = _recover_raw_breakpoint_preflight(trace_payload, trace_step)
    if trace_payload.get("breakpoint_preflight_recovered"):
        trace_json.write_text(json.dumps(trace_payload, indent=2) + "\n", encoding="utf-8")
    trace_status = _classify_trace(trace_step, trace_payload)
    hit_count = _int(trace_payload.get("hit_count"))
    runtime_hits = normalize_lldb_trace_hits(
        trace_payload,
        project=project,
        program=program,
        source_artifact=trace_json,
    )
    runtime_hits_json = report_dir / "runtime_hits.json"
    runtime_hits_payload = write_runtime_hits_artifact(
        runtime_hits_json,
        project=project,
        program=program,
        hits=runtime_hits,
        source=trace_json,
    )

    enrich_result: dict = {}
    if trace_status in {"ok", "partial_timeout"} and hit_count > 0:
        try:
            enrich_result = enrich_lldb_trace(
                project=project,
                program=program,
                trace_path=trace_json,
                output=report_dir / "lldb_trace_enriched.json",
                function_inventory_path=function_inventory,
                include_decompile=include_decompile,
                decompile_timeout=decompile_timeout,
            )
        except Exception as exc:
            enrich_result = {"ok": False, "error": str(exc)}

    next_work_items = _next_work_items(trace_status, trace_payload, enrich_result)
    trigger_guidance = _trigger_guidance(
        trace_status,
        trace_payload,
        launch_cmd=launch_cmd,
        attach_pid=attach_pid,
        attach_name=attach_name,
        symbols=symbols,
        addresses=addresses,
    )
    trigger_guidance.extend(_symbol_export_guidance(steps, binary))
    ok = trace_status in {"ok", "no_breakpoints", "breakpoints_no_hits", "attach_blocked"} and all(
        _step_ok_for_report(step, trace_status, trace_payload) for step in steps
    )
    report = {
        "schema": "ghidra-re.lldb-trace-validation.v1",
        "ok": ok,
        "created_at": utc_now(),
        "project_name": project,
        "program_name": program,
        "report_dir": str(report_dir),
        "objc_description_registers": objc_description_registers.split(",") if objc_description_registers else [],
        "trace_status": trace_status,
        "hit_count": hit_count,
        "trace_json": str(trace_json),
        "runtime_hits_json": str(runtime_hits_json),
        "runtime_hit_count": runtime_hits_payload["hit_count"],
        "runtime_modules": trace_payload.get("runtime_modules", []),
        "enriched_json": enrich_result.get("output", ""),
        "matched_function_count": enrich_result.get("matched_function_count", 0),
        "address_mapped_function_count": enrich_result.get("address_mapped_function_count", 0),
        "symbol_mismatch_count": enrich_result.get("symbol_mismatch_count", 0),
        "symbol_resolved_mismatch_count": enrich_result.get("symbol_resolved_mismatch_count", 0),
        "interior_boundary_mismatch_count": enrich_result.get("interior_boundary_mismatch_count", 0),
        "slide_conflict": enrich_result.get("slide_conflict", False),
        "slide_confidence": enrich_result.get("slide_confidence", "none"),
        "slide_candidates": enrich_result.get("slide_candidates", []),
        "steps": steps,
        "trace": _trace_summary(trace_payload),
        "enrich": enrich_result,
        "trigger_guidance": trigger_guidance,
        "next_work_items": next_work_items,
    }
    json_path = report_dir / "lldb-trace-validation.json"
    markdown_path = report_dir / "lldb-trace-validation.md"
    report["json_report"] = str(json_path)
    report["markdown_report"] = str(markdown_path)
    json_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    markdown_path.write_text(_render_markdown(report), encoding="utf-8")
    return report


def _run(cmd: Sequence[str], cwd: Path, timeout: float) -> ProcessResult:
    try:
        completed = subprocess.run(
            list(cmd),
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return ProcessResult(completed.returncode, completed.stdout, completed.stderr)
    except subprocess.TimeoutExpired as exc:
        return ProcessResult(124, _ensure_text(exc.stdout), _ensure_text(exc.stderr or "timeout expired"))


def _run_step(label: str, command: Sequence[str], report_dir: Path, runner: Runner, timeout: float) -> dict:
    result = runner(command, cfg.skill_root, timeout)
    stdout = _ensure_text(result.stdout)
    stderr = _ensure_text(result.stderr)
    payload = {
        "label": label,
        "command": list(command),
        "returncode": result.returncode,
        "ok": result.returncode == 0,
        "stdout_tail": stdout[-4000:],
        "stderr_tail": _clean_stderr(stderr)[-4000:],
    }
    safe = "".join(ch.lower() if ch.isalnum() else "-" for ch in label).strip("-")
    (report_dir / f"{safe}.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return payload


def _step_ok_for_report(step: dict, trace_status: str, trace: dict) -> bool:
    if step.get("returncode") == 0:
        return True
    if step.get("label") == "lldb trace" and trace_status == "attach_blocked":
        return True
    if step.get("label") == "lldb symbols" and trace_status in {"ok", "breakpoints_no_hits"}:
        if _int(trace.get("hit_count")) > 0:
            return True
        preflight = _breakpoint_preflight(trace)
        return preflight["resolved_location_count"] > 0
    return False


def _classify_trace(step: dict, trace: dict) -> str:
    text = "\n".join([step.get("stdout_tail", ""), step.get("stderr_tail", ""), str(trace.get("raw_tail", ""))]).lower()
    if step.get("returncode") != 0:
        if _int(trace.get("hit_count")) > 0 and bool(trace.get("ok", False)) and not _looks_policy_blocked(text):
            return "partial_timeout" if step.get("returncode") == 124 else "partial_failed"
        return "attach_blocked" if _looks_policy_blocked(text) else "failed"
    if _looks_policy_blocked(text):
        return "attach_blocked"
    if _trace_marker_missing_without_preflight(trace):
        return "trace_incomplete"
    preflight = _breakpoint_preflight(trace)
    if _int(trace.get("hit_count")) == 0:
        if preflight["breakpoint_count"] == 0 or preflight["resolved_location_count"] == 0:
            return "no_breakpoints"
        return "breakpoints_no_hits"
    return "ok"


def _looks_policy_blocked(text: str) -> bool:
    needles = [
        "operation not permitted",
        "not allowed to attach",
        "attach failed",
        "failed to get task",
        "system integrity protection",
        "debugserver is not executable",
    ]
    return any(needle in text for needle in needles)


def _trace_marker_missing_without_preflight(trace: dict) -> bool:
    warning = str(trace.get("warning", "")).lower()
    if "ghidra_trace_begin marker not found" not in warning:
        return False
    if _int(trace.get("hit_count")) > 0:
        return False
    preflight = _breakpoint_preflight(trace)
    return preflight["breakpoint_count"] == 0


def _trace_summary(trace: dict) -> dict:
    preflight = _breakpoint_preflight(trace)
    return {
        "ok": trace.get("ok", False),
        "warning": trace.get("warning", ""),
        "hit_count": _int(trace.get("hit_count")),
        "breakpoint_count": preflight["breakpoint_count"],
        "resolved_breakpoint_locations": preflight["resolved_location_count"],
        "breakpoints_hit": preflight["hit_breakpoint_count"],
        "breakpoint_preflight": preflight,
        "symbols_requested": trace.get("symbols_requested", []),
        "addresses_requested": trace.get("addresses_requested", []),
        "data_slide": trace.get("data_slide"),
        "runtime_modules": trace.get("runtime_modules", []),
        "isa_map_error": trace.get("isa_map_error"),
        "raw_tail": str(trace.get("raw_tail", ""))[-2000:],
        "breakpoint_preflight_recovered": bool(trace.get("breakpoint_preflight_recovered")),
        "breakpoint_preflight_partial": bool(trace.get("breakpoint_preflight_partial")),
        "breakpoint_preflight_source": trace.get("breakpoint_preflight_source", ""),
    }


def _next_work_items(trace_status: str, trace: dict, enrich: dict) -> list[str]:
    items: list[str] = []
    if trace_status == "attach_blocked":
        items.append("Classify LLDB attach policy blockers separately from trace command failures")
    elif trace_status == "no_breakpoints":
        items.append("Improve LLDB trace symbol/address preflight when no breakpoint locations resolve")
    elif trace_status == "breakpoints_no_hits":
        items.append("Improve LLDB trace trigger guidance when breakpoints resolve but do not fire")
    elif trace_status == "trace_incomplete":
        items.append("Preserve LLDB wait/trace lifecycle failures separately from unresolved breakpoint locations")
    elif trace_status in {"partial_timeout", "partial_failed"}:
        items.append("Preserve and enrich LLDB runtime hits from partial traces without upgrading them to clean success")
    if enrich and not enrich.get("ok", False):
        items.append("Improve LLDB trace enrichment error reporting")
    if enrich.get("ok") and _int(enrich.get("matched_function_count")) < _int(trace.get("hit_count")):
        items.append("Improve LLDB trace slide/function matching for unmatched runtime PCs")
    if enrich.get("ok") and _int(enrich.get("symbol_mismatch_count")) > 0:
        items.append("Review LLDB trace slide/function matching where runtime symbols disagree with static functions")
    if enrich.get("ok") and _int(enrich.get("symbol_resolved_mismatch_count")) > 0:
        items.append("Use symbol-resolved identity as a cross-check when address mapping lands in a neighboring function")
    if enrich.get("ok") and _int(enrich.get("interior_boundary_mismatch_count")) > 0:
        items.append("Recover static function boundaries where runtime symbols land inside conflicting function bodies")
    if enrich.get("ok") and enrich.get("slide_conflict"):
        items.append("Resolve static/runtime binary identity drift before trusting conflicting LLDB slide correlations")
    if trace.get("isa_map_error"):
        items.append("Improve isa_map generation/loading for ObjC argument capture")
    return items


def _render_markdown(report: dict) -> str:
    lines = [
        "# LLDB Trace Validation",
        "",
        f"- Status: `{report['trace_status']}`",
        f"- Hits: {report['hit_count']}",
        f"- Matched functions: {report.get('matched_function_count', 0)}",
        f"- Address-mapped functions: {report.get('address_mapped_function_count', 0)}",
        f"- Symbol mismatches: {report.get('symbol_mismatch_count', 0)}",
        f"- Symbol-resolved mismatches: {report.get('symbol_resolved_mismatch_count', 0)}",
        f"- Interior boundary mismatches: {report.get('interior_boundary_mismatch_count', 0)}",
        f"- Slide confidence: `{report.get('slide_confidence', 'none')}`",
        f"- Slide conflict: `{report.get('slide_conflict', False)}`",
        f"- Breakpoints: {report.get('trace', {}).get('breakpoint_count', 0)}",
        f"- Resolved breakpoint locations: {report.get('trace', {}).get('resolved_breakpoint_locations', 0)}",
        f"- Trace JSON: `{report['trace_json']}`",
        f"- Runtime hits JSON: `{report.get('runtime_hits_json', '')}`",
    ]
    if report.get("enriched_json"):
        lines.append(f"- Enriched JSON: `{report['enriched_json']}`")
    if report.get("objc_description_registers"):
        lines.append(f"- Objective-C descriptions: `{','.join(report['objc_description_registers'])}`")
    slide_candidates = report.get("slide_candidates", [])
    if slide_candidates:
        lines.append("")
        lines.append("## Slide Candidates")
        for candidate in slide_candidates[:5]:
            symbols = candidate.get("symbols") if isinstance(candidate.get("symbols"), list) else []
            symbol_text = ", ".join(str(symbol) for symbol in symbols[:4])
            suffix = f", symbols={symbol_text}" if symbol_text else ""
            lines.append(
                "- "
                f"slide=`{candidate.get('slide', '')}`, "
                f"mapped={candidate.get('mapped_hit_count', 0)}, "
                f"evidence={candidate.get('evidence_count', 0)}, "
                f"runtime_hits={candidate.get('runtime_hit_count', 0)}"
                f"{suffix}"
            )
    runtime_modules = report.get("runtime_modules", [])
    if runtime_modules:
        lines.append("")
        lines.append("## Runtime Modules")
        for module in runtime_modules:
            lines.append(
                f"- `{module.get('name', '')}` UUID=`{module.get('uuid', '')}` path=`{module.get('path', '')}`"
            )
    raw_tail = str(report.get("trace", {}).get("raw_tail") or "").strip()
    if report.get("trace_status") == "trace_incomplete" and raw_tail:
        lines.append("")
        lines.append("## LLDB Raw Tail")
        lines.append("")
        lines.append("```text")
        lines.append(raw_tail[-1200:])
        lines.append("```")
    preflight = report.get("trace", {}).get("breakpoint_preflight", {})
    breakpoints = preflight.get("breakpoints") if isinstance(preflight, dict) else []
    if breakpoints:
        lines.append("")
        lines.append("## Breakpoint Preflight")
        if report.get("trace", {}).get("breakpoint_preflight_partial"):
            lines.append("- Partial recovery: only breakpoint locations supported by preserved runtime hits are listed.")
        elif report.get("trace", {}).get("breakpoint_preflight_source") == "durable_preflight_sidecar":
            lines.append("- Durable recovery: the complete breakpoint preflight was saved before the bounded runtime wait ended.")
        for bp in breakpoints:
            requested = bp.get("requested") if isinstance(bp.get("requested"), dict) else {}
            summary = bp.get("summary") or requested.get("value") or ""
            suffix = f" - {summary}" if summary else ""
            lines.append(f"- Breakpoint {bp.get('id')}: locs={bp.get('locs', 0)}, hits={bp.get('hits', 0)}{suffix}")
    guidance = report.get("trigger_guidance", [])
    lines.append("")
    lines.append("## Trigger Guidance")
    if guidance:
        lines.extend(f"- {item}" for item in guidance)
    else:
        lines.append("- none")
    items = report.get("next_work_items", [])
    lines.append("")
    lines.append("## Next Work Items")
    if items:
        lines.extend(f"- {item}" for item in items)
    else:
        lines.append("- none")
    lines.append("")
    return "\n".join(lines)


def _load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _bool_arg(value: bool) -> str:
    return "true" if value else "false"


def _normalize_csv_values(values: str | Sequence[str] | None) -> str:
    if values is None:
        return ""
    raw_values: Sequence[str]
    if isinstance(values, str):
        raw_values = [values]
    else:
        raw_values = [str(value) for value in values]

    normalized: list[str] = []
    seen: set[str] = set()
    for raw in raw_values:
        for item in raw.split(","):
            value = item.strip()
            if not value or value in seen:
                continue
            normalized.append(value)
            seen.add(value)
    return ",".join(normalized)


def _validate_objc_description_registers(value: str) -> str:
    registers = [item.strip() for item in value.split(",") if item.strip()]
    invalid = [item for item in registers if item not in {f"x{index}" for index in range(8)}]
    if invalid:
        raise RuntimeError("objc description registers must be selected from x0 through x7")
    return ",".join(dict.fromkeys(registers))


def _int(value: object) -> int:
    return value if isinstance(value, int) else 0


def _breakpoint_preflight(trace: dict) -> dict:
    raw = trace.get("breakpoints", [])
    breakpoints = raw if isinstance(raw, list) else []
    resolved_locations = 0
    hit_breakpoints = 0
    unresolved: list[dict] = []
    normalized: list[dict] = []
    for item in breakpoints:
        if not isinstance(item, dict):
            continue
        locs = _int(item.get("locs"))
        hits = _int(item.get("hits"))
        if locs == 0:
            unresolved.append(item)
        if locs > 0:
            resolved_locations += locs
        if hits > 0:
            hit_breakpoints += 1
        normalized_item = {"id": item.get("id"), "locs": locs, "hits": hits}
        if item.get("source"):
            normalized_item["source"] = item.get("source")
        if item.get("summary"):
            normalized_item["summary"] = item.get("summary")
        if isinstance(item.get("requested"), dict):
            normalized_item["requested"] = item.get("requested")
        normalized.append(normalized_item)
    return {
        "breakpoint_count": len(normalized),
        "resolved_location_count": resolved_locations,
        "unresolved_breakpoint_count": len(unresolved),
        "hit_breakpoint_count": hit_breakpoints,
        "breakpoints": normalized,
    }


def _recover_raw_breakpoint_preflight(trace: dict, step: dict) -> dict:
    """Recover LLDB breakpoint setup when timeout prevents JSON marker emission."""
    if trace.get("breakpoints"):
        return trace
    text = "\n".join([step.get("stdout_tail", ""), step.get("stderr_tail", ""), str(trace.get("raw_tail", ""))])
    recovered: list[dict] = []
    seen: set[int] = set()
    for line in text.splitlines():
        match = re.search(r"\bBreakpoint\s+(\d+):\s*(.*)", line)
        if not match:
            continue
        bp_id = int(match.group(1))
        if bp_id in seen:
            continue
        body = match.group(2).strip()
        lowered = body.lower()
        locs = 0
        if "where =" in lowered or "address =" in lowered:
            locs = 1
        else:
            loc_match = re.search(r"\b(\d+)\s+locations?\b", lowered)
            if loc_match:
                locs = int(loc_match.group(1))
        recovered.append({"id": bp_id, "locs": locs, "hits": 0, "source": "raw_lldb_output", "summary": body})
        seen.add(bp_id)
    partial = False
    if not recovered:
        recovered = _recover_breakpoints_from_hits(trace)
        partial = bool(recovered)
    if not recovered:
        return trace
    updated = dict(trace)
    updated["breakpoints"] = recovered
    updated["breakpoint_preflight_recovered"] = True
    if partial:
        updated["breakpoint_preflight_partial"] = True
    return updated


def _recover_breakpoints_from_hits(trace: dict) -> list[dict]:
    """Infer only hit breakpoint locations when a timed-out trace loses its trailer."""
    raw_hits = trace.get("hits", [])
    hits = raw_hits if isinstance(raw_hits, list) else []
    grouped: dict[str, dict] = {}
    for hit in hits:
        if not isinstance(hit, dict):
            continue
        symbol = str(hit.get("symbol") or "").strip()
        pc = str(hit.get("pc") or "").strip()
        key = symbol or pc
        if not key:
            continue
        if key not in grouped:
            grouped[key] = {
                "id": len(grouped) + 1,
                "locs": 1,
                "hits": 0,
                "source": "runtime_hit_sidecar",
                "summary": f"preserved runtime hit: {key}",
            }
        grouped[key]["hits"] += 1
    return list(grouped.values())


def _trigger_guidance(
    trace_status: str,
    trace: dict,
    *,
    launch_cmd: str,
    attach_pid: str,
    attach_name: str,
    symbols: str,
    addresses: str,
) -> list[str]:
    requested = [item.strip() for item in ",".join([symbols, addresses]).split(",") if item.strip()]
    target = attach_pid or attach_name or launch_cmd
    if trace_status == "attach_blocked":
        return [
            "Attach was blocked by platform policy; prefer a controlled launch target or a signed/get-task-allow harness before changing breakpoints.",
            "Keep the same requested symbols so the next run can distinguish policy changes from symbol-resolution changes.",
        ]
    if trace_status == "no_breakpoints":
        guidance = [
            "No breakpoint locations resolved; verify that the module is loaded in the target and prefer exported file addresses when symbol names are ambiguous.",
        ]
        if requested:
            guidance.append(f"Recheck symbol/address spelling against the export before retrying: {', '.join(requested[:3])}.")
        mach_o_c_exports = [item for item in requested if item.startswith("_") and not item.startswith("__") and len(item) > 1]
        if mach_o_c_exports:
            aliases = [item[1:] for item in mach_o_c_exports[:3]]
            guidance.append(
                "For Mach-O C exports copied from nm/Ghidra, LLDB commonly resolves the user-facing name without the leading underscore; retry aliases such as "
                + ", ".join(aliases)
                + "."
            )
        return guidance
    if trace_status == "trace_incomplete":
        guidance = [
            "LLDB finished without the structured GHIDRA_TRACE_BEGIN marker; treat this as an incomplete wait/trace lifecycle, not proof that symbols are absent.",
        ]
        if requested:
            guidance.append(f"Retry with a longer-lived target, direct PID attach, or a lower-level spawn/wait strategy before changing symbols: {', '.join(requested[:3])}.")
        return guidance
    if trace_status in {"partial_timeout", "partial_failed"}:
        guidance = [
            "LLDB preserved runtime hits but the trace command did not exit cleanly; use the enriched hit evidence, but keep the run classified as partial until the lifecycle issue is fixed.",
        ]
        if requested:
            guidance.append(f"Retry the same symbols with a longer-lived target or narrower breakpoint set before changing targets: {', '.join(requested[:3])}.")
        return guidance
    if trace_status == "breakpoints_no_hits":
        guidance = [
            "Breakpoints resolved but did not fire during the bounded window; keep the resolved symbol and trigger the owning subsystem instead of changing probes first.",
        ]
        if target:
            guidance.append(f"Repeat against the same target context ({target}) with a deliberate owning-subsystem trigger or a longer timeout.")
        return guidance
    return []


def _symbol_export_guidance(steps: list[dict], binary: str) -> list[str]:
    if not binary or not _looks_like_system_framework_path(binary):
        return []
    for step in steps:
        if step.get("label") != "lldb symbols" or step.get("returncode") == 0:
            continue
        text = "\n".join([str(step.get("stdout_tail", "")), str(step.get("stderr_tail", ""))]).lower()
        if "binary not found" not in text:
            continue
        return [
            "LLDB static symbol export could not read the supplied /System framework path. On modern macOS, live /System framework paths may be dyld-cache stubs without an on-disk Mach-O; pass the extracted dyld-cache binary for --binary and keep the live process as the trace target.",
        ]
    return []


def _looks_like_system_framework_path(path: str) -> bool:
    normalized = str(path or "")
    return normalized.startswith("/System/Library/") and ".framework/" in normalized


def _clean_stderr(stderr: str) -> str:
    lines = []
    for line in str(stderr or "").splitlines():
        lowered = line.lower()
        if "terminated: 15" in lowered and "sleep" in lowered and "kill -term" in lowered:
            continue
        lines.append(line)
    return "\n".join(lines)


def _ensure_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", errors="replace")
    return str(value)
