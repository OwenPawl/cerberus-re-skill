"""Structured Frida diagnostics, no-attach validation, and guarded runtime rechecks."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, Sequence

from cerberus_re_skill.core.config import cfg
from cerberus_re_skill.core.subprocess_utils import find_tool
from cerberus_re_skill.core.utils import timestamp, utc_now
from cerberus_re_skill.modules.frida_diagnostics import collect_frida_diagnostics, frida_cli_command, known_frida_tool
from cerberus_re_skill.modules.frida_scripts import (
    _split_symbols,
    generate_frida_heap_scan_script,
    generate_frida_native_trace_script,
    generate_frida_selector_trace_script,
    generate_frida_trace_script,
)
from cerberus_re_skill.modules.runtime_hits import normalize_frida_console_hits, write_runtime_hits_artifact


Runner = Callable[[Sequence[str], float], dict]
_DEFAULT_OBJC_TRACE_SYMBOL = "-[NSObject description]"


def write_frida_diagnostic_artifact(
    *,
    target: str | Path | None = None,
    output_dir: str | Path | None = None,
    runner: Runner | None = None,
) -> dict:
    report_dir = _report_dir(output_dir, "diagnostics")
    run = runner or _run_command
    diagnostics = collect_frida_diagnostics(target)
    boot_args = _boot_args(run)
    helper_blocked = any(
        item.level == "WARN" and ("amfi_get_out_of_my_way=1" in item.value or "frida-helper" in item.value)
        for item in diagnostics
    )
    report = {
        "schema": "ghidra-re.frida-diagnostics.v1",
        "ok": True,
        "status": "blocked-by-host-policy" if helper_blocked else "diagnosed",
        "created_at": utc_now(),
        "target": str(target or ""),
        "diagnostics": [item.__dict__ for item in diagnostics],
        "boot_args": boot_args,
        "runtime_attach_blocked": helper_blocked,
    }
    return _write_report(report_dir, "frida-diagnostics", report)


def validate_no_attach_scripts(
    *,
    output_dir: str | Path | None = None,
    symbol: str = "-[CodexProbe greet:]",
    class_name: str = "CodexProbe",
    runner: Runner | None = None,
) -> dict:
    report_dir = _report_dir(output_dir, "scripts")
    run = runner or _run_command
    trace_js = report_dir / "frida_trace.js"
    heap_js = report_dir / "frida_heap.js"
    trace = generate_frida_trace_script(symbol, trace_js)
    heap = generate_frida_heap_scan_script(class_name, heap_js)
    node = shutil.which("node")
    checks = []
    if node:
        checks.append({"label": "trace JavaScript syntax", **run([node, "--check", str(trace_js)], 60)})
        checks.append({"label": "heap JavaScript syntax", **run([node, "--check", str(heap_js)], 60)})
    else:
        checks.append({"label": "node", "returncode": 127, "stdout": "", "stderr": "node not found"})
    ok = all(check["returncode"] == 0 for check in checks)
    report = {
        "schema": "ghidra-re.frida-no-attach.v1",
        "ok": ok,
        "created_at": utc_now(),
        "trace": trace,
        "heap": heap,
        "checks": checks,
    }
    return _write_report(report_dir, "frida-no-attach", report)


def recheck_runtime_attach(
    *,
    target: str | Path | None = None,
    attach_pid: int | None = None,
    attach_name: str = "",
    await_regex: str = "",
    output_dir: str | Path | None = None,
    allow_runtime: bool = False,
    symbol: str | Sequence[str] = "-[NSObject description]",
    selectors: Sequence[str] | None = None,
    class_filters: Sequence[str] | None = None,
    exact_classes: Sequence[str] | None = None,
    max_selector_hooks: int = 128,
    native_symbols: Sequence[str] | None = None,
    addresses: Sequence[str] | None = None,
    capture_returns: bool = False,
    native_wait_seconds: float = 0.0,
    native_arg_preview: bool = False,
    target_args: Sequence[str] | None = None,
    pre_run_delay_seconds: float = 0.0,
    readiness_marker: str = "",
    require_readiness_marker: bool = False,
    require_runtime_hit: bool = False,
    timeout_seconds: float = 10.0,
    runner: Runner | None = None,
) -> dict:
    report_dir = _report_dir(output_dir, "runtime")
    attach_name_pattern = str(attach_name or "").strip()
    await_pattern = str(await_regex or "").strip()
    attach_modes = [target is not None, attach_pid is not None, bool(attach_name_pattern), bool(await_pattern)]
    if sum(1 for active in attach_modes if active) != 1:
        raise RuntimeError("exactly one of target, attach_pid, attach_name, or await_regex is required")
    if (attach_pid is not None or attach_name_pattern or await_pattern) and target_args:
        raise RuntimeError("target_args can only be used when spawning --target")
    target_path = Path(target) if target is not None else None
    target_argv = [str(arg) for arg in (target_args or [])]
    trace_js = report_dir / "frida_runtime_probe.js"
    selector_list = [str(item) for item in (selectors or []) if str(item).strip()]
    class_filter_list = [str(item) for item in (class_filters or []) if str(item).strip()]
    exact_class_list = [str(item) for item in (exact_classes or []) if str(item).strip()]
    symbol_list = _split_symbols(symbol)
    native_symbol_list = [str(item) for item in (native_symbols or []) if str(item).strip()]
    address_list = [str(item) for item in (addresses or []) if str(item).strip()]
    native_wait = max(0.0, float(native_wait_seconds or 0.0))
    if (selector_list or native_symbol_list or address_list) and symbol_list == [_DEFAULT_OBJC_TRACE_SYMBOL]:
        symbol_list = []
    if selector_list and symbol_list:
        raise RuntimeError("--symbol cannot be combined with --selector; run exact ObjC method and selector-wide rechecks separately")
    if selector_list and (native_symbol_list or address_list):
        raise RuntimeError("--selector cannot be combined with native hooks")
    if symbol_list and (native_symbol_list or address_list):
        raise RuntimeError("--symbol cannot be combined with native hooks; run ObjC and native rechecks separately")
    if not (selector_list or native_symbol_list or address_list or symbol_list):
        symbol_list = [_DEFAULT_OBJC_TRACE_SYMBOL]
    hook_mode = "native" if native_symbol_list or address_list else ("objc-selector" if selector_list else "objc")
    if hook_mode == "native":
        trace = generate_frida_native_trace_script(
            symbols=native_symbol_list,
            addresses=address_list,
            output=trace_js,
            capture_returns=capture_returns,
            native_wait_seconds=native_wait,
            native_arg_preview=native_arg_preview,
        )
    elif hook_mode == "objc-selector":
        trace = generate_frida_selector_trace_script(
            selector_list,
            trace_js,
            class_filters=class_filter_list,
            exact_classes=exact_class_list,
            max_hooks=max_selector_hooks,
            capture_returns=capture_returns,
        )
    else:
        trace = generate_frida_trace_script(symbol_list, trace_js, capture_returns=capture_returns)
    program_name = target_path.name if target_path else f"pid-{attach_pid}"
    if attach_name_pattern:
        program_name = f"name:{attach_name_pattern}"
    if await_pattern:
        program_name = f"await:{await_pattern}"
    if not allow_runtime:
        report = {
            "schema": "ghidra-re.frida-runtime-recheck.v1",
            "ok": True,
            "status": "skipped",
            "created_at": utc_now(),
            "target": str(target_path or ""),
            "attach_pid": attach_pid,
            "attach_name": attach_name_pattern,
            "resolved_attach_pid": None,
            "await_regex": await_pattern,
            "target_args": target_argv,
            "symbol": symbol,
            "symbols": symbol_list,
            "selectors": selector_list,
            "class_filters": class_filter_list,
            "exact_classes": exact_class_list,
            "max_selector_hooks": max_selector_hooks,
            "native_symbols": native_symbol_list,
            "addresses": address_list,
            "hook_mode": hook_mode,
            "capture_returns": capture_returns,
            "native_wait_seconds": native_wait,
            "native_arg_preview": native_arg_preview,
            "pre_run_delay_seconds": pre_run_delay_seconds,
            "readiness_marker": readiness_marker,
            "require_readiness_marker": require_readiness_marker,
            "require_runtime_hit": require_runtime_hit,
            "trace": trace,
            "native_target_hits": [],
            "native_missing_targets": [],
            "native_zero_hit_targets": [],
            "native_unqualified_zero_hit_targets": [],
            "message": "Runtime attach recheck skipped; pass --allow-runtime to spawn or attach with Frida.",
        }
        return _write_report(report_dir, "frida-runtime-recheck", report)

    frida = known_frida_tool("frida") or find_tool("frida")
    if not frida:
        report = {
            "schema": "ghidra-re.frida-runtime-recheck.v1",
            "ok": False,
            "status": "blocked",
            "created_at": utc_now(),
            "target": str(target_path or ""),
            "attach_pid": attach_pid,
            "attach_name": attach_name_pattern,
            "resolved_attach_pid": None,
            "await_regex": await_pattern,
            "target_args": target_argv,
            "symbol": symbol,
            "symbols": symbol_list,
            "selectors": selector_list,
            "class_filters": class_filter_list,
            "exact_classes": exact_class_list,
            "max_selector_hooks": max_selector_hooks,
            "native_symbols": native_symbol_list,
            "addresses": address_list,
            "hook_mode": hook_mode,
            "capture_returns": capture_returns,
            "native_wait_seconds": native_wait,
            "native_arg_preview": native_arg_preview,
            "pre_run_delay_seconds": pre_run_delay_seconds,
            "readiness_marker": readiness_marker,
            "require_readiness_marker": require_readiness_marker,
            "require_runtime_hit": require_runtime_hit,
            "native_target_hits": [],
            "native_missing_targets": [],
            "native_zero_hit_targets": [],
            "native_unqualified_zero_hit_targets": [],
            "error": "frida CLI not found",
        }
        return _write_report(report_dir, "frida-runtime-recheck", report)

    run = runner or _run_command
    resolved_attach_pid = attach_pid
    if attach_name_pattern:
        resolved_attach_pid = _wait_for_process_name(attach_name_pattern, timeout_seconds, run)
        if resolved_attach_pid is None:
            runtime_hits_json = report_dir / "runtime_hits.json"
            runtime_hits_payload = write_runtime_hits_artifact(
                runtime_hits_json,
                project="",
                program=program_name,
                hits=[],
                source=trace_js,
            )
            report = {
                "schema": "ghidra-re.frida-runtime-recheck.v1",
                "ok": False,
                "status": "blocked",
                "created_at": utc_now(),
                "target": str(target_path or ""),
                "attach_pid": None,
                "attach_name": attach_name_pattern,
                "resolved_attach_pid": None,
                "await_regex": await_pattern,
                "target_args": target_argv,
                "symbol": symbol,
                "symbols": symbol_list,
                "selectors": selector_list,
                "class_filters": class_filter_list,
                "exact_classes": exact_class_list,
                "max_selector_hooks": max_selector_hooks,
                "native_symbols": native_symbol_list,
                "addresses": address_list,
                "hook_mode": hook_mode,
                "capture_returns": capture_returns,
                "native_wait_seconds": native_wait,
                "native_arg_preview": native_arg_preview,
                "pre_run_delay_seconds": pre_run_delay_seconds,
                "readiness_marker": readiness_marker,
                "readiness_observed": False,
                "require_readiness_marker": require_readiness_marker,
                "require_runtime_hit": require_runtime_hit,
                "trace": trace,
                "command": [],
                "result": {
                    "returncode": 124,
                    "stdout": "",
                    "stderr": f"timed out waiting for process matching {attach_name_pattern!r}",
                    "command": [],
                },
                "frida_helper_crashed": False,
                "frida_event_summary": summarize_frida_console_events(""),
                "native_target_hits": [],
                "native_missing_targets": [],
                "native_zero_hit_targets": [],
                "native_unqualified_zero_hit_targets": [],
                "runtime_hits_json": str(runtime_hits_json),
                "runtime_hit_count": runtime_hits_payload["hit_count"],
            }
            return _write_report(report_dir, "frida-runtime-recheck", report)

    command = [*frida_cli_command("frida", frida)]
    if resolved_attach_pid is not None:
        command.extend(["-p", str(resolved_attach_pid)])
    elif await_pattern:
        command.extend(["-W", await_pattern])
    else:
        command.extend(["-f", str(target_path)])
    command.extend(["-l", str(trace_js), "--runtime=v8", "-q", "-t", _frida_quiet_timeout(timeout_seconds)])
    if target_argv:
        command.extend(["--", *target_argv])
    if pre_run_delay_seconds > 0:
        time.sleep(pre_run_delay_seconds)
    result = run(command, timeout_seconds)
    combined_text = f"{result.get('stdout', '')}\n{result.get('stderr', '')}"
    combined = combined_text.lower()
    helper_crashed = "frida-helper" in combined and "crash" in combined
    readiness_observed = readiness_marker in combined_text if readiness_marker else False
    event_summary = summarize_frida_console_events(combined_text)
    runtime_hits = normalize_frida_console_hits(
        combined_text,
        program=program_name,
        source_artifact=trace_js,
    )
    runtime_hits_json = report_dir / "runtime_hits.json"
    runtime_hits_payload = write_runtime_hits_artifact(
        runtime_hits_json,
        project="",
        program=program_name,
        hits=runtime_hits,
        source=trace_js,
    )
    runtime_hit_count = runtime_hits_payload["hit_count"]
    native_target_hits = summarize_native_runtime_targets(
        native_symbols=native_symbol_list,
        addresses=address_list,
        event_summary=event_summary,
        runtime_hits=runtime_hits,
    )
    installed_count = _installed_hook_count(event_summary)
    hook_installation_inferred_from_hits = installed_count == 0 and runtime_hit_count > 0
    hook_installation_observed = installed_count > 0 or runtime_hit_count > 0
    target_failure_observed = _target_failure_observed(combined_text)
    native_zero_hit_targets = [
        item["label"] for item in native_target_hits if item.get("installed") and int(item.get("hit_count") or 0) == 0
    ]
    native_unqualified_zero_hit_targets = _native_unqualified_zero_hit_targets(native_target_hits)
    attach_timeout_with_evidence = (resolved_attach_pid is not None or await_pattern) and result["returncode"] == 124 and (
        installed_count > 0 or runtime_hit_count > 0
    )
    ok = (result["returncode"] == 0 or attach_timeout_with_evidence) and (
        not require_readiness_marker or readiness_observed
    ) and (
        not require_runtime_hit or runtime_hit_count > 0
    ) and not target_failure_observed
    status = "passed" if ok else "blocked"
    if target_failure_observed and runtime_hit_count > 0:
        status = "target-failed-after-runtime-hit"
    elif not ok and require_runtime_hit and runtime_hit_count == 0 and hook_installation_observed:
        status = "no-runtime-hits"
    runtime_guidance = _runtime_guidance(
        hook_mode=hook_mode,
        native_wait=native_wait,
        installed_count=installed_count,
        runtime_hit_count=runtime_hit_count,
        event_summary=event_summary,
        result=result,
        readiness_marker=readiness_marker,
        readiness_observed=readiness_observed,
    )
    runtime_guidance.extend(_native_module_ambiguity_guidance(native_unqualified_zero_hit_targets))
    report = {
        "schema": "ghidra-re.frida-runtime-recheck.v1",
        "ok": ok,
        "status": status,
        "created_at": utc_now(),
        "target": str(target_path or ""),
        "attach_pid": resolved_attach_pid,
        "attach_name": attach_name_pattern,
        "resolved_attach_pid": resolved_attach_pid if attach_name_pattern else None,
        "await_regex": await_pattern,
        "target_args": target_argv,
        "symbol": symbol,
        "symbols": symbol_list,
        "selectors": selector_list,
        "class_filters": class_filter_list,
        "exact_classes": exact_class_list,
        "max_selector_hooks": max_selector_hooks,
        "native_symbols": native_symbol_list,
        "addresses": address_list,
        "hook_mode": hook_mode,
        "capture_returns": capture_returns,
        "native_wait_seconds": native_wait,
        "native_arg_preview": native_arg_preview,
        "pre_run_delay_seconds": pre_run_delay_seconds,
        "readiness_marker": readiness_marker,
        "readiness_observed": readiness_observed,
        "require_readiness_marker": require_readiness_marker,
        "require_runtime_hit": require_runtime_hit,
        "trace": trace,
        "command": command,
        "result": result,
        "frida_helper_crashed": helper_crashed,
        "hook_installation_observed": hook_installation_observed,
        "hook_installation_inferred_from_hits": hook_installation_inferred_from_hits,
        "target_failure_observed": target_failure_observed,
        "frida_event_summary": event_summary,
        "native_target_hits": native_target_hits,
        "native_missing_targets": _explicit_native_missing_targets(event_summary),
        "native_zero_hit_targets": native_zero_hit_targets,
        "native_unqualified_zero_hit_targets": native_unqualified_zero_hit_targets,
        "runtime_guidance": runtime_guidance,
        "runtime_hits_json": str(runtime_hits_json),
        "runtime_hit_count": runtime_hit_count,
    }
    return _write_report(report_dir, "frida-runtime-recheck", report)


def _wait_for_process_name(pattern: str, timeout_seconds: float, runner: Runner) -> int | None:
    deadline = time.time() + max(0.1, timeout_seconds)
    while time.time() < deadline:
        result = runner(["ps", "-axo", "pid=,command="], min(5.0, max(0.1, deadline - time.time())))
        if result.get("returncode") == 0:
            pid = _find_process_name_match(pattern, result.get("stdout", ""))
            if pid is not None:
                return pid
        time.sleep(0.25)
    return None


def _find_process_name_match(pattern: str, ps_output: str) -> int | None:
    try:
        regex = re.compile(pattern)
    except re.error:
        regex = re.compile(re.escape(pattern))
    ignored_pid = os.getpid()
    ignored_parent = os.getppid()
    for raw_line in str(ps_output or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        pid_text, _, command = line.partition(" ")
        try:
            pid = int(pid_text)
        except ValueError:
            continue
        if pid in {ignored_pid, ignored_parent}:
            continue
        if _looks_like_self_match(command):
            continue
        if regex.search(command):
            return pid
    return None


def _looks_like_self_match(command: str) -> bool:
    needles = [
        "cerberus_re_skill",
        "frida_validation",
        "frida recheck-attach",
        "mission_harness.py",
        "watch_live_file.py",
    ]
    return any(needle in command for needle in needles)


def _report_dir(output_dir: str | Path | None, name: str) -> Path:
    path = Path(output_dir) if output_dir else cfg.logs_dir / "frida" / f"{name}-{timestamp()}"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _run_command(command: Sequence[str], timeout_seconds: float) -> dict:
    try:
        result = subprocess.run(
            [str(part) for part in command],
            shell=False,
            check=False,
            capture_output=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "returncode": 124,
            "stdout": _decode(exc.stdout),
            "stderr": _decode(exc.stderr) or "timed out",
            "command": [str(part) for part in command],
        }
    except OSError as exc:
        return {"returncode": 127, "stdout": "", "stderr": str(exc), "command": [str(part) for part in command]}
    return {
        "returncode": result.returncode,
        "stdout": _decode(result.stdout),
        "stderr": _decode(result.stderr),
        "command": [str(part) for part in command],
    }


def _frida_quiet_timeout(timeout_seconds: float) -> str:
    return f"{max(0.1, timeout_seconds - 0.5):g}"


def _target_failure_observed(text: str) -> bool:
    lower = str(text or "").lower()
    return any(
        marker in lower
        for marker in (
            "fatal error:",
            "terminating due to uncaught exception",
            "abort trap:",
            "segmentation fault:",
        )
    )


def summarize_frida_console_events(text: str) -> dict[str, Any]:
    """Summarize generated Frida control lines without losing raw stdout."""
    prefixes = {
        "GHIDRA_FRIDA_WAITING_CLASS": ("waiting_class_count", "waiting_classes"),
        "GHIDRA_FRIDA_INSTALLED": ("installed_count", "installed_symbols"),
        "GHIDRA_FRIDA_MISSING_CLASS": ("missing_class_count", "missing_classes"),
        "GHIDRA_FRIDA_MISSING_METHOD": ("missing_method_count", "missing_methods"),
        "GHIDRA_FRIDA_NATIVE_INSTALLED": ("native_installed_count", "native_installed"),
        "GHIDRA_FRIDA_NATIVE_MISSING": ("native_missing_count", "native_missing"),
        "GHIDRA_FRIDA_NATIVE_ERROR": ("native_error_count", "native_errors"),
        "GHIDRA_FRIDA_SELECTOR_INSTALLED": ("selector_installed_count", "selector_installed"),
        "GHIDRA_FRIDA_SELECTOR_ALIAS": ("selector_alias_count", "selector_aliases"),
        "GHIDRA_FRIDA_SELECTOR_NO_MATCH": ("selector_no_match_count", "selector_no_match"),
        "GHIDRA_FRIDA_SELECTOR_SKIPPED_LIMIT": ("selector_skipped_limit_count", "selector_skipped_limit"),
        "GHIDRA_FRIDA_SELECTOR_ENUM_ERROR": ("selector_enumeration_error_count", "selector_enumeration_errors"),
        "GHIDRA_FRIDA_SELECTOR_CLASS_ERROR": ("selector_class_error_count", "selector_class_errors"),
    }
    summary: dict[str, Any] = {count_key: 0 for count_key, _ in prefixes.values()}
    seen: dict[str, set[str]] = {list_key: set() for _, list_key in prefixes.values()}
    for raw_line in str(text or "").splitlines():
        line = raw_line.strip()
        for prefix, (count_key, list_key) in prefixes.items():
            marker = prefix + " "
            if not line.startswith(marker):
                continue
            value = line[len(marker):].strip()
            summary[count_key] += 1
            if value:
                seen[list_key].add(value)
            break
    for list_key, values in seen.items():
        summary[list_key] = sorted(values)
    return summary


def summarize_native_runtime_targets(
    *,
    native_symbols: Sequence[str],
    addresses: Sequence[str],
    event_summary: dict[str, Any],
    runtime_hits: Sequence[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return per-native-target call/return counts for installed hooks."""
    requested = _ordered_unique([*native_symbols, *addresses])
    installed = _installed_native_targets(event_summary)
    labels = _ordered_unique([*requested, *installed.keys()])
    if not labels:
        return []
    counts: dict[str, dict[str, int]] = {label: {"call_count": 0, "return_count": 0} for label in labels}
    for hit in runtime_hits:
        target = hit.get("target") if isinstance(hit.get("target"), dict) else {}
        label = str(target.get("label") or target.get("symbol") or hit.get("symbol") or "")
        if not label:
            continue
        if label not in counts:
            counts[label] = {"call_count": 0, "return_count": 0}
            labels.append(label)
        event_type = str(hit.get("event_type") or "")
        if event_type.endswith("return"):
            counts[label]["return_count"] += 1
        else:
            counts[label]["call_count"] += 1
    rows: list[dict[str, Any]] = []
    for label in labels:
        call_count = counts.get(label, {}).get("call_count", 0)
        return_count = counts.get(label, {}).get("return_count", 0)
        installed_info = installed.get(label, {})
        rows.append(
            {
                "label": label,
                "installed": label in installed,
                "address": installed_info.get("address", ""),
                "call_count": call_count,
                "return_count": return_count,
                "hit_count": call_count + return_count,
            }
        )
    return rows


def _installed_native_targets(event_summary: dict[str, Any]) -> dict[str, dict[str, str]]:
    installed: dict[str, dict[str, str]] = {}
    for value in event_summary.get("native_installed", []) if isinstance(event_summary, dict) else []:
        text = str(value).strip()
        if not text:
            continue
        label, address = _split_installed_native(text)
        installed[label] = {"address": address}
    return installed


def _explicit_native_missing_targets(event_summary: dict[str, Any]) -> list[str]:
    if not isinstance(event_summary, dict):
        return []
    return _ordered_unique([str(item) for item in event_summary.get("native_missing", [])])


def _native_unqualified_zero_hit_targets(native_target_hits: Sequence[dict[str, Any]]) -> list[str]:
    return [
        label
        for item in native_target_hits
        if item.get("installed")
        and int(item.get("hit_count") or 0) == 0
        and (label := str(item.get("label") or "").strip())
        and _is_unqualified_native_label(label)
    ]


def _is_unqualified_native_label(label: str) -> bool:
    return "!" not in label and not label.lower().startswith("0x")


def _native_module_ambiguity_guidance(targets: Sequence[str]) -> list[str]:
    ordered = _ordered_unique([str(item) for item in targets])
    if not ordered:
        return []
    sample = ", ".join(ordered[:3])
    return [
        "Installed unqualified native hooks produced zero hits: "
        f"{sample}. If the intended export belongs to a specific framework or dylib, retry with Module!symbol "
        "to avoid same-name exports or wrapper-adjacent symbols in another module."
    ]


def _split_installed_native(value: str) -> tuple[str, str]:
    label, _, suffix = value.rpartition(" ")
    if label and suffix.startswith("0x"):
        return label, suffix
    return value, ""


def _ordered_unique(values: Sequence[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        ordered.append(text)
    return ordered


def _boot_args(runner: Runner) -> dict:
    if sys.platform != "darwin":
        return {"checked": False, "value": "", "error": "not macOS"}
    nvram = find_tool("nvram")
    if not nvram:
        return {"checked": False, "value": "", "error": "nvram not found"}
    result = runner([nvram, "boot-args"], 5)
    value = f"{result.get('stdout', '')}\n{result.get('stderr', '')}".strip()
    return {"checked": True, "value": value, "returncode": result.get("returncode", 0)}


def _write_report(report_dir: Path, stem: str, report: dict) -> dict:
    json_path = report_dir / f"{stem}.json"
    markdown_path = report_dir / f"{stem}.md"
    report["json_report"] = str(json_path)
    report["markdown_report"] = str(markdown_path)
    json_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    markdown_path.write_text(_render_markdown(report), encoding="utf-8")
    return report


def _installed_hook_count(summary: dict) -> int:
    return sum(
        int(summary.get(key) or 0)
        for key in ("installed_count", "native_installed_count", "selector_installed_count")
    )


def _runtime_guidance(
    *,
    hook_mode: str,
    native_wait: float,
    installed_count: int,
    runtime_hit_count: int,
    event_summary: dict[str, Any],
    result: dict[str, Any],
    readiness_marker: str,
    readiness_observed: bool,
) -> list[str]:
    guidance: list[str] = []
    native_missing = int(event_summary.get("native_missing_count") or 0)
    native_errors = int(event_summary.get("native_error_count") or 0)
    waiting_classes = int(event_summary.get("waiting_class_count") or 0)
    if (
        hook_mode == "native"
        and native_wait > 0
        and installed_count == 0
        and runtime_hit_count == 0
        and native_missing == 0
        and native_errors == 0
    ):
        guidance.append(
            "Native hooks produced no installed, missing, or hit evidence during the wait window; if the target dlopens the module and exits quickly, add an owned post-dlopen readiness marker or delay before the interesting call."
        )
        if not readiness_marker:
            guidance.append(
                "Retry with --readiness-marker and --require-readiness-marker after the target has loaded the framework so Frida can install late native exports before invocation."
            )
        if int(result.get("returncode") or 0) == 0:
            guidance.append("A clean target exit with no hook evidence is not proof that the native export is absent.")
    if hook_mode.startswith("objc") and installed_count > 0 and runtime_hit_count == 0:
        if not readiness_marker:
            guidance.append(
                "ObjC hooks installed but produced zero hits before the target exited; for short-lived owned probes, emit a readiness marker after class/framework loading and delay briefly before the interesting call so hook installation and invocation order are observable."
            )
        elif readiness_observed:
            guidance.append(
                "ObjC hooks installed and readiness was observed but produced zero hits; verify the trigger calls the hooked implementation, then retry with a longer pre-invocation delay before changing selectors."
            )
    if hook_mode == "objc" and waiting_classes > 0 and installed_count == 0 and runtime_hit_count == 0:
        if readiness_marker and readiness_observed:
            guidance.append(
                "Readiness was observed but ObjC classes were still waiting; spawned targets may invoke methods before deferred ObjC hooks install, so emit a class-ready marker after objc_getClass/NSClassFromString succeeds and keep the target alive briefly before the interesting call."
            )
        elif readiness_marker:
            guidance.append(
                "ObjC classes were still waiting and the readiness marker was not observed; retry with a marker emitted after the target framework and classes are loaded."
            )
        else:
            guidance.append(
                "ObjC classes were still waiting with no runtime hits; add an owned readiness marker or pre-invocation delay after class loading before the interesting call."
            )
    return guidance


def _render_markdown(report: dict) -> str:
    status = "PASS" if report.get("ok") else "BLOCKED"
    lines = [
        f"# Frida Report - {status}",
        "",
        f"- Schema: `{report.get('schema', '')}`",
        f"- Created: `{report.get('created_at', '')}`",
        f"- Status: `{report.get('status', 'ok')}`",
        f"- Target: `{report.get('target', '')}`",
        "",
        "## Summary",
        "",
    ]
    if report.get("diagnostics"):
        for item in report["diagnostics"]:
            lines.append(f"- `{item.get('level')}` {item.get('label')}: {item.get('value')}")
    elif report.get("checks"):
        for item in report["checks"]:
            state = "PASS" if item.get("returncode") == 0 else f"FAIL ({item.get('returncode')})"
            lines.append(f"- {state}: {item.get('label')}")
    elif report.get("message"):
        lines.append(f"- {report['message']}")
    elif report.get("result"):
        lines.append(f"- Frida return code: `{report['result'].get('returncode')}`")
        lines.append(f"- Frida helper crashed: `{report.get('frida_helper_crashed')}`")
        if report.get("attach_name"):
            lines.append(f"- Attach name: `{report.get('attach_name')}`")
            lines.append(f"- Resolved attach PID: `{report.get('resolved_attach_pid')}`")
        lines.append(f"- Target args: `{report.get('target_args', [])}`")
        if report.get("readiness_marker"):
            lines.append(f"- Readiness marker observed: `{report.get('readiness_observed')}`")
        if report.get("frida_event_summary"):
            summary = report["frida_event_summary"]
            lines.append(f"- Waiting classes: `{summary.get('waiting_class_count', 0)}`")
            lines.append(f"- Installed hooks: `{_installed_hook_count(summary)}`")
            lines.append(f"- Missing classes: `{summary.get('missing_class_count', 0)}`")
            lines.append(f"- Missing methods: `{summary.get('missing_method_count', 0)}`")
        lines.append(f"- Hook installation observed: `{report.get('hook_installation_observed', False)}`")
        if report.get("hook_installation_inferred_from_hits"):
            lines.append("- Hook installation was inferred from a preserved generated runtime hit.")
        lines.append(f"- Target failure observed: `{report.get('target_failure_observed', False)}`")
        lines.append(f"- Runtime hits: `{report.get('runtime_hit_count', 0)}`")
        lines.append(f"- Runtime hits JSON: `{report.get('runtime_hits_json', '')}`")
        if report.get("runtime_guidance"):
            lines.extend(["", "### Runtime Guidance", ""])
            for item in report.get("runtime_guidance") or []:
                lines.append(f"- {item}")
        if report.get("native_target_hits"):
            lines.extend(["", "### Native Target Hits", ""])
            for item in report["native_target_hits"]:
                state = "installed" if item.get("installed") else "not-installed"
                lines.append(
                    "- "
                    f"`{item.get('label')}`: {state}, "
                    f"calls={item.get('call_count', 0)}, returns={item.get('return_count', 0)}"
                )
            zero_hit = report.get("native_zero_hit_targets") or []
            missing = report.get("native_missing_targets") or []
            if missing:
                lines.append(f"- Missing native targets: `{', '.join(str(item) for item in missing)}`")
            if zero_hit:
                lines.append(f"- Installed zero-hit targets: `{', '.join(str(item) for item in zero_hit)}`")
        for label, text in (
            ("Frida stdout tail", report["result"].get("stdout")),
            ("Frida stderr tail", report["result"].get("stderr")),
        ):
            tail = _markdown_tail(text)
            if tail:
                lines.extend(["", f"### {label}", "", "```text", tail, "```"])
    lines.append("")
    return "\n".join(lines)


def _markdown_tail(text: str | None, *, limit: int = 1200) -> str:
    value = str(text or "").strip()
    if not value:
        return ""
    return value[-limit:]


def _decode(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return value.decode(errors="replace")
