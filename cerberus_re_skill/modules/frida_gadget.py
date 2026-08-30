"""Owned-process Frida Gadget launch probes with immutable lifecycle evidence."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
from typing import Any, Iterable

from cerberus_re_skill.core.utils import utc_now, write_json_atomic
from cerberus_re_skill.modules.probe_plan import (
    build_executable_identity,
    build_probe_plan,
    build_target_identity,
    materialize_helper,
    new_probe_lifecycle,
    record_lifecycle_event,
    summarize_probe_lifecycle,
    write_probe_lifecycle,
    write_probe_plan,
)


REPORT_SCHEMA = "cerberus.frida-gadget-probe.v1"
EVENT_SCHEMA = "cerberus.frida-gadget-event.v1"
LAUNCH_SCHEMA = "cerberus.frida-gadget-launch.v1"
EVENT_PREFIX = "CERBERUS_FRIDA_GADGET "
_HELPER_NAME = re.compile(r"^[A-Za-z0-9_.-]+$")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _required_file(value: str | Path, label: str) -> Path:
    path = Path(value).expanduser().resolve()
    if not path.is_file():
        raise RuntimeError(f"{label} is not a file: {path}")
    return path


def _stage_identity(identity: dict[str, Any], destination: Path) -> None:
    source = Path(identity["path"])
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() or destination.is_symlink():
        if (
            not destination.is_file()
            or destination.stat().st_size != identity["size"]
            or _sha256_file(destination) != identity["sha256"]
        ):
            raise RuntimeError(f"staged helper conflicts with immutable identity: {destination}")
        return
    os.link(source, destination)
    if destination.stat().st_size != identity["size"] or _sha256_file(
        destination
    ) != identity["sha256"]:
        raise RuntimeError(f"staged helper failed verification: {destination}")


def _parse_events(output: str) -> tuple[list[dict[str, Any]], list[str]]:
    events: list[dict[str, Any]] = []
    errors: list[str] = []
    for line in output.splitlines():
        if not line.startswith(EVENT_PREFIX):
            continue
        try:
            event = json.loads(line[len(EVENT_PREFIX) :])
        except json.JSONDecodeError as exc:
            errors.append(f"invalid Gadget event JSON: {exc}")
            continue
        if not isinstance(event, dict) or event.get("schema") != EVENT_SCHEMA:
            errors.append("Gadget event had an unexpected schema")
            continue
        events.append(event)
    return events, errors


def _signal_name(return_code: int) -> str:
    if return_code >= 0:
        return ""
    try:
        return signal.Signals(-return_code).name
    except ValueError:
        return f"SIGNAL_{-return_code}"


def _communicate_owned(
    process: subprocess.Popen[str],
    timeout_seconds: float,
) -> tuple[str, bool, bool]:
    """Capture output and terminate only the child launched by this probe."""
    try:
        output, _ = process.communicate(timeout=timeout_seconds)
        return output or "", False, False
    except subprocess.TimeoutExpired as exc:
        partial = exc.output or ""
        if isinstance(partial, bytes):
            partial = partial.decode(errors="replace")
        process.terminate()
        forced = False
        try:
            output, _ = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            forced = True
            output, _ = process.communicate(timeout=5)
        output = output or partial
        if partial and partial not in output:
            output = partial + output
        return output, True, forced


def run_frida_gadget_probe(
    target: str | Path,
    gadget: str | Path,
    script: str | Path,
    output_dir: str | Path,
    *,
    stable_target_key: str,
    timeout_seconds: float = 5.0,
    arguments: Iterable[str] = (),
    parameters: dict[str, Any] | None = None,
    architecture: str = "",
    allow_runtime: bool = False,
) -> dict[str, Any]:
    """Stage and optionally launch one owned process with Frida Gadget."""
    if not stable_target_key.strip():
        raise RuntimeError("stable_target_key must not be empty")
    if timeout_seconds <= 0:
        raise RuntimeError("timeout_seconds must be positive")
    target_path = _required_file(target, "target")
    gadget_path = _required_file(gadget, "gadget")
    script_path = _required_file(script, "script")
    out = Path(output_dir).expanduser().resolve()
    out.mkdir(parents=True, exist_ok=True)
    helper_root = out / "helpers"
    argument_list = [str(argument) for argument in arguments]

    script_name = script_path.name if _HELPER_NAME.fullmatch(script_path.name) else "probe.js"
    script_identity = materialize_helper(helper_root, script_name, script_path.read_bytes())
    gadget_identity = materialize_helper(
        helper_root,
        "FridaGadget.dylib",
        gadget_path.read_bytes(),
    )
    config = {
        "interaction": {
            "type": "script",
            "path": script_name,
            "parameters": parameters or {},
        },
        "teardown": "full",
    }
    config_bytes = (json.dumps(config, indent=2, sort_keys=True) + "\n").encode("utf-8")
    config_identity = materialize_helper(
        helper_root,
        "FridaGadget.config",
        config_bytes,
    )

    executable = build_executable_identity(
        target_path,
        architecture=architecture or platform.machine(),
    )
    target_identity = build_target_identity(
        stable_target_key,
        executable,
        display_name=target_path.name,
        platform="macos" if platform.system() == "Darwin" else platform.system().lower(),
        architecture=architecture or platform.machine(),
    )
    launch_manifest = {
        "schema": LAUNCH_SCHEMA,
        "target_executable_id": executable["executable_id"],
        "arguments": argument_list,
    }
    launch_identity = materialize_helper(
        helper_root,
        "launch.json",
        (json.dumps(launch_manifest, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )
    plan_path = out / "probe-plan.json"
    lifecycle_path = out / "probe-lifecycle.json"
    output_path = out / "gadget-output.txt"
    report_path = out / "gadget-report.json"
    plan = build_probe_plan(
        target_identity,
        transport="frida",
        mode="launch",
        timeout_seconds=max(1, int(timeout_seconds)),
        detach_policy="always",
        kill_policy="owned-only-on-timeout",
        helpers=[gadget_identity, config_identity, script_identity, launch_identity],
        outputs={
            "lifecycle": lifecycle_path,
            "raw_output": output_path,
            "report": report_path,
        },
    )
    write_probe_plan(plan_path, plan)
    lifecycle = new_probe_lifecycle(plan["plan_id"])

    def record(phase: str, outcome: str, details: dict[str, Any]) -> None:
        record_lifecycle_event(lifecycle, phase, outcome, details=details)
        write_probe_lifecycle(lifecycle_path, lifecycle)

    stage = out / "staging" / plan["plan_id"].removeprefix("sha256:")
    staged_gadget = stage / "FridaGadget.dylib"
    staged_config = stage / "FridaGadget.config"
    staged_script = stage / script_name
    staged_launch = stage / "launch.json"
    _stage_identity(gadget_identity, staged_gadget)
    _stage_identity(config_identity, staged_config)
    _stage_identity(script_identity, staged_script)
    _stage_identity(launch_identity, staged_launch)
    record(
        "preflight",
        "succeeded",
        {
            "gadget_sha256": gadget_identity["sha256"],
            "script_sha256": script_identity["sha256"],
            "stage": str(stage),
        },
    )

    base_report: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "created_at": utc_now(),
        "plan_id": plan["plan_id"],
        "plan_path": str(plan_path),
        "lifecycle_path": str(lifecycle_path),
        "report_path": str(report_path),
        "target": target_identity,
        "gadget": gadget_identity,
        "config": config_identity,
        "script": script_identity,
        "launch": launch_identity,
        "stage": str(stage),
        "raw_output": str(output_path),
        "runtime_attempted": allow_runtime,
    }
    if not allow_runtime:
        output_path.write_text("", encoding="utf-8")
        record("launch", "skipped", {"reason": "allow_runtime was not set"})
        report = {
            **base_report,
            "ok": True,
            "status": "skipped",
            "events": [],
            "event_errors": [],
            "hit_count": 0,
            "objc_exception_count": 0,
            "crash_backtrace_count": 0,
            "lifecycle_summary": summarize_probe_lifecycle(lifecycle),
        }
        write_json_atomic(report_path, report)
        return report

    command = [str(target_path), *argument_list]
    environment = dict(os.environ)
    environment["DYLD_INSERT_LIBRARIES"] = str(staged_gadget)
    try:
        process = subprocess.Popen(
            command,
            cwd=target_path.parent,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
        )
    except OSError as exc:
        output_path.write_text("", encoding="utf-8")
        record(
            "launch",
            "failed",
            {"error": str(exc), "error_type": type(exc).__name__, "command": command},
        )
        report = {
            **base_report,
            "ok": False,
            "status": "failed",
            "error": str(exc),
            "error_type": type(exc).__name__,
            "events": [],
            "event_errors": [],
            "hit_count": 0,
            "objc_exception_count": 0,
            "crash_backtrace_count": 0,
            "lifecycle_summary": summarize_probe_lifecycle(lifecycle),
        }
        write_json_atomic(report_path, report)
        return report
    record("launch", "started", {"pid": process.pid, "command": command})
    output, window_elapsed, forced_kill = _communicate_owned(process, timeout_seconds)
    output_path.write_text(output, encoding="utf-8")
    events, event_errors = _parse_events(output)
    initialized = next((item for item in events if item.get("event") == "initialized"), None)
    rejected = next((item for item in events if item.get("event") == "rejected"), None)
    hits = [item for item in events if item.get("event") == "hit"]
    exceptions = [item for item in events if item.get("event") == "objc-exception"]
    crash_backtraces = [item for item in events if item.get("event") == "crash-backtrace"]
    return_code = int(process.returncode or 0)
    crash_observed = return_code < 0 and not window_elapsed

    if initialized:
        record("launch", "succeeded", {"pid": process.pid, "module": initialized.get("module")})
    elif rejected:
        record("launch", "failed", {"pid": process.pid, "rejection": rejected})
    else:
        record("launch", "failed", {"pid": process.pid, "reason": "no initialization event"})
    if hits:
        record("hit", "observed", {"count": len(hits)})
    elif initialized:
        record("hit", "not_observed", {"window_seconds": timeout_seconds})
    if window_elapsed:
        record("liveness", "observed", {"pid": process.pid, "at_window_end": True})
        record("detach", "succeeded", {"forced_kill": forced_kill, "owned_pid": process.pid})
    if crash_observed:
        record(
            "crash",
            "observed",
            {
                "pid": process.pid,
                "return_code": return_code,
                "signal": _signal_name(return_code),
                "backtrace_count": len(crash_backtraces),
            },
        )

    if crash_observed:
        status = "crash"
    elif rejected:
        status = "rejected"
    elif hits:
        status = "hit"
    elif initialized:
        status = "no_hit"
    else:
        status = "failed"
    report = {
        **base_report,
        "ok": status in {"hit", "no_hit"},
        "status": status,
        "pid": process.pid,
        "return_code": return_code,
        "signal": _signal_name(return_code) if crash_observed else "",
        "window_elapsed": window_elapsed,
        "forced_kill": forced_kill,
        "events": events,
        "event_errors": event_errors,
        "hit_count": len(hits),
        "objc_exception_count": len(exceptions),
        "crash_backtrace_count": len(crash_backtraces),
        "lifecycle_summary": summarize_probe_lifecycle(lifecycle),
    }
    write_json_atomic(report_path, report)
    return report
