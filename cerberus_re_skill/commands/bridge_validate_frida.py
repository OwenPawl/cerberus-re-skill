from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import typer

from cerberus_re_skill.cli_runtime import (
    app,
    bridge_app,
    validate_app,
    polish_app,
    frida_app,
    source_app,
    notes_app,
    import_app,
    export_app,
    publish_app,
    plugins_app,
    console,
    _die,
    _print_json,
)

@bridge_app.command("arm")
def bridge_arm(
    project: str = typer.Argument(..., help="Ghidra project name."),
    program: str = typer.Argument("", help="Program name (optional)."),
) -> None:
    """Arm the bridge for a project."""
    from cerberus_re_skill.modules.bridge import arm

    try:
        result = arm(project, program)
        _print_json(result)
    except Exception as e:
        _die(str(e))


@bridge_app.command("disarm")
def bridge_disarm(
    session: str = typer.Option("", help="Session ID to disarm."),
    project: str = typer.Option("", help="Project name to disarm."),
    program: str = typer.Option("", help="Program name to disarm."),
) -> None:
    """Disarm the bridge session."""
    from cerberus_re_skill.modules.bridge import disarm

    try:
        result = disarm(session, project, program)
        _print_json(result)
    except Exception as e:
        _die(str(e))


@bridge_app.command("close")
def bridge_close(
    session: str = typer.Option("", help="Session ID to close."),
    project: str = typer.Option("", help="Project name to close."),
    program: str = typer.Option("", help="Program name to close."),
    disarm_timeout: int = typer.Option(15, help="Seconds to wait for bridge disarm."),
    terminate_timeout: float = typer.Option(10.0, help="Seconds to wait after SIGTERM/taskkill."),
    kill_after_timeout: bool = typer.Option(
        True,
        "--kill-after-timeout/--no-kill-after-timeout",
        help="Escalate to SIGKILL/taskkill /F if graceful termination times out.",
    ),
) -> None:
    """Disarm a selected bridge session and terminate its owning Ghidra process."""
    from cerberus_re_skill.modules.bridge import close_bridge

    try:
        result = close_bridge(
            session,
            project,
            program,
            disarm_timeout_seconds=disarm_timeout,
            terminate_timeout_seconds=terminate_timeout,
            kill_after_timeout=kill_after_timeout,
        )
        _print_json(result)
        if not result.get("ok"):
            raise typer.Exit(code=1)
    except Exception as e:
        _die(str(e))


@bridge_app.command("build")
def bridge_build() -> None:
    """Build the bridge Ghidra extension."""
    from cerberus_re_skill.modules.bridge import build

    try:
        zip_path = build()
        console.print(f"Built bridge extension: {zip_path}")
    except Exception as e:
        _die(str(e))


@bridge_app.command("install")
def bridge_install() -> None:
    """Build and install the bridge extension into Ghidra settings."""
    from cerberus_re_skill.modules.bridge import install

    try:
        result = install()
        _print_json(result)
    except Exception as e:
        _die(str(e))


@bridge_app.command("call")
def bridge_call(
    endpoint: str = typer.Argument(..., help="API endpoint (e.g. /session or /symbols/get)."),
    body: str = typer.Argument("{}", help="JSON body string, @file, or '-' for stdin."),
) -> None:
    """Call a bridge endpoint and print the JSON response."""
    from cerberus_re_skill.modules.bridge import call_bridge

    # Handle @file and stdin
    if body.startswith("@"):
        body_file = Path(body[1:])
        if not body_file.exists():
            _die(f"JSON body file not found: {body_file}")
        body = body_file.read_text(encoding="utf-8")
    elif body == "-":
        body = sys.stdin.read()

    try:
        result = call_bridge(endpoint, body)
        _print_json(result)
    except Exception as e:
        _die(str(e))


@bridge_app.command("status")
def bridge_status_cmd(
    body: str = typer.Argument("{}", help="Optional JSON body with session/project/program selectors."),
) -> None:
    """Show bridge status."""
    from cerberus_re_skill.modules.bridge import bridge_status

    result = bridge_status(body)
    _print_json(result)
    if not result.get("ok"):
        raise typer.Exit(code=1)


@bridge_app.command("sessions")
def bridge_sessions() -> None:
    """List all active bridge sessions."""
    from cerberus_re_skill.modules.bridge import list_sessions

    sessions = list_sessions()
    _print_json(sessions)


@bridge_app.command("audit")
def bridge_audit() -> None:
    """Report raw bridge session files, stale state, and Ghidra JVMs."""
    from cerberus_re_skill.modules.bridge import audit_bridge_state

    result = audit_bridge_state()
    _print_json(result)
    if result.get("stale_session_files"):
        raise typer.Exit(code=1)


@bridge_app.command("health")
def bridge_health(
    session: str = typer.Option("", help="Session ID."),
    project: str = typer.Option("", help="Project name."),
    program: str = typer.Option("", help="Program name."),
) -> None:
    """Check bridge session health."""
    from cerberus_re_skill.modules.bridge import health_check

    result = health_check(session, project, program)
    _print_json(result)
    if not result.get("ok"):
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# validate subcommands
# ---------------------------------------------------------------------------


@validate_app.command("local")
def validate_local_cmd(
    headless_smoke: bool = typer.Option(False, "--headless-smoke", help="Run /usr/bin/true headless import/export/decompile smoke checks."),
    live_bridge_smoke: bool = typer.Option(False, "--live-bridge-smoke", help="Launch a small live bridge session and close it afterward."),
    lldb_smoke: bool = typer.Option(False, "--lldb-smoke", help="Compile the ObjC fixture and run LLDB symbol export smoke checks."),
    frida_smoke: bool = typer.Option(False, "--frida-smoke", help="Run Frida diagnostics and no-attach generated-script validation."),
    frida_target: Optional[str] = typer.Option(None, "--frida-target", help="Optional target binary for Frida diagnostics."),
    output_dir: Optional[str] = typer.Option(None, "--output-dir", "-o", help="Report directory; defaults under ~/ghidra-projects/logs/validation/."),
    timeout: float = typer.Option(180.0, "--timeout", help="Default per-step timeout in seconds."),
) -> None:
    """Run local validation and write JSON/Markdown evidence reports."""
    from cerberus_re_skill.modules.validation import validate_local

    try:
        result = validate_local(
            headless_smoke=headless_smoke,
            live_bridge_smoke=live_bridge_smoke,
            lldb_smoke=lldb_smoke,
            frida_smoke=frida_smoke,
            frida_target=frida_target,
            output_dir=output_dir,
            timeout_seconds=timeout,
        )
        summary = {
            "ok": result["ok"],
            "json_report": result["json_report"],
            "markdown_report": result["markdown_report"],
            "step_count": result["step_count"],
            "failed_step_count": result["failed_step_count"],
            "next_work_items": result["next_work_items"],
        }
        _print_json(summary)
        if not result.get("ok"):
            raise typer.Exit(code=1)
    except Exception as e:
        _die(str(e))


@validate_app.command("lldb-trace")
def validate_lldb_trace_cmd(
    project: str = typer.Argument(..., help="Ghidra project name."),
    program: str = typer.Argument(..., help="Program name within the project."),
    launch_cmd: str = typer.Option("", "--launch-cmd", help="Binary command to launch under LLDB."),
    attach_pid: str = typer.Option("", "--attach-pid", help="PID to attach to under LLDB."),
    attach_name: str = typer.Option("", "--attach-name", help="Process name to wait for and attach to."),
    symbols: Optional[list[str]] = typer.Option(
        None,
        "--symbols",
        help="Symbols/selectors to trace. Repeatable; comma-separated values are also accepted.",
    ),
    addresses: Optional[list[str]] = typer.Option(
        None,
        "--addresses",
        help="File addresses to trace. Repeatable; comma-separated values are also accepted.",
    ),
    binary: str = typer.Option("", "--binary", help="Optional binary path for LLDB static symbol export first."),
    function_inventory: Optional[str] = typer.Option(None, "--function-inventory", help="Path to function_inventory.json for enrichment (auto-derived if omitted)."),
    output_dir: Optional[str] = typer.Option(None, "--output-dir", "-o", help="Validation report directory."),
    timeout: float = typer.Option(30.0, "--timeout", help="Trace timeout in seconds."),
    max_hits: int = typer.Option(10, "--max-hits", help="Maximum breakpoint hits."),
    capture_objc_args: bool = typer.Option(False, "--capture-objc-args", help="Capture ObjC self/selector argument context."),
    objc_description_registers: str = typer.Option(
        "",
        "--objc-description-registers",
        help="Comma-separated known ObjC argument registers to describe, such as x2; invokes description in the target.",
    ),
    capture_backtrace: bool = typer.Option(False, "--capture-backtrace", help="Capture breakpoint backtraces."),
    include_decompile: bool = typer.Option(False, "--include-decompile", help="Attach cached decompile snippets while enriching hits."),
    decompile_timeout: int = typer.Option(60, "--decompile-timeout", help="Decompiler timeout in seconds."),
) -> None:
    """Validate LLDB runtime tracing and static enrichment in one report."""
    from cerberus_re_skill.modules.lldb_validation import validate_lldb_trace

    try:
        result = validate_lldb_trace(
            project=project,
            program=program,
            launch_cmd=launch_cmd,
            attach_pid=attach_pid,
            attach_name=attach_name,
            symbols=symbols,
            addresses=addresses,
            binary=binary,
            function_inventory=function_inventory,
            output_dir=output_dir,
            timeout=timeout,
            max_hits=max_hits,
            capture_objc_args=capture_objc_args,
            objc_description_registers=objc_description_registers,
            capture_backtrace=capture_backtrace,
            include_decompile=include_decompile,
            decompile_timeout=decompile_timeout,
        )
        _print_json(
            {
                "ok": result["ok"],
                "trace_status": result["trace_status"],
                "hit_count": result["hit_count"],
                "matched_function_count": result["matched_function_count"],
                "json_report": result["json_report"],
                "markdown_report": result["markdown_report"],
                "next_work_items": result["next_work_items"],
            }
        )
        if not result["ok"]:
            raise typer.Exit(code=1)
    except Exception as e:
        _die(str(e))


# ---------------------------------------------------------------------------
# polish subcommands
# ---------------------------------------------------------------------------


@polish_app.command("release")
def polish_release_cmd(
    mode: str = typer.Option("quick", "--mode", help="Polish mode: quick or release."),
    output_dir: Optional[str] = typer.Option(None, "--output-dir", "-o", help="Report directory; defaults under ~/ghidra-projects/logs/polish/."),
    live_bridge: bool = typer.Option(False, "--live-bridge", help="Include live bridge validation; off by default for CI-friendly runs."),
    strict_command_surface: bool = typer.Option(False, "--strict-command-surface", help="Fail when active docs reference missing scripts."),
) -> None:
    """Run release-polish checks and write JSON/Markdown evidence reports."""
    from cerberus_re_skill.modules.polish import polish_release

    try:
        result = polish_release(
            mode=mode,
            output_dir=output_dir,
            live_bridge=live_bridge,
            strict_command_surface=strict_command_surface,
        )
        summary = {
            "ok": result["ok"],
            "json_report": result["json_report"],
            "markdown_report": result["markdown_report"],
            "mode": result["mode"],
            "missing_cli_references": len(result["command_surface"]["missing_cli_references"]),
            "missing_script_references": len(result["command_surface"]["missing_script_references"]),
            "missing_required_files": len(result["package_surface"]["missing_required_files"]),
            "next_work_items": result["next_work_items"],
        }
        _print_json(summary)
        if not result.get("ok"):
            raise typer.Exit(code=1)
    except Exception as e:
        _die(str(e))


# ---------------------------------------------------------------------------
# frida subcommands
# ---------------------------------------------------------------------------


@frida_app.command("diagnose")
def frida_diagnose_cmd(
    target: Optional[str] = typer.Option(None, "--target", help="Optional binary to inspect for target-signing diagnostics."),
    output_dir: Optional[str] = typer.Option(None, "--output-dir", "-o", help="Report directory; defaults under ~/ghidra-projects/logs/frida/."),
) -> None:
    """Write a structured Frida diagnostic artifact."""
    from cerberus_re_skill.modules.frida_validation import write_frida_diagnostic_artifact

    result = write_frida_diagnostic_artifact(target=target, output_dir=output_dir)
    _print_json({
        "ok": result["ok"],
        "status": result["status"],
        "json_report": result["json_report"],
        "markdown_report": result["markdown_report"],
        "runtime_attach_blocked": result["runtime_attach_blocked"],
    })


@frida_app.command("validate-scripts")
def frida_validate_scripts_cmd(
    output_dir: Optional[str] = typer.Option(None, "--output-dir", "-o", help="Report directory; defaults under ~/ghidra-projects/logs/frida/."),
    symbol: str = typer.Option("-[CodexProbe greet:]", "--symbol", help="ObjC method symbol for generated trace JS."),
    class_name: str = typer.Option("CodexProbe", "--class-name", help="ObjC class name for generated heap JS."),
) -> None:
    """Generate Frida scripts and syntax-check them without runtime attach."""
    from cerberus_re_skill.modules.frida_validation import validate_no_attach_scripts

    result = validate_no_attach_scripts(output_dir=output_dir, symbol=symbol, class_name=class_name)
    _print_json({
        "ok": result["ok"],
        "json_report": result["json_report"],
        "markdown_report": result["markdown_report"],
        "checks": result["checks"],
    })
    if not result.get("ok"):
        raise typer.Exit(code=1)


@frida_app.command("recheck-attach")
def frida_recheck_attach_cmd(
    target: Optional[str] = typer.Option(None, "--target", help="Binary to spawn under Frida for the guarded runtime recheck."),
    attach_pid: Optional[int] = typer.Option(None, "--attach-pid", help="Existing process PID to attach to instead of spawning --target."),
    attach_name: str = typer.Option("", "--attach-name", help="Process-name/command regex to poll and attach by PID; avoids Frida spawn-gating privileges."),
    await_regex: str = typer.Option("", "--await-regex", help="Regex for Frida spawn-gating wait mode (-W); useful for short-lived XPC helpers."),
    output_dir: Optional[str] = typer.Option(None, "--output-dir", "-o", help="Report directory; defaults under ~/ghidra-projects/logs/frida/."),
    allow_runtime: bool = typer.Option(False, "--allow-runtime", help="Actually spawn or attach under Frida; omitted means artifact-only skip."),
    symbol: list[str] = typer.Option([], "--symbol", help="ObjC method symbol for generated runtime trace JS; repeatable."),
    selector: list[str] = typer.Option([], "--selector", help="ObjC selector to hook across runtime classes; repeatable."),
    class_filter: list[str] = typer.Option([], "--class-filter", help="Substring filter for selector-wide ObjC class names; repeatable."),
    exact_class: list[str] = typer.Option([], "--exact-class", help="Exact ObjC class name to hook; without --class-filter skips global class enumeration; repeatable."),
    max_selector_hooks: int = typer.Option(128, "--max-selector-hooks", help="Maximum selector-wide ObjC implementations to hook."),
    native_symbol: list[str] = typer.Option([], "--native-symbol", help="Native export to hook; repeatable. Use Module!symbol or symbol."),
    address: list[str] = typer.Option([], "--address", help="Absolute runtime address to hook; repeatable."),
    capture_returns: bool = typer.Option(False, "--capture-returns", help="Capture GHIDRA_FRIDA_RETURN events in addition to call hits."),
    native_wait_seconds: float = typer.Option(
        0.0,
        "--native-wait-seconds",
        help="Seconds to poll for native exports that appear after dlopen before marking them missing.",
    ),
    native_arg_preview: bool = typer.Option(
        False,
        "--native-arg-preview",
        help="Add best-effort bounded previews for native register arguments to call hits.",
    ),
    target_arg: list[str] = typer.Option([], "--target-arg", help="Argument passed to the spawned target; repeat for multiple argv entries."),
    pre_run_delay: float = typer.Option(0.0, "--pre-run-delay", help="Seconds to wait before launching the guarded Frida recheck."),
    readiness_marker: str = typer.Option("", "--readiness-marker", help="Target stdout/stderr marker to record as readiness evidence."),
    require_readiness_marker: bool = typer.Option(False, "--require-readiness-marker", help="Treat the recheck as blocked if --readiness-marker is not observed."),
    require_runtime_hit: bool = typer.Option(False, "--require-runtime-hit", help="Treat the recheck as blocked if hooks install but no runtime hit is observed."),
    timeout: float = typer.Option(10.0, "--timeout", help="Runtime recheck timeout in seconds."),
) -> None:
    """Guarded runtime attach recheck; skipped unless --allow-runtime is passed."""
    from cerberus_re_skill.modules.frida_validation import recheck_runtime_attach

    try:
        result = recheck_runtime_attach(
            target=target,
            attach_pid=attach_pid,
            attach_name=attach_name,
            await_regex=await_regex,
            output_dir=output_dir,
            allow_runtime=allow_runtime,
            symbol=symbol or ["-[NSObject description]"],
            selectors=selector,
            class_filters=class_filter,
            exact_classes=exact_class,
            max_selector_hooks=max_selector_hooks,
            native_symbols=native_symbol,
            addresses=address,
            capture_returns=capture_returns,
            native_wait_seconds=native_wait_seconds,
            native_arg_preview=native_arg_preview,
            target_args=target_arg,
            pre_run_delay_seconds=pre_run_delay,
            readiness_marker=readiness_marker,
            require_readiness_marker=require_readiness_marker,
            require_runtime_hit=require_runtime_hit,
            timeout_seconds=timeout,
        )
    except Exception as e:
        _die(str(e))
    _print_json({
        "ok": result["ok"],
        "status": result["status"],
        "hook_mode": result.get("hook_mode", ""),
        "attach_pid": result.get("attach_pid"),
        "attach_name": result.get("attach_name", ""),
        "resolved_attach_pid": result.get("resolved_attach_pid"),
        "await_regex": result.get("await_regex", ""),
        "json_report": result["json_report"],
        "markdown_report": result["markdown_report"],
        "selectors": result.get("selectors", []),
        "class_filters": result.get("class_filters", []),
        "exact_classes": result.get("exact_classes", []),
        "native_wait_seconds": result.get("native_wait_seconds", 0.0),
        "native_arg_preview": result.get("native_arg_preview", False),
        "frida_helper_crashed": result.get("frida_helper_crashed", False),
        "readiness_observed": result.get("readiness_observed", False),
        "frida_event_summary": result.get("frida_event_summary", {}),
        "runtime_guidance": result.get("runtime_guidance", []),
        "runtime_hits_json": result.get("runtime_hits_json", ""),
        "runtime_hit_count": result.get("runtime_hit_count", 0),
    })
    if allow_runtime and not result.get("ok"):
        raise typer.Exit(code=1)


@frida_app.command("objc-probe")
def frida_objc_probe_cmd(
    target: Optional[str] = typer.Option(None, "--target", help="Binary to spawn under Frida for the ObjC probe."),
    attach_pid: Optional[int] = typer.Option(None, "--attach-pid", help="Existing process PID to attach to instead of spawning --target."),
    attach_name: str = typer.Option("", "--attach-name", help="Process-name/command regex to poll and attach by PID."),
    class_name: list[str] = typer.Option([], "--class", "--class-name", help="ObjC class to inventory; repeatable."),
    call: list[str] = typer.Option([], "--call", help="No-argument method chain such as Class.shared.isEnabled; repeatable."),
    call_string: list[str] = typer.Option(
        [],
        "--call-string",
        help="Chain ending in one NSString selector, such as Class.shared.valueForType:=Name; repeatable.",
    ),
    output_dir: Optional[str] = typer.Option(None, "--output-dir", "-o", help="Report directory; defaults under ~/ghidra-projects/logs/frida/."),
    allow_runtime: bool = typer.Option(False, "--allow-runtime", help="Actually spawn or attach under Frida; omitted means artifact-only skip."),
    target_arg: list[str] = typer.Option([], "--target-arg", help="Argument passed to the spawned target; repeat for multiple argv entries."),
    require_successful_call: bool = typer.Option(False, "--require-successful-call", help="Treat the probe as blocked unless at least one requested call succeeds."),
    allow_attached_call: bool = typer.Option(
        False,
        "--allow-attached-call",
        help="Allow --call-string against --attach-pid/--attach-name after disposable-target validation.",
    ),
    timeout: float = typer.Option(10.0, "--timeout", help="Runtime probe timeout in seconds."),
) -> None:
    """Inventory ObjC classes and run explicit zero- or one-string-argument probes."""
    from cerberus_re_skill.modules.frida_objc_probe import write_objc_probe_artifact

    result = write_objc_probe_artifact(
        target=target,
        attach_pid=attach_pid,
        attach_name=attach_name,
        classes=class_name,
        calls=call,
        string_calls=call_string,
        output_dir=output_dir,
        allow_runtime=allow_runtime,
        target_args=target_arg,
        require_successful_call=require_successful_call,
        allow_attached_call=allow_attached_call,
        timeout_seconds=timeout,
    )
    _print_json({
        "ok": result["ok"],
        "status": result["status"],
        "json_report": result["json_report"],
        "markdown_report": result["markdown_report"],
        "attach_pid": result.get("attach_pid"),
        "attach_name": result.get("attach_name", ""),
        "resolved_attach_pid": result.get("resolved_attach_pid"),
        "classes": result.get("classes", []),
        "calls": result.get("calls", []),
        "string_calls": result.get("string_calls", []),
        "event_count": result.get("event_count", len(result.get("events", []))),
        "successful_call_count": result.get("successful_call_count", 0),
        "successful_string_call_count": result.get("successful_string_call_count", 0),
        "allow_attached_call": result.get("allow_attached_call", False),
    })
    if allow_runtime and not result.get("ok"):
        raise typer.Exit(code=1)


@frida_app.command("objc-heap")
def frida_objc_heap_cmd(
    target: Optional[str] = typer.Option(None, "--target", help="Binary to spawn under Frida for the ObjC heap inspection."),
    attach_pid: Optional[int] = typer.Option(None, "--attach-pid", help="Existing process PID to attach to instead of spawning --target."),
    attach_name: str = typer.Option("", "--attach-name", help="Process-name/command regex to poll and attach by PID."),
    class_name: list[str] = typer.Option([], "--class", "--class-name", help="ObjC class to enumerate in the live heap; repeatable."),
    getter: list[str] = typer.Option([], "--getter", help="No-argument getter to call on each observed instance; repeatable."),
    output_dir: Optional[str] = typer.Option(None, "--output-dir", "-o", help="Report directory; defaults under ~/ghidra-projects/logs/frida/."),
    allow_runtime: bool = typer.Option(False, "--allow-runtime", help="Actually spawn or attach under Frida; omitted means artifact-only skip."),
    target_arg: list[str] = typer.Option([], "--target-arg", help="Argument passed to the spawned target; repeat for multiple argv entries."),
    max_instances: int = typer.Option(8, "--max-instances", help="Maximum instances emitted per class."),
    include_ivars: bool = typer.Option(False, "--include-ivars", help="Include Frida ObjC ivar snapshots for each emitted instance."),
    require_instance: bool = typer.Option(False, "--require-instance", help="Treat the probe as blocked unless at least one instance is observed."),
    timeout: float = typer.Option(10.0, "--timeout", help="Runtime heap-inspection timeout in seconds."),
) -> None:
    """Inspect live ObjC heap instances and safe no-argument getters."""
    from cerberus_re_skill.modules.frida_objc_heap import write_objc_heap_artifact

    result = write_objc_heap_artifact(
        target=target,
        attach_pid=attach_pid,
        attach_name=attach_name,
        classes=class_name,
        getters=getter,
        output_dir=output_dir,
        allow_runtime=allow_runtime,
        target_args=target_arg,
        max_instances=max_instances,
        include_ivars=include_ivars,
        require_instance=require_instance,
        timeout_seconds=timeout,
    )
    _print_json({
        "ok": result["ok"],
        "status": result["status"],
        "json_report": result["json_report"],
        "markdown_report": result["markdown_report"],
        "attach_pid": result.get("attach_pid"),
        "attach_name": result.get("attach_name", ""),
        "resolved_attach_pid": result.get("resolved_attach_pid"),
        "classes": result.get("classes", []),
        "getters": result.get("getters", []),
        "include_ivars": result.get("include_ivars", False),
        "max_instances": result.get("max_instances"),
        "event_count": result.get("event_count", len(result.get("events", []))),
        "instance_count": result.get("instance_count", 0),
    })
    if allow_runtime and not result.get("ok"):
        raise typer.Exit(code=1)


@frida_app.command("objc-plan")
def frida_objc_plan_cmd(
    plan: str = typer.Option(..., "--plan", help="JSON plan containing bounded ObjC construction/readback steps."),
    target: Optional[str] = typer.Option(None, "--target", help="Binary to spawn under Frida for the ObjC plan."),
    attach_pid: Optional[int] = typer.Option(None, "--attach-pid", help="Existing process PID to attach to instead of spawning --target."),
    attach_name: str = typer.Option("", "--attach-name", help="Process-name/command regex to poll and attach by PID."),
    output_dir: Optional[str] = typer.Option(None, "--output-dir", "-o", help="Report directory; defaults under ~/ghidra-projects/logs/frida/."),
    allow_runtime: bool = typer.Option(False, "--allow-runtime", help="Actually spawn or attach under Frida; omitted means artifact-only skip."),
    allow_attached_plan: bool = typer.Option(
        False,
        "--allow-attached-plan",
        help="Allow constructor plans against --attach-pid/--attach-name after disposable-target validation.",
    ),
    extract_base64_step: list[str] = typer.Option([], "--extract-base64-step", help="Plan step containing base64 text to decode into a report artifact; repeatable."),
    target_arg: list[str] = typer.Option([], "--target-arg", help="Argument passed to the spawned target; repeat for multiple argv entries."),
    timeout: float = typer.Option(10.0, "--timeout", help="Runtime plan timeout in seconds."),
) -> None:
    """Run a validated bounded Objective-C construction/readback plan."""
    from cerberus_re_skill.modules.frida_objc_plan import write_objc_plan_artifact

    result = write_objc_plan_artifact(
        plan_path=plan,
        target=target,
        attach_pid=attach_pid,
        attach_name=attach_name,
        output_dir=output_dir,
        allow_runtime=allow_runtime,
        allow_attached_plan=allow_attached_plan,
        extract_base64_steps=extract_base64_step,
        target_args=target_arg,
        timeout_seconds=timeout,
    )
    _print_json({
        "ok": result["ok"],
        "status": result["status"],
        "json_report": result["json_report"],
        "markdown_report": result["markdown_report"],
        "attach_pid": result.get("attach_pid"),
        "attach_name": result.get("attach_name", ""),
        "resolved_attach_pid": result.get("resolved_attach_pid"),
        "plan_path": result.get("plan_path", ""),
        "plan_sha256": result.get("plan_sha256", ""),
        "event_count": result.get("event_count", len(result.get("events", []))),
        "completed_step_count": result.get("completed_step_count", 0),
        "failed_step_count": result.get("failed_step_count", 0),
        "allow_attached_plan": result.get("allow_attached_plan", False),
        "extracted_outputs": result.get("extracted_outputs", []),
    })
    if allow_runtime and not result.get("ok"):
        raise typer.Exit(code=1)


@frida_app.command("objc-archive")
def frida_objc_archive_cmd(
    archive: str = typer.Option(..., "--archive", help="Host secure-archive file to embed and read back in the target."),
    class_name: str = typer.Option(..., "--class", "--class-name", help="Expected ObjC secure-coding root class."),
    target: Optional[str] = typer.Option(None, "--target", help="Binary to spawn under Frida for archive readback."),
    attach_pid: Optional[int] = typer.Option(None, "--attach-pid", help="Existing process PID to attach to instead of spawning --target."),
    attach_name: str = typer.Option("", "--attach-name", help="Process-name/command regex to poll and attach by PID."),
    getter: list[str] = typer.Option([], "--getter", help="No-argument getter to call on the decoded root object; repeatable."),
    output_dir: Optional[str] = typer.Option(None, "--output-dir", "-o", help="Report directory; defaults under ~/ghidra-projects/logs/frida/."),
    allow_runtime: bool = typer.Option(False, "--allow-runtime", help="Actually spawn or attach under Frida; omitted means artifact-only skip."),
    target_arg: list[str] = typer.Option([], "--target-arg", help="Argument passed to the spawned target; repeat for multiple argv entries."),
    timeout: float = typer.Option(10.0, "--timeout", help="Runtime archive-readback timeout in seconds."),
) -> None:
    """Secure-unarchive host bytes in an ObjC target and inspect no-argument getters."""
    from cerberus_re_skill.modules.frida_objc_archive import write_objc_archive_artifact

    result = write_objc_archive_artifact(
        archive_path=archive,
        class_name=class_name,
        target=target,
        attach_pid=attach_pid,
        attach_name=attach_name,
        getters=getter,
        output_dir=output_dir,
        allow_runtime=allow_runtime,
        target_args=target_arg,
        timeout_seconds=timeout,
    )
    _print_json({
        "ok": result["ok"],
        "status": result["status"],
        "json_report": result["json_report"],
        "markdown_report": result["markdown_report"],
        "attach_pid": result.get("attach_pid"),
        "attach_name": result.get("attach_name", ""),
        "resolved_attach_pid": result.get("resolved_attach_pid"),
        "archive_path": result.get("archive_path", ""),
        "archive_sha256": result.get("archive_sha256", ""),
        "class_name": result.get("class_name", ""),
        "getters": result.get("getters", []),
        "event_count": result.get("event_count", len(result.get("events", []))),
        "decoded_object_count": result.get("decoded_object_count", 0),
    })
    if allow_runtime and not result.get("ok"):
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# source subcommands
# ---------------------------------------------------------------------------
