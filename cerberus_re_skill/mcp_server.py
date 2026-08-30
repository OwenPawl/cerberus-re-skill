"""Local-stdio MCP server for Cerberus RE, optionally composed with mission tools."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import Context, FastMCP
from pydantic import BaseModel

from .mcp_jobs import JobStore
from .mcp_runtime import (
    BLOCKED,
    FAILED,
    SUCCESS,
    UNVERIFIED,
    CommandRunner,
    MCPSettings,
    append_audit,
    bridge_tier,
    envelope,
    passthrough_policy,
)


class Approval(BaseModel):
    approve: bool
    note: str = ""


class DestructiveApproval(BaseModel):
    approve: bool
    confirm_target: str
    note: str = ""


def _caller(context: Context | None) -> str:
    if context is None:
        return "unknown"
    for attribute in ("client_id", "session_id"):
        value = getattr(context, attribute, None)
        if value:
            return str(value)
    return "local-stdio"


def _csv_env(name: str) -> set[str]:
    return {item.strip() for item in os.environ.get(name, "").split(",") if item.strip()}


def _runtime_preapproved(
    pid: int | None,
    name: str,
    target: str,
) -> bool:
    if pid is not None and str(pid) in _csv_env("CERBERUS_MCP_RUNTIME_PIDS"):
        return True
    haystack = f"{name} {target}".lower()
    return any(
        approved.lower() in haystack
        for approved in _csv_env("CERBERUS_MCP_RUNTIME_NAMES")
    )


async def _gate_runtime(
    settings: MCPSettings,
    context: Context,
    *,
    action: str,
    target: str,
    pid: int | None = None,
    name: str = "",
) -> str | None:
    audit_base = {
        "tier": "runtime",
        "action": action,
        "target": target,
        "pid": pid,
        "name": name,
        "caller": _caller(context),
    }
    if _runtime_preapproved(pid, name, target):
        append_audit(settings, {**audit_base, "outcome": "allowed_allowlist"})
        return None
    message = f"Approve live runtime operation {action!r} on {target!r}?"
    try:
        response = await asyncio.wait_for(
            context.elicit(message=message, schema=Approval),
            timeout=settings.elicit_timeout,
        )
    except Exception as exc:  # noqa: BLE001 - unsupported elicitation must fail closed.
        append_audit(
            settings,
            {**audit_base, "outcome": "denied_no_channel", "detail": str(exc)},
        )
        return f"runtime operation denied: no working approval channel ({exc})"
    approved = (
        getattr(response, "action", None) == "accept"
        and bool(getattr(getattr(response, "data", None), "approve", False))
    )
    append_audit(
        settings,
        {
            **audit_base,
            "outcome": "allowed_elicitation" if approved else "denied_elicitation",
        },
    )
    return None if approved else "runtime operation denied by operator"


def _bridge_flags_valid(tier: str, body: dict[str, Any]) -> str | None:
    if tier in {"write", "destructive"} and body.get("write") is not True:
        return "mutating bridge calls require body.write=true"
    if tier == "destructive" and body.get("destructive") is not True:
        return "destructive bridge calls require body.destructive=true"
    return None


async def _gate_bridge(
    settings: MCPSettings,
    context: Context,
    endpoint: str,
    tier: str,
) -> str | None:
    audit_base = {
        "tier": f"bridge_{tier}",
        "action": "bridge_call",
        "target": endpoint,
        "caller": _caller(context),
    }
    if tier == "read":
        return None
    if tier == "write" and os.environ.get("CERBERUS_MCP_BRIDGE_WRITE_OK") == "1":
        append_audit(settings, {**audit_base, "outcome": "allowed_environment"})
        return None
    schema: type[BaseModel] = Approval if tier == "write" else DestructiveApproval
    if tier == "write":
        message = f"Approve a Ghidra database mutation through {endpoint!r}?"
    else:
        message = (
            f"Approve destructive Ghidra mutation {endpoint!r}? Set approve=true "
            "and echo the endpoint exactly in confirm_target."
        )
    try:
        response = await asyncio.wait_for(
            context.elicit(message=message, schema=schema),
            timeout=settings.elicit_timeout,
        )
    except Exception as exc:  # noqa: BLE001 - unsupported elicitation must fail closed.
        append_audit(
            settings,
            {**audit_base, "outcome": "denied_no_channel", "detail": str(exc)},
        )
        return f"bridge {tier} denied: no working approval channel ({exc})"
    data = getattr(response, "data", None)
    approved = (
        getattr(response, "action", None) == "accept"
        and bool(getattr(data, "approve", False))
    )
    if tier == "destructive":
        approved = approved and getattr(data, "confirm_target", "").strip() == endpoint.strip()
    append_audit(
        settings,
        {
            **audit_base,
            "outcome": "allowed_elicitation" if approved else "denied_elicitation",
        },
    )
    return None if approved else f"bridge {tier} denied by operator or confirmation mismatch"


def _register_mission_companion(server: FastMCP) -> dict[str, Any]:
    """Load mission tools from an installed package or common local skill root."""
    candidates = []
    explicit = os.environ.get("CERBERUS_MCP_LONG_RUN_AGENT_ROOT")
    if explicit:
        candidates.append(Path(explicit).expanduser())
    candidates.extend(
        [
            Path.home() / ".codex" / "skills" / "long-run-agent",
            Path.home() / ".claude" / "skills" / "long-run-agent",
        ]
    )
    try:
        from long_run_agent_skill.mcp_tools import register_mission_tools
    except ModuleNotFoundError as exc:
        if exc.name not in {"long_run_agent_skill", "long_run_agent_skill.mcp_tools"}:
            return {
                "available": False,
                "registered_tools": [],
                "reason": f"long-run-agent import failed: {exc}",
            }
        for candidate in candidates:
            if not (candidate / "long_run_agent_skill" / "mcp_tools.py").is_file():
                continue
            sys.path.insert(0, str(candidate))
            try:
                from long_run_agent_skill.mcp_tools import register_mission_tools
            except ModuleNotFoundError:
                continue
            break
        else:
            return {
                "available": False,
                "registered_tools": [],
                "reason": "long-run-agent package or local skill was not found",
            }
    try:
        names = register_mission_tools(server)
    except Exception as exc:  # noqa: BLE001 - optional companion failures are reported as state.
        return {
            "available": False,
            "registered_tools": [],
            "reason": str(exc),
        }
    return {
        "available": True,
        "registered_tools": names,
        "reason": "mission tools composed from long-run-agent",
    }


def create_server(settings: MCPSettings | None = None) -> FastMCP:
    settings = settings or MCPSettings.from_env()
    settings.ensure_state()
    runner = CommandRunner(settings)
    jobs = JobStore(settings)
    server = FastMCP(
        "cerberus-re",
        log_level="WARNING",
        instructions=(
            "Use the static/dynamic/instrumentation evidence loop. Runtime operations "
            "and bridge mutations are gated and audited. Read envelope status instead "
            "of inferring success from prose. When mission_* tools are available, use "
            "them for durable state, claims, friction, artifacts, and closeout."
        ),
    )
    companion = _register_mission_companion(server)

    @server.tool()
    def mission_companion_status() -> dict[str, Any]:
        """Report whether long-run-agent mission tools are composed into this server."""
        status = SUCCESS if companion["available"] else UNVERIFIED
        return envelope(status, data=companion, note=companion["reason"])

    @server.tool()
    def env_doctor(frida_target: str = "") -> dict[str, Any]:
        """Check Ghidra, JDK, LLDB, and Frida without attaching to a process."""
        args = ["doctor"]
        if frida_target:
            args.extend(["--frida-target", frida_target])
        return runner.wrap(runner.run(args, timeout=180))

    @server.tool()
    def surface_check(strict: bool = False) -> dict[str, Any]:
        """Run Cerberus's release and public command-surface checks."""
        args = ["polish", "release", "--mode", "quick"]
        if strict:
            args.append("--strict-command-surface")
        return runner.wrap(runner.run(args, timeout=600))

    @server.tool()
    def import_analyze(
        binary: str,
        project: str = "",
        skip_macho_reexports: bool = False,
        macho_arch: str = "",
        disable_analysis_option: list[str] | None = None,
    ) -> dict[str, Any]:
        """Start a durable background Ghidra import and analysis job."""
        args = ["import", "analyze", binary]
        if project:
            args.append(project)
        if skip_macho_reexports:
            args.append("--skip-macho-reexports")
        if macho_arch:
            args.extend(["--macho-arch", macho_arch])
        for option in disable_analysis_option or []:
            args.extend(["--disable-analysis-option", option])
        job_id = jobs.start(args, kind="generic", label="import_analyze")
        return envelope(
            SUCCESS,
            command=[*settings.cli_command, *args],
            data={"job_id": job_id},
            note="import started; poll job_status",
        )

    @server.tool()
    def export_apple_bundle(
        project: str,
        program: str,
        output_dir: str = "",
    ) -> dict[str, Any]:
        """Export functions, strings, symbols, ObjC/Swift, and Mach-O evidence."""
        args = ["export", "apple-bundle", project, program]
        if output_dir:
            args.extend(["--output-dir", output_dir])
        return runner.wrap(
            runner.run(args, timeout=900),
            artifacts=runner.artifacts_for(project, program),
        )

    @server.tool()
    def export_xpc_surface(
        project: str,
        program: str,
        bundle_dir: str = "",
    ) -> dict[str, Any]:
        """Recover XPC surface evidence; warnings make zero counts unverified."""
        args = ["export", "xpc-surface", project, program]
        if bundle_dir:
            args.extend(["--bundle-dir", bundle_dir])
        return runner.wrap(
            runner.run(args, timeout=300),
            artifacts=runner.artifacts_for(project, program),
        )

    @server.tool()
    def export_triage_bundle(
        project: str,
        program: str,
        top_candidates: int = 50,
        max_depth: int = 4,
        background: bool = False,
    ) -> dict[str, Any]:
        """Export ranked entrypoint-to-sink evidence, optionally in the background."""
        args = [
            "export",
            "triage-bundle",
            project,
            program,
            "--top-candidates",
            str(top_candidates),
            "--max-depth",
            str(max_depth),
        ]
        if background:
            job_id = jobs.start(
                args,
                kind="generic",
                label="export_triage_bundle",
                artifact_hint=(project, program),
            )
            return envelope(
                SUCCESS,
                command=[*settings.cli_command, *args],
                data={"job_id": job_id},
                note="triage started; poll job_status",
            )
        return runner.wrap(
            runner.run(args, timeout=1200),
            artifacts=runner.artifacts_for(project, program),
        )

    @server.tool()
    def runtime_enrich(
        project: str,
        program: str,
        runtime_hits_json: str,
        include_decompile: bool = False,
    ) -> dict[str, Any]:
        """Correlate LLDB or Frida runtime hits back to static function context."""
        args = ["export", "runtime-enrich", project, program, runtime_hits_json]
        if include_decompile:
            args.append("--include-decompile")
        return runner.wrap(
            runner.run(args, timeout=600),
            kind="runtime",
            artifacts=runner.artifacts_for(project, program),
        )

    @server.tool(name="diff_programs")
    def diff_programs(
        project_a: str,
        program_a: str,
        project_b: str,
        program_b: str,
        output: str = "",
    ) -> dict[str, Any]:
        """Diff added, removed, and changed functions between analyzed programs."""
        args = ["diff", project_a, program_a, project_b, program_b]
        if output:
            args.extend(["--output", output])
        return runner.wrap(runner.run(args, timeout=600))

    @server.tool()
    async def lldb_trace(
        project: str,
        program: str,
        ctx: Context,
        launch_cmd: str = "",
        attach_pid: int | None = None,
        attach_name: str = "",
        symbols: list[str] | None = None,
        addresses: list[str] | None = None,
        binary: str = "",
        function_inventory: str = "",
        output_dir: str = "",
        timeout: float = 30.0,
        max_hits: int = 10,
        capture_objc_args: bool = False,
        objc_description_registers: str = "",
        capture_backtrace: bool = False,
        include_decompile: bool = False,
        decompile_timeout: int = 60,
    ) -> dict[str, Any]:
        """Run a per-call-approved LLDB launch or attach trace."""
        choices = bool(launch_cmd) + (attach_pid is not None) + bool(attach_name)
        if choices != 1:
            return envelope(BLOCKED, note="provide exactly one launch_cmd, attach_pid, or attach_name")
        target = launch_cmd or attach_name or f"pid:{attach_pid}"
        denied = await _gate_runtime(
            settings,
            ctx,
            action="lldb_trace",
            target=target,
            pid=attach_pid,
            name=attach_name or launch_cmd,
        )
        if denied:
            return envelope(BLOCKED, note=denied)
        args = [
            "validate",
            "lldb-trace",
            project,
            program,
            "--timeout",
            str(timeout),
            "--max-hits",
            str(max_hits),
        ]
        for flag, value in (
            ("--launch-cmd", launch_cmd),
            ("--attach-pid", attach_pid),
            ("--attach-name", attach_name),
            ("--binary", binary),
            ("--function-inventory", function_inventory),
            ("--output-dir", output_dir),
            ("--objc-description-registers", objc_description_registers),
        ):
            if value not in (None, ""):
                args.extend([flag, str(value)])
        for symbol in symbols or []:
            args.extend(["--symbols", symbol])
        for address in addresses or []:
            args.extend(["--addresses", address])
        if capture_objc_args:
            args.append("--capture-objc-args")
        if capture_backtrace:
            args.append("--capture-backtrace")
        if include_decompile:
            args.append("--include-decompile")
        args.extend(["--decompile-timeout", str(decompile_timeout)])
        result = await asyncio.to_thread(runner.run, args, int(timeout) + 180)
        wrapped = runner.wrap(
            result,
            kind="lldb",
            artifacts=runner.artifacts_for(project, program),
        )
        append_audit(
            settings,
            {
                "tier": "runtime",
                "action": "lldb_trace",
                "target": target,
                "outcome": "executed",
                "status": wrapped["status"],
            },
        )
        return wrapped

    @server.tool()
    def frida_diagnose(target: str = "") -> dict[str, Any]:
        """Run no-attach Frida environment and signing diagnostics."""
        args = ["frida", "diagnose"]
        if target:
            args.extend(["--target", target])
        return runner.wrap(runner.run(args, timeout=180), kind="frida")

    @server.tool()
    def frida_validate_scripts(symbol: str = "", class_name: str = "") -> dict[str, Any]:
        """Statically validate generated Frida JavaScript without attaching."""
        args = ["frida", "validate-scripts"]
        if symbol:
            args.extend(["--symbol", symbol])
        if class_name:
            args.extend(["--class-name", class_name])
        return runner.wrap(runner.run(args, timeout=180), kind="frida")

    @server.tool()
    async def frida_recheck_attach(
        ctx: Context,
        target: str = "",
        attach_pid: int | None = None,
        attach_name: str = "",
        await_regex: str = "",
        output_dir: str = "",
        allow_runtime: bool = False,
        symbols: list[str] | None = None,
        selectors: list[str] | None = None,
        class_filters: list[str] | None = None,
        exact_classes: list[str] | None = None,
        native_symbols: list[str] | None = None,
        addresses: list[str] | None = None,
        max_selector_hooks: int = 128,
        capture_returns: bool = False,
        native_wait_seconds: float = 0.0,
        native_arg_preview: bool = False,
        target_args: list[str] | None = None,
        pre_run_delay: float = 0.0,
        readiness_marker: str = "",
        require_readiness_marker: bool = False,
        require_runtime_hit: bool = False,
        timeout: float = 10.0,
    ) -> dict[str, Any]:
        """Run artifact-only validation or a per-call-approved live Frida recheck."""
        args = ["frida", "recheck-attach", "--timeout", str(timeout)]
        for flag, value in (
            ("--target", target),
            ("--attach-pid", attach_pid),
            ("--attach-name", attach_name),
            ("--await-regex", await_regex),
            ("--output-dir", output_dir),
        ):
            if value not in (None, ""):
                args.extend([flag, str(value)])
        for flag, values in (
            ("--symbol", symbols),
            ("--selector", selectors),
            ("--class-filter", class_filters),
            ("--exact-class", exact_classes),
            ("--native-symbol", native_symbols),
            ("--address", addresses),
        ):
            for value in values or []:
                args.extend([flag, value])
        if capture_returns:
            args.append("--capture-returns")
        args.extend(["--max-selector-hooks", str(max_selector_hooks)])
        args.extend(["--native-wait-seconds", str(native_wait_seconds)])
        if native_arg_preview:
            args.append("--native-arg-preview")
        for target_arg in target_args or []:
            args.extend(["--target-arg", target_arg])
        args.extend(["--pre-run-delay", str(pre_run_delay)])
        if readiness_marker:
            args.extend(["--readiness-marker", readiness_marker])
        if require_readiness_marker:
            args.append("--require-readiness-marker")
        if require_runtime_hit:
            args.append("--require-runtime-hit")
        if not allow_runtime:
            return runner.wrap(runner.run(args, int(timeout) + 90), kind="frida")
        choices = bool(target) + (attach_pid is not None) + bool(attach_name) + bool(await_regex)
        if choices != 1:
            return envelope(
                BLOCKED,
                note="provide exactly one target, attach_pid, attach_name, or await_regex for live Frida",
            )
        target_name = target or attach_name or await_regex or f"pid:{attach_pid}"
        denied = await _gate_runtime(
            settings,
            ctx,
            action="frida_recheck_attach",
            target=target_name,
            pid=attach_pid,
            name=attach_name or target or await_regex,
        )
        if denied:
            return envelope(BLOCKED, note=denied)
        args.append("--allow-runtime")
        result = await asyncio.to_thread(runner.run, args, int(timeout) + 180)
        wrapped = runner.wrap(result, kind="frida")
        append_audit(
            settings,
            {
                "tier": "runtime",
                "action": "frida_recheck_attach",
                "target": target_name,
                "outcome": "executed",
                "status": wrapped["status"],
            },
        )
        return wrapped

    @server.tool()
    def bridge_arm(project: str, program: str = "") -> dict[str, Any]:
        """Arm a local Ghidra bridge session."""
        args = ["bridge", "arm", project] + ([program] if program else [])
        append_audit(settings, {"tier": "bridge_lifecycle", "action": "arm", "target": project})
        return runner.wrap(runner.run(args, timeout=300))

    @server.tool()
    def bridge_disarm(session: str = "", project: str = "", program: str = "") -> dict[str, Any]:
        """Disarm a bridge session without terminating the owning Ghidra process."""
        args = ["bridge", "disarm"]
        for flag, value in (("--session", session), ("--project", project), ("--program", program)):
            if value:
                args.extend([flag, value])
        return runner.wrap(runner.run(args, timeout=120))

    @server.tool()
    def bridge_sessions() -> dict[str, Any]:
        """List active Ghidra bridge sessions."""
        return runner.wrap(runner.run(["bridge", "sessions"], timeout=60))

    @server.tool()
    def bridge_inventory() -> dict[str, Any]:
        """List Ghidra applications, tools, and open programs with stable handles."""
        return runner.wrap(runner.run(["bridge", "inventory"], timeout=60))

    @server.tool()
    def bridge_open_program(
        project: str,
        program: str,
        tool_id: str,
        application_id: str = "",
    ) -> dict[str, Any]:
        """Open a program in one explicit live Ghidra tool without selecting it."""
        args = ["bridge", "open", project, program, "--tool-id", tool_id]
        if application_id:
            args.extend(["--application-id", application_id])
        return runner.wrap(runner.run(args, timeout=90))

    @server.tool()
    def bridge_status(body: dict[str, Any] | None = None) -> dict[str, Any]:
        """Read bridge status for an optional session/project/program selector."""
        payload = json.dumps(body or {}, separators=(",", ":"))
        return runner.wrap(runner.run(["bridge", "status", payload], timeout=60))

    @server.tool()
    def bridge_audit() -> dict[str, Any]:
        """Report stale session state and stray Ghidra bridge processes."""
        return runner.wrap(runner.run(["bridge", "audit"], timeout=60))

    @server.tool()
    async def bridge_call(
        endpoint: str,
        ctx: Context,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Call a bridge endpoint with native flags plus per-call approval for mutations."""
        payload = body or {}
        tier = bridge_tier(endpoint)
        invalid = _bridge_flags_valid(tier, payload)
        if invalid:
            append_audit(
                settings,
                {"tier": f"bridge_{tier}", "action": "blocked_flags", "target": endpoint},
            )
            return envelope(BLOCKED, note=invalid)
        denied = await _gate_bridge(settings, ctx, endpoint, tier)
        if denied:
            return envelope(BLOCKED, note=denied)
        args = ["bridge", "call", endpoint, json.dumps(payload, separators=(",", ":"))]
        result = await asyncio.to_thread(runner.run, args, 180)
        wrapped = runner.wrap(result)
        wrapped["note"] = f"bridge tier={tier}"
        if tier != "read":
            append_audit(
                settings,
                {
                    "tier": f"bridge_{tier}",
                    "action": "bridge_call",
                    "target": endpoint,
                    "outcome": "executed",
                    "status": wrapped["status"],
                },
            )
        return wrapped

    @server.tool()
    def cerberus_run(argv: list[str]) -> dict[str, Any]:
        """Run a long-tail local CLI command that does not bypass dedicated safety gates."""
        policy, reason = passthrough_policy(argv)
        append_audit(
            settings,
            {"tier": "passthrough", "action": policy, "command": argv, "reason": reason},
        )
        if policy == "blocked":
            return envelope(BLOCKED, command=[*settings.cli_command, *argv], note=reason)
        result = runner.wrap(runner.run(argv, timeout=900))
        result["note"] = reason
        return result

    @server.tool()
    def job_status(job_id: str) -> dict[str, Any]:
        """Poll restart-safe import or triage job state."""
        record = jobs.read(job_id)
        if record is None:
            return envelope(FAILED, note=f"unknown job_id {job_id}")
        status = FAILED if record["status"] == "error" else SUCCESS
        if record["status"] == "orphaned":
            status = UNVERIFIED
        return envelope(status, data=record, note=f"job {record['status']}")

    @server.tool()
    def job_list(include_archived: bool = False) -> dict[str, Any]:
        """List active jobs and optionally their archived durable records."""
        return envelope(SUCCESS, data={"jobs": jobs.list(include_archived=include_archived)})

    @server.tool()
    def job_close(job_id: str) -> dict[str, Any]:
        """Archive a terminal job record without deleting its evidence."""
        return jobs.archive(job_id)

    @server.resource("cerberus://projects")
    def projects_resource() -> str:
        projects = settings.workspace / "projects"
        names = sorted(path.name for path in projects.iterdir()) if projects.is_dir() else []
        return json.dumps({"workspace": str(settings.workspace), "projects": names}, indent=2)

    @server.resource("cerberus://audit")
    def audit_resource() -> str:
        if not settings.audit_log.is_file():
            return ""
        return "\n".join(settings.audit_log.read_text(encoding="utf-8").splitlines()[-200:])

    @server.resource("cerberus://jobs")
    def jobs_resource() -> str:
        return json.dumps({"jobs": jobs.list(include_archived=False)}, indent=2)

    @server.prompt()
    def operating_contract() -> str:
        mission = (
            "Mission tools are composed: record the run, claims, artifacts, friction, and closeout."
            if companion["available"]
            else "Mission tools are unavailable: install long-run-agent for durable long-run state."
        )
        return (
            "Loop: import_analyze -> export_apple_bundle -> focused static reports -> "
            "guarded lldb_trace/frida_recheck_attach -> runtime_enrich. Runtime and bridge "
            "mutation denials return blocked and must not be routed through cerberus_run. "
            "Treat no_hit and unverified as distinct from success. "
            + mission
        )

    return server


def preflight(settings: MCPSettings | None = None) -> None:
    settings = settings or MCPSettings.from_env()
    pinned = os.environ.get("CERBERUS_MCP_PINNED_VERSION")
    if pinned:
        try:
            installed = version("cerberus-re")
        except PackageNotFoundError:
            installed = None
        if installed != pinned:
            raise SystemExit(
                f"cerberus-mcp version mismatch: expected {pinned}, installed {installed}"
            )
    runner = CommandRunner(settings)
    probe = runner.run(["--help"], timeout=60)
    if not probe.get("_spawn_ok") or probe.get("returncode") not in (0, None):
        raise SystemExit(
            "cerberus-re CLI is not runnable; install the package or set CERBERUS_BIN"
        )
    if os.environ.get("CERBERUS_MCP_STRICT_SURFACE") == "1":
        result = runner.run(
            ["polish", "release", "--mode", "quick", "--strict-command-surface"],
            timeout=600,
        )
        if result.get("returncode") not in (0, None):
            raise SystemExit("Cerberus strict command-surface preflight failed")


mcp = create_server()


def main() -> None:
    settings = MCPSettings.from_env()
    preflight(settings)
    create_server(settings).run(transport="stdio")


if __name__ == "__main__":
    main()
