"""Frida artifacts for bounded Objective-C construction/readback plans."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Sequence

from cerberus_re_skill.core.config import cfg
from cerberus_re_skill.core.subprocess_utils import find_tool
from cerberus_re_skill.core.utils import timestamp, utc_now
from cerberus_re_skill.modules.frida_diagnostics import frida_cli_command, known_frida_tool
from cerberus_re_skill.modules.frida_objc_probe import (
    _frida_quiet_timeout,
    _run_command,
    _wait_for_process_name,
)


EVENT_PREFIX = "GHIDRA_FRIDA_OBJC_PLAN "
PLAN_SCHEMA = "ghidra-re.objc-plan.v1"
REPORT_SCHEMA = "ghidra-re.frida-objc-plan.v1"
UNSAFE_SELECTOR = re.compile(r"(?:run|execute|perform|save|update|delete|remove|write|fire|trigger|launch|open|set)", re.I)
STEP_ID = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def write_objc_plan_artifact(
    *,
    plan_path: str | Path,
    target: str | Path | None = None,
    attach_pid: int | None = None,
    attach_name: str = "",
    output_dir: str | Path | None = None,
    allow_runtime: bool = False,
    allow_attached_plan: bool = False,
    extract_base64_steps: Sequence[str] | None = None,
    timeout_seconds: float = 10.0,
    target_args: Sequence[str] | None = None,
    runner: Any | None = None,
) -> dict:
    """Run a validated construction/readback plan in one ObjC process."""
    plan_file = Path(plan_path)
    if not plan_file.exists():
        raise RuntimeError(f"plan does not exist: {plan_file}")
    plan_bytes = plan_file.read_bytes()
    plan = _validate_plan(json.loads(plan_bytes.decode("utf-8")))
    extracted_step_ids = _validate_extracted_step_ids(plan, extract_base64_steps or [])
    target_argv = [str(arg) for arg in (target_args or [])]
    attach_name_pattern = str(attach_name or "").strip()
    modes = [target is not None, attach_pid is not None, bool(attach_name_pattern)]
    if sum(1 for active in modes if active) != 1:
        raise RuntimeError("exactly one of target, attach_pid, or attach_name is required")
    if (attach_pid is not None or attach_name_pattern) and target_argv:
        raise RuntimeError("target_args can only be used when spawning --target")
    if allow_runtime and (attach_pid is not None or attach_name_pattern) and not allow_attached_plan:
        raise RuntimeError(
            "Objective-C construction plans may throw in an attached process; "
            "use a disposable spawned target first, then pass --allow-attached-plan explicitly"
        )

    report_dir = _report_dir(output_dir)
    trace_js = report_dir / "frida_objc_plan.js"
    trace = generate_objc_plan_script(plan=plan, output=trace_js)
    base = {
        "schema": REPORT_SCHEMA,
        "created_at": utc_now(),
        "target": str(target or ""),
        "attach_pid": attach_pid,
        "attach_name": attach_name_pattern,
        "resolved_attach_pid": None,
        "target_args": target_argv,
        "plan_path": str(plan_file),
        "plan_sha256": hashlib.sha256(plan_bytes).hexdigest(),
        "plan": plan,
        "allow_attached_plan": allow_attached_plan,
        "extract_base64_steps": extracted_step_ids,
        "trace": trace,
    }
    if not allow_runtime:
        return _write_report(
            report_dir,
            {
                **base,
                "ok": True,
                "status": "skipped",
                "command": [],
                "events": [],
                "message": "Runtime ObjC plan skipped; pass --allow-runtime to spawn or attach with Frida.",
            },
        )

    frida = known_frida_tool("frida") or find_tool("frida")
    if not frida:
        return _write_report(
            report_dir,
            {**base, "ok": False, "status": "blocked", "command": [], "events": [], "error": "frida CLI not found"},
        )

    run = runner or _run_command
    resolved_attach_pid = attach_pid
    if attach_name_pattern:
        resolved_attach_pid = _wait_for_process_name(attach_name_pattern, timeout_seconds, run)
        if resolved_attach_pid is None:
            return _write_report(
                report_dir,
                {
                    **base,
                    "ok": False,
                    "status": "blocked",
                    "command": [],
                    "events": [],
                    "error": f"timed out waiting for process matching {attach_name_pattern!r}",
                },
            )

    command = [*frida_cli_command("frida", frida)]
    if resolved_attach_pid is not None:
        command.extend(["-p", str(resolved_attach_pid)])
    else:
        command.extend(["-f", str(target)])
    command.extend(["-l", str(trace_js), "--runtime=v8", "-q", "-t", _frida_quiet_timeout(timeout_seconds)])
    if target_argv:
        command.extend(["--", *target_argv])
    result = run(command, timeout_seconds)
    events = parse_objc_plan_events(f"{result.get('stdout', '')}\n{result.get('stderr', '')}")
    execution = _summarize_execution(plan, events)
    extracted_outputs = _extract_base64_outputs(report_dir, events, extracted_step_ids)
    timeout_with_evidence = result.get("returncode") == 124 and bool(events)
    extraction_ok = all(output["ok"] for output in extracted_outputs)
    ok = (result.get("returncode") == 0 or timeout_with_evidence) and execution["ok"] and extraction_ok
    status = "blocked"
    if not extraction_ok:
        status = "extraction_failed"
    elif ok:
        if execution["trailing_step_count"]:
            status = "passed_with_trailing_events"
        elif execution["suppressed_replay_count"]:
            status = "passed_with_suppressed_replay"
        else:
            status = "passed"
    report = {
        **base,
        **execution,
        "ok": ok,
        "status": status,
        "attach_pid": resolved_attach_pid,
        "resolved_attach_pid": resolved_attach_pid if attach_name_pattern else None,
        "command": command,
        "result": result,
        "events": events,
        "event_count": len(events),
        "extracted_outputs": extracted_outputs,
    }
    return _write_report(report_dir, report)


def generate_objc_plan_script(*, plan: dict[str, Any], output: str | Path) -> dict:
    validated = _validate_plan(plan)
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(_render_script(validated), encoding="utf-8")
    return {"ok": True, "output": str(output_path), "step_count": len(validated["steps"])}


def parse_objc_plan_events(text: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for raw_line in str(text or "").splitlines():
        line = raw_line.strip()
        if not line.startswith(EVENT_PREFIX):
            continue
        try:
            event = json.loads(line[len(EVENT_PREFIX):])
        except json.JSONDecodeError:
            event = {"kind": "parse-error", "line": line}
        events.append(event)
    return events


def _summarize_execution(plan: dict[str, Any], events: list[dict[str, Any]]) -> dict[str, Any]:
    done_index = next(
        (index for index, event in enumerate(events) if event.get("kind") == "done"),
        None,
    )
    primary = events if done_index is None else events[:done_index]
    trailing = [] if done_index is None else events[done_index + 1:]
    completed = [event for event in primary if event.get("kind") == "step" and event.get("ok")]
    failed = [event for event in primary if event.get("kind") == "step" and not event.get("ok")]
    expected_ids = [step["id"] for step in plan["steps"]]
    completed_ids = [str(event.get("id", "")) for event in completed]
    done_ok = done_index is not None and bool(events[done_index].get("ok"))
    sequence_ok = completed_ids == expected_ids
    return {
        "ok": done_ok and sequence_ok and not failed,
        "done_ok": done_ok,
        "sequence_ok": sequence_ok,
        "expected_step_count": len(expected_ids),
        "completed_step_count": len(completed),
        "failed_step_count": len(failed),
        "trailing_event_count": len(trailing),
        "trailing_step_count": sum(1 for event in trailing if event.get("kind") == "step"),
        "suppressed_replay_count": sum(1 for event in trailing if event.get("kind") == "suppressed"),
    }


def _validate_plan(plan: Any) -> dict[str, Any]:
    if not isinstance(plan, dict) or plan.get("schema") != PLAN_SCHEMA:
        raise RuntimeError(f"plan schema must be {PLAN_SCHEMA!r}")
    allow_ephemeral_configuration = plan.get("allow_ephemeral_configuration") is True
    raw_steps = plan.get("steps")
    if not isinstance(raw_steps, list) or not raw_steps:
        raise RuntimeError("plan requires a non-empty steps list")
    known: set[str] = set()
    steps: list[dict[str, Any]] = []
    for raw in raw_steps:
        if not isinstance(raw, dict):
            raise RuntimeError("each plan step must be an object")
        step_id = str(raw.get("id", "")).strip()
        operation = str(raw.get("op", "")).strip()
        if not STEP_ID.fullmatch(step_id) or step_id in known:
            raise RuntimeError("plan step ids must be unique identifier names")
        if operation not in {
            "string",
            "boolean",
            "empty-dictionary",
            "nil",
            "class-read",
            "construct",
            "call",
            "read",
            "ln-entity-property",
            "configure-parameter-state",
        }:
            raise RuntimeError(f"unsupported plan operation: {operation!r}")
        step: dict[str, Any] = {"id": step_id, "op": operation}
        if operation == "string":
            step["value"] = str(raw.get("value", ""))
        elif operation == "boolean":
            if not isinstance(raw.get("value"), bool):
                raise RuntimeError("boolean steps require a JSON true or false value")
            step["value"] = raw["value"]
        elif operation == "class-read":
            class_name = str(raw.get("class", "")).strip()
            selector = str(raw.get("selector", "")).strip()
            if not class_name or not selector or ":" in selector:
                raise RuntimeError("class-read steps require a class and a zero-argument selector")
            if UNSAFE_SELECTOR.search(selector):
                raise RuntimeError(f"unsafe selector is not permitted in an ObjC plan: {selector}")
            step["class"] = class_name
            step["selector"] = selector
        elif operation in {"construct", "call", "read"}:
            selector = str(raw.get("selector", "")).strip()
            args = list(raw.get("args") or [])
            if not selector:
                raise RuntimeError(f"step {step_id!r} requires a selector")
            if operation == "construct":
                class_name = str(raw.get("class", "")).strip()
                if not class_name or not selector.startswith("initWith"):
                    raise RuntimeError("construct steps require a class and an initWith... selector")
                step["class"] = class_name
            else:
                receiver = str(raw.get("receiver", "")).strip()
                _require_reference(receiver, known)
                step["receiver"] = receiver
            if operation == "read" and args:
                raise RuntimeError("read steps cannot accept arguments")
            if operation != "read" and selector.count(":") != len(args):
                raise RuntimeError(f"step {step_id!r} selector argument count does not match args")
            if operation == "read" and ":" in selector:
                raise RuntimeError("read steps must use a zero-argument selector")
            if operation != "construct" and UNSAFE_SELECTOR.search(selector):
                raise RuntimeError(f"unsafe selector is not permitted in an ObjC plan: {selector}")
            for reference in args:
                _require_reference(str(reference), known)
            step["selector"] = selector
            step["args"] = [str(reference) for reference in args]
        elif operation == "ln-entity-property":
            receiver = str(raw.get("receiver", "")).strip()
            identifier = str(raw.get("identifier", "")).strip()
            _require_reference(receiver, known)
            if not identifier:
                raise RuntimeError("ln-entity-property steps require a property identifier")
            step["receiver"] = receiver
            step["identifier"] = identifier
        elif operation == "configure-parameter-state":
            if not allow_ephemeral_configuration:
                raise RuntimeError("configure-parameter-state requires allow_ephemeral_configuration=true")
            receiver = str(raw.get("receiver", "")).strip()
            state = str(raw.get("state", "")).strip()
            key = str(raw.get("key", "")).strip()
            _require_reference(receiver, known)
            _require_reference(state, known)
            _require_reference(key, known)
            step["receiver"] = receiver
            step["state"] = state
            step["key"] = key
            step["selector"] = "setParameterState:forKey:"
        known.add(step_id)
        steps.append(step)
    return {
        "schema": PLAN_SCHEMA,
        "allow_ephemeral_configuration": allow_ephemeral_configuration,
        "steps": steps,
    }


def _require_reference(reference: str, known: set[str]) -> None:
    if not reference.startswith("$") or reference[1:] not in known:
        raise RuntimeError(f"plan reference must name an earlier step: {reference!r}")


def _validate_extracted_step_ids(plan: dict[str, Any], step_ids: Sequence[str]) -> list[str]:
    known = {step["id"] for step in plan["steps"]}
    validated: list[str] = []
    for raw in step_ids:
        step_id = str(raw).strip()
        if step_id not in known:
            raise RuntimeError(f"base64 extraction step must name a plan step: {step_id!r}")
        if step_id not in validated:
            validated.append(step_id)
    return validated


def _extract_base64_outputs(report_dir: Path, events: list[dict[str, Any]], step_ids: list[str]) -> list[dict[str, Any]]:
    primary_events: dict[str, dict[str, Any]] = {}
    for event in events:
        if event.get("kind") == "done":
            break
        if event.get("kind") == "step" and event.get("ok") and event.get("id") not in primary_events:
            primary_events[str(event["id"])] = event
    outputs: list[dict[str, Any]] = []
    for step_id in step_ids:
        text = primary_events.get(step_id, {}).get("result", {}).get("text")
        if not isinstance(text, str):
            outputs.append({"step_id": step_id, "ok": False, "error": "step did not return a textual base64 result"})
            continue
        try:
            decoded = base64.b64decode(text, validate=True)
        except (binascii.Error, ValueError) as error:
            outputs.append({"step_id": step_id, "ok": False, "error": f"invalid base64 result: {error}"})
            continue
        output_path = report_dir / f"frida-objc-plan-{step_id}.bin"
        output_path.write_bytes(decoded)
        outputs.append(
            {
                "step_id": step_id,
                "ok": True,
                "path": str(output_path),
                "byte_length": len(decoded),
                "sha256": hashlib.sha256(decoded).hexdigest(),
            }
        )
    return outputs


def _render_script(plan: dict[str, Any]) -> str:
    plan_json = json.dumps(plan, sort_keys=True)
    plan_guard_key = "ghidra_re_objc_plan_" + hashlib.sha256(plan_json.encode("utf-8")).hexdigest()
    return f"""const GHIDRA_PLAN = {plan_json};
const EVENT_PREFIX = "{EVENT_PREFIX}";
const RUN_GUARD = "{plan_guard_key}";
const values = {{}};

function emit(kind, payload) {{
  console.log(EVENT_PREFIX + JSON.stringify(Object.assign({{ kind: kind }}, payload || {{}})));
}}
function shortError(error) {{
  try {{ return String(error.stack || error.message || error); }}
  catch (_) {{ return "<unprintable error>"; }}
}}
function describe(value) {{
  try {{
    if (value === null || value === undefined) return {{ kind: "null", text: String(value) }};
    if (typeof value === "boolean") return {{ kind: "boolean", value: value, text: String(value) }};
    if (value.isNull && value.isNull()) return {{ kind: "null", text: "0x0" }};
    return {{ kind: "objc", className: value.$className, text: value.toString() }};
  }} catch (error) {{
    return {{ kind: "value", text: String(value), error: shortError(error) }};
  }}
}}
function argument(reference) {{
  return values[reference.substring(1)];
}}
function methodName(selector) {{
  return selector.replace(/:/g, "_");
}}
function lnEntityPropertyValue(receiver, identifier) {{
  var entity = receiver.value();
  var properties = entity.properties();
  for (var index = 0; index < Number(properties.count()); index += 1) {{
    var property = properties.objectAtIndex_(index);
    if (String(property.identifier()) === identifier) return property.value();
  }}
  throw new Error("LNEntity property not found: " + identifier);
}}
function globalExport(name) {{
  if (Module.findGlobalExportByName) return Module.findGlobalExportByName(name);
  return Module.findExportByName(null, name);
}}
function claimProcessPlan() {{
  var registerName = new NativeFunction(globalExport("sel_registerName"), "pointer", ["pointer"]);
  var getAssociated = new NativeFunction(globalExport("objc_getAssociatedObject"), "pointer", ["pointer", "pointer"]);
  var setAssociated = new NativeFunction(globalExport("objc_setAssociatedObject"), "void", ["pointer", "pointer", "pointer", "ulong"]);
  var key = registerName(Memory.allocUtf8String(RUN_GUARD));
  var owner = ObjC.classes.NSProcessInfo.processInfo().handle;
  if (!getAssociated(owner, key).isNull()) return false;
  var marker = ObjC.classes.NSString.stringWithString_("executed");
  setAssociated(owner, key, marker.handle, 1);
  return true;
}}
function execute(step) {{
  var result;
  if (step.op === "string") {{
    result = ObjC.classes.NSString.stringWithString_(step.value);
  }} else if (step.op === "boolean") {{
    result = step.value;
  }} else if (step.op === "empty-dictionary") {{
    result = ObjC.classes.NSDictionary.dictionary();
  }} else if (step.op === "nil") {{
    result = ptr(0);
  }} else if (step.op === "class-read") {{
    result = ObjC.classes[step.class][methodName(step.selector)]();
  }} else if (step.op === "construct") {{
    var instance = ObjC.classes[step.class].alloc();
    result = instance[methodName(step.selector)].apply(instance, step.args.map(argument));
  }} else if (step.op === "call" || step.op === "read") {{
    var receiver = argument(step.receiver);
    result = receiver[methodName(step.selector)].apply(receiver, step.args.map(argument));
  }} else if (step.op === "ln-entity-property") {{
    result = lnEntityPropertyValue(argument(step.receiver), step.identifier);
  }} else if (step.op === "configure-parameter-state") {{
    var configuredReceiver = argument(step.receiver);
    configuredReceiver.setParameterState_forKey_(argument(step.state), argument(step.key));
    result = configuredReceiver;
  }}
  values[step.id] = result;
  emit("step", {{ id: step.id, op: step.op, selector: step.selector || "", ok: true, result: describe(result) }});
}}
setImmediate(function () {{
  try {{
    if (!ObjC.available) {{
      emit("done", {{ ok: false, status: "objc-unavailable" }});
      return;
    }}
    if (!claimProcessPlan()) {{
      emit("suppressed", {{ ok: true, status: "already-executed" }});
      emit("done", {{ ok: true, status: "already-executed" }});
      return;
    }}
    GHIDRA_PLAN.steps.forEach(execute);
    emit("done", {{ ok: true }});
  }} catch (error) {{
    emit("step", {{ ok: false, status: "exception", error: shortError(error) }});
    emit("done", {{ ok: false, status: "exception" }});
  }}
}});
"""


def _report_dir(output_dir: str | Path | None) -> Path:
    path = Path(output_dir) if output_dir else cfg.logs_dir / "frida" / f"objc-plan-{timestamp()}"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _write_report(report_dir: Path, report: dict) -> dict:
    json_path = report_dir / "frida-objc-plan.json"
    markdown_path = report_dir / "frida-objc-plan.md"
    report["json_report"] = str(json_path)
    report["markdown_report"] = str(markdown_path)
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_path.write_text(_render_markdown(report), encoding="utf-8")
    return report


def _render_markdown(report: dict) -> str:
    return "\n".join(
        [
            f"# Frida ObjC Plan - {'PASS' if report.get('ok') else report.get('status', 'BLOCKED').upper()}",
            "",
            f"- Schema: `{report.get('schema', '')}`",
            f"- Created: `{report.get('created_at', '')}`",
            f"- Status: `{report.get('status', '')}`",
            f"- Plan: `{report.get('plan_path', '')}`",
            f"- Plan SHA-256: `{report.get('plan_sha256', '')}`",
            f"- Attach PID: `{report.get('attach_pid')}`",
            f"- Attach plan opt-in: `{report.get('allow_attached_plan', False)}`",
            f"- Base64 extraction steps: `{report.get('extract_base64_steps', [])}`",
            f"- Steps expected: `{report.get('expected_step_count', 0)}`",
            f"- Steps completed: `{report.get('completed_step_count', 0)}`",
            f"- Steps failed: `{report.get('failed_step_count', 0)}`",
            f"- Trailing events: `{report.get('trailing_event_count', 0)}`",
            f"- Suppressed replays: `{report.get('suppressed_replay_count', 0)}`",
            f"- Extracted outputs: `{report.get('extracted_outputs', [])}`",
            "",
        ]
    )
