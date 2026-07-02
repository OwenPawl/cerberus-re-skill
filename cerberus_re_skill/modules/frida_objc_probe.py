"""General Frida ObjC class inventory and bounded method-call probe artifacts."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Sequence

from cerberus_re_skill.core.config import cfg
from cerberus_re_skill.core.subprocess_utils import find_tool
from cerberus_re_skill.core.utils import timestamp, utc_now
from cerberus_re_skill.modules.frida_diagnostics import frida_cli_command, known_frida_tool


EVENT_PREFIX = "GHIDRA_FRIDA_OBJC_PROBE "


def write_objc_probe_artifact(
    *,
    target: str | Path | None = None,
    attach_pid: int | None = None,
    attach_name: str = "",
    classes: Sequence[str] | None = None,
    calls: Sequence[str] | None = None,
    string_calls: Sequence[str] | None = None,
    output_dir: str | Path | None = None,
    allow_runtime: bool = False,
    timeout_seconds: float = 10.0,
    target_args: Sequence[str] | None = None,
    require_successful_call: bool = False,
    allow_attached_call: bool = False,
    runner: Any | None = None,
) -> dict:
    """Inventory ObjC classes and run bounded zero- or one-string-argument calls."""

    report_dir = _report_dir(output_dir)
    class_list = [str(item).strip() for item in (classes or []) if str(item).strip()]
    call_list = [str(item).strip() for item in (calls or []) if str(item).strip()]
    string_call_list = [str(item).strip() for item in (string_calls or []) if str(item).strip()]
    target_argv = [str(arg) for arg in (target_args or [])]
    trace_js = report_dir / "frida_objc_probe.js"
    trace = generate_objc_probe_script(class_list, call_list, trace_js, string_call_list)

    attach_name_pattern = str(attach_name or "").strip()
    modes = [target is not None, attach_pid is not None, bool(attach_name_pattern)]
    if sum(1 for active in modes if active) != 1:
        raise RuntimeError("exactly one of target, attach_pid, or attach_name is required")
    if (attach_pid is not None or attach_name_pattern) and target_argv:
        raise RuntimeError("target_args can only be used when spawning --target")
    if allow_runtime and string_call_list and (attach_pid is not None or attach_name_pattern) and not allow_attached_call:
        raise RuntimeError(
            "--call-string can terminate an attached process if a selector raises; "
            "validate in a disposable spawned target first, then pass --allow-attached-call explicitly"
        )

    if not allow_runtime:
        report = {
            "schema": "ghidra-re.frida-objc-probe.v1",
            "ok": True,
            "status": "skipped",
            "created_at": utc_now(),
            "target": str(target or ""),
            "attach_pid": attach_pid,
            "attach_name": attach_name_pattern,
            "resolved_attach_pid": None,
            "target_args": target_argv,
            "classes": class_list,
            "calls": call_list,
            "string_calls": string_call_list,
            "require_successful_call": require_successful_call,
            "allow_attached_call": allow_attached_call,
            "trace": trace,
            "command": [],
            "events": [],
            "message": "Runtime ObjC probe skipped; pass --allow-runtime to spawn or attach with Frida.",
        }
        return _write_report(report_dir, report)

    frida = known_frida_tool("frida") or find_tool("frida")
    if not frida:
        report = {
            "schema": "ghidra-re.frida-objc-probe.v1",
            "ok": False,
            "status": "blocked",
            "created_at": utc_now(),
            "target": str(target or ""),
            "attach_pid": attach_pid,
            "attach_name": attach_name_pattern,
            "resolved_attach_pid": None,
            "target_args": target_argv,
            "classes": class_list,
            "calls": call_list,
            "string_calls": string_call_list,
            "require_successful_call": require_successful_call,
            "allow_attached_call": allow_attached_call,
            "trace": trace,
            "command": [],
            "events": [],
            "error": "frida CLI not found",
        }
        return _write_report(report_dir, report)

    run = runner or _run_command
    resolved_attach_pid = attach_pid
    if attach_name_pattern:
        resolved_attach_pid = _wait_for_process_name(attach_name_pattern, timeout_seconds, run)
        if resolved_attach_pid is None:
            report = _base_runtime_report(
                target=str(target or ""),
                attach_pid=None,
                attach_name=attach_name_pattern,
                resolved_attach_pid=None,
                target_args=target_argv,
                classes=class_list,
                calls=call_list,
                string_calls=string_call_list,
                require_successful_call=require_successful_call,
                allow_attached_call=allow_attached_call,
                trace=trace,
                command=[],
                result={
                    "returncode": 124,
                    "stdout": "",
                    "stderr": f"timed out waiting for process matching {attach_name_pattern!r}",
                    "command": [],
                },
                events=[],
            )
            report["ok"] = False
            report["status"] = "blocked"
            return _write_report(report_dir, report)

    command = [*frida_cli_command("frida", frida)]
    if resolved_attach_pid is not None:
        command.extend(["-p", str(resolved_attach_pid)])
    else:
        command.extend(["-f", str(target)])
    command.extend(["-l", str(trace_js), "--runtime=v8", "-q", "-t", _frida_quiet_timeout(timeout_seconds)])
    if target_argv:
        command.extend(["--", *target_argv])

    result = run(command, timeout_seconds)
    combined_text = f"{result.get('stdout', '')}\n{result.get('stderr', '')}"
    events = parse_objc_probe_events(combined_text)
    done_ok = any(event.get("kind") == "done" and event.get("ok") for event in events)
    successful_calls = [
        event for event in events if event.get("kind") in {"call", "string-call"} and event.get("ok")
    ]
    successful_string_calls = [event for event in events if event.get("kind") == "string-call" and event.get("ok")]
    timeout_with_evidence = result.get("returncode") == 124 and bool(events)
    ok = (result.get("returncode") == 0 or timeout_with_evidence) and done_ok
    if require_successful_call:
        ok = ok and bool(successful_calls)
    status = "passed" if ok else "blocked"
    if done_ok and require_successful_call and not successful_calls:
        status = "no-successful-call"

    report = _base_runtime_report(
        target=str(target or ""),
        attach_pid=resolved_attach_pid,
        attach_name=attach_name_pattern,
        resolved_attach_pid=resolved_attach_pid if attach_name_pattern else None,
        target_args=target_argv,
        classes=class_list,
        calls=call_list,
        string_calls=string_call_list,
        require_successful_call=require_successful_call,
        allow_attached_call=allow_attached_call,
        trace=trace,
        command=command,
        result=result,
        events=events,
    )
    report["ok"] = ok
    report["status"] = status
    report["event_count"] = len(events)
    report["successful_call_count"] = len(successful_calls)
    report["successful_string_call_count"] = len(successful_string_calls)
    return _write_report(report_dir, report)


def generate_objc_probe_script(
    classes: Sequence[str],
    calls: Sequence[str],
    output: str | Path,
    string_calls: Sequence[str] | None = None,
) -> dict:
    output_path = Path(output)
    parsed_string_calls = _parse_string_calls(string_calls or [])
    script = _render_objc_probe_script(classes, calls, parsed_string_calls)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(script, encoding="utf-8")
    return {
        "ok": True,
        "output": str(output_path),
        "classes": list(classes),
        "calls": list(calls),
        "string_calls": [item["spec"] for item in parsed_string_calls],
    }


def parse_objc_probe_events(text: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw_line in str(text or "").splitlines():
        line = raw_line.strip()
        if not line.startswith(EVENT_PREFIX):
            continue
        try:
            event = json.loads(line[len(EVENT_PREFIX):])
        except json.JSONDecodeError:
            event = {"kind": "parse-error", "line": line}
        key = json.dumps(event, sort_keys=True)
        if key in seen:
            continue
        seen.add(key)
        events.append(event)
    return events


def _parse_string_calls(string_calls: Sequence[str]) -> list[dict[str, str]]:
    parsed: list[dict[str, str]] = []
    for raw_spec in string_calls:
        spec = str(raw_spec).strip()
        chain, separator, value = spec.partition("=")
        parts = chain.split(".") if separator else []
        if not separator or len(parts) < 2:
            raise RuntimeError("--call-string requires '<Class>.<zeroArg>.<oneArgSelector:>=<NSString>'")
        if any(":" in member for member in parts[1:-1]) or parts[-1].count(":") != 1:
            raise RuntimeError("--call-string permits exactly one string argument on the final selector only")
        parsed.append({"spec": spec, "chain": chain, "value": value})
    return parsed


def _render_objc_probe_script(classes: Sequence[str], calls: Sequence[str], string_calls: Sequence[dict[str, str]]) -> str:
    class_json = json.dumps(list(classes), sort_keys=True)
    call_json = json.dumps(list(calls), sort_keys=True)
    string_call_json = json.dumps(list(string_calls), sort_keys=True)
    return f"""const GHIDRA_CLASSES = {class_json};
const GHIDRA_CALLS = {call_json};
const GHIDRA_STRING_CALLS = {string_call_json};
const EVENT_PREFIX = "{EVENT_PREFIX}";

function emit(kind, payload) {{
  console.log(EVENT_PREFIX + JSON.stringify(Object.assign({{ kind: kind }}, payload || {{}})));
}}

function shortError(error) {{
  if (!error) return "";
  try {{ return String(error.stack || error.message || error); }}
  catch (_) {{ return "<unprintable error>"; }}
}}

function isLikelyObjCPointer(value) {{
  try {{
    if (value === null || value === undefined) return false;
    if (value.isNull && value.isNull()) return false;
    if (value.compare && value.compare(ptr("0x10000")) < 0) return false;
    var text = value.toString();
    var last = text[text.length - 1];
    if (last !== "0" && last !== "8") return false;
    var range = Process.findRangeByAddress(value);
    if (!range || range.protection.indexOf("r") === -1) return false;
    return true;
  }} catch (_) {{
    return false;
  }}
}}

function collectionPreview(object) {{
  try {{
    if (!object || typeof object.count !== "function") return null;
    var count = Number(object.count());
    var limit = Math.min(count, 2000);
    if (typeof object.allKeys === "function") {{
      var keys = object.allKeys();
      var items = [];
      var keyCount = Math.min(Number(keys.count()), limit);
      for (var i = 0; i < keyCount; i++) {{
        items.push(keys.objectAtIndex_(i).toString());
      }}
      items.sort();
      return {{ kind: "dictionary", count: count, keys: items, truncated: count > limit }};
    }}
    if (typeof object.objectAtIndex_ === "function") {{
      var values = [];
      for (var j = 0; j < limit; j++) {{
        values.push(object.objectAtIndex_(j).toString());
      }}
      return {{ kind: "indexed", count: count, values: values, truncated: count > limit }};
    }}
    return {{ kind: "collection", count: count, truncated: false }};
  }} catch (error) {{
    return {{ kind: "collection-error", error: shortError(error) }};
  }}
}}

function describeObjCObject(object) {{
  var result = {{ kind: "objc", className: object.$className, text: object.toString() }};
  var preview = collectionPreview(object);
  if (preview) result.collection = preview;
  return result;
}}

function describe(value) {{
  try {{
    if (value === null || value === undefined) return {{ kind: "null", text: String(value) }};
    if (value.$className) {{
      return describeObjCObject(value);
    }}
    if (isLikelyObjCPointer(value)) {{
      var object = ObjC.Object(value);
      return describeObjCObject(object);
    }}
    return {{ kind: typeof value, text: value.toString ? value.toString() : String(value) }};
  }} catch (error) {{
    return {{ kind: "error", text: shortError(error) }};
  }}
}}

function methodList(className) {{
  var cls = ObjC.classes[className];
  if (!cls) return {{ present: false }};
  try {{
    return {{ present: true, methods: cls.$ownMethods || [] }};
  }} catch (error) {{
    return {{ present: true, error: shortError(error), methods: [] }};
  }}
}}

function callChain(chain) {{
  var parts = chain.split(".");
  var className = parts.shift();
  var receiver = ObjC.classes[className];
  if (!receiver) {{
    emit("call", {{ chain: chain, ok: false, status: "missing-class", className: className }});
    return;
  }}
  var current = receiver;
  for (var i = 0; i < parts.length; i++) {{
    var member = parts[i];
    try {{
      if (!current || typeof current[member] !== "function") {{
        emit("call", {{ chain: chain, ok: false, status: "missing-member", member: member, step: i + 1 }});
        return;
      }}
      current = current[member]();
      emit("call-step", {{ chain: chain, member: member, step: i + 1, result: describe(current) }});
    }} catch (error) {{
      emit("call", {{ chain: chain, ok: false, status: "exception", member: member, step: i + 1, error: shortError(error) }});
      return;
    }}
  }}
  emit("call", {{ chain: chain, ok: true, status: "called", result: describe(current) }});
}}

function callString(spec) {{
  var parts = spec.chain.split(".");
  var className = parts.shift();
  var finalSelector = parts.pop();
  var receiver = ObjC.classes[className];
  if (!receiver) {{
    emit("string-call", {{ spec: spec.spec, chain: spec.chain, ok: false, status: "missing-class", className: className }});
    return;
  }}
  var current = receiver;
  for (var i = 0; i < parts.length; i++) {{
    var member = parts[i];
    try {{
      if (!current || typeof current[member] !== "function") {{
        emit("string-call", {{ spec: spec.spec, chain: spec.chain, ok: false, status: "missing-member", member: member, step: i + 1 }});
        return;
      }}
      current = current[member]();
      emit("string-call-step", {{ spec: spec.spec, chain: spec.chain, member: member, step: i + 1, result: describe(current) }});
    }} catch (error) {{
      emit("string-call", {{ spec: spec.spec, chain: spec.chain, ok: false, status: "exception", member: member, step: i + 1, error: shortError(error) }});
      return;
    }}
  }}
  var memberName = finalSelector.replace(/:/g, "_");
  try {{
    if (!current || typeof current[memberName] !== "function") {{
      emit("string-call", {{ spec: spec.spec, chain: spec.chain, ok: false, status: "missing-member", member: finalSelector, step: parts.length + 1 }});
      return;
    }}
    var argument = ObjC.classes.NSString.stringWithString_(spec.value);
    current = current[memberName](argument);
    emit("string-call", {{
      spec: spec.spec,
      chain: spec.chain,
      selector: finalSelector,
      argument: {{ kind: "NSString", text: spec.value }},
      ok: true,
      status: "called",
      result: describe(current)
    }});
  }} catch (error) {{
    emit("string-call", {{ spec: spec.spec, chain: spec.chain, ok: false, status: "exception", member: finalSelector, step: parts.length + 1, error: shortError(error) }});
  }}
}}

setImmediate(function () {{
  try {{
    if (typeof ObjC === "undefined") {{
      emit("done", {{ ok: false, status: "objc-global-missing" }});
      return;
    }}
    if (!ObjC.available) {{
      emit("done", {{ ok: false, status: "objc-unavailable" }});
      return;
    }}
    emit("status", {{ ok: true, status: "objc-available" }});
    GHIDRA_CLASSES.forEach(function (name) {{
      emit("class", {{ name: name, surface: methodList(name) }});
    }});
    GHIDRA_CALLS.forEach(callChain);
    GHIDRA_STRING_CALLS.forEach(callString);
    emit("done", {{ ok: true }});
  }} catch (error) {{
    emit("done", {{ ok: false, status: "exception", error: shortError(error) }});
  }}
}});
"""


def _base_runtime_report(**kwargs: Any) -> dict:
    return {
        "schema": "ghidra-re.frida-objc-probe.v1",
        "ok": False,
        "status": "blocked",
        "created_at": utc_now(),
        **kwargs,
    }


def _report_dir(output_dir: str | Path | None) -> Path:
    path = Path(output_dir) if output_dir else cfg.logs_dir / "frida" / f"objc-probe-{timestamp()}"
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


def _wait_for_process_name(pattern: str, timeout_seconds: float, runner: Any) -> int | None:
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
        if any(needle in command for needle in ["cerberus_re_skill", "frida_objc_probe", "mission_harness.py"]):
            continue
        if regex.search(command):
            return pid
    return None


def _frida_quiet_timeout(timeout_seconds: float) -> str:
    return f"{max(0.1, timeout_seconds - 0.5):g}"


def _write_report(report_dir: Path, report: dict) -> dict:
    json_path = report_dir / "frida-objc-probe.json"
    markdown_path = report_dir / "frida-objc-probe.md"
    report["json_report"] = str(json_path)
    report["markdown_report"] = str(markdown_path)
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_path.write_text(_render_markdown(report), encoding="utf-8")
    return report


def _render_markdown(report: dict) -> str:
    lines = [
        f"# Frida ObjC Probe - {'PASS' if report.get('ok') else report.get('status', 'BLOCKED').upper()}",
        "",
        f"- Schema: `{report.get('schema', '')}`",
        f"- Created: `{report.get('created_at', '')}`",
        f"- Status: `{report.get('status', '')}`",
        f"- Target: `{report.get('target', '')}`",
        f"- Attach PID: `{report.get('attach_pid')}`",
        f"- Attach name: `{report.get('attach_name', '')}`",
        f"- Classes: `{report.get('classes', [])}`",
        f"- Calls: `{report.get('calls', [])}`",
        f"- String calls: `{report.get('string_calls', [])}`",
        f"- Event count: `{report.get('event_count', len(report.get('events', [])))}`",
        f"- Successful calls: `{report.get('successful_call_count', 0)}`",
        f"- Successful string calls: `{report.get('successful_string_call_count', 0)}`",
        f"- Attached argument-call opt-in: `{report.get('allow_attached_call', False)}`",
    ]
    if report.get("message"):
        lines.extend(["", "## Message", "", f"- {report['message']}"])
    return "\n".join(lines).rstrip() + "\n"


def _decode(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return value.decode(errors="replace")
