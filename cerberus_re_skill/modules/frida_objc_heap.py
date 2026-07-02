"""Frida ObjC heap instance inspection artifacts."""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any, Sequence

from cerberus_re_skill.core.config import cfg
from cerberus_re_skill.core.subprocess_utils import find_tool
from cerberus_re_skill.core.utils import timestamp, utc_now
from cerberus_re_skill.modules.frida_diagnostics import frida_cli_command, known_frida_tool


EVENT_PREFIX = "GHIDRA_FRIDA_OBJC_HEAP "


def write_objc_heap_artifact(
    *,
    target: str | Path | None = None,
    attach_pid: int | None = None,
    attach_name: str = "",
    classes: Sequence[str] | None = None,
    getters: Sequence[str] | None = None,
    output_dir: str | Path | None = None,
    allow_runtime: bool = False,
    timeout_seconds: float = 10.0,
    target_args: Sequence[str] | None = None,
    max_instances: int = 8,
    include_ivars: bool = False,
    require_instance: bool = False,
    runner: Any | None = None,
) -> dict:
    """Inspect live ObjC heap instances for selected classes."""

    report_dir = _report_dir(output_dir)
    class_list = [str(item).strip() for item in (classes or []) if str(item).strip()]
    getter_list = [str(item).strip() for item in (getters or []) if str(item).strip()]
    target_argv = [str(arg) for arg in (target_args or [])]
    trace_js = report_dir / "frida_objc_heap.js"
    trace = generate_objc_heap_script(
        classes=class_list,
        getters=getter_list,
        output=trace_js,
        max_instances=max_instances,
        include_ivars=include_ivars,
    )

    attach_name_pattern = str(attach_name or "").strip()
    modes = [target is not None, attach_pid is not None, bool(attach_name_pattern)]
    if sum(1 for active in modes if active) != 1:
        raise RuntimeError("exactly one of target, attach_pid, or attach_name is required")
    if (attach_pid is not None or attach_name_pattern) and target_argv:
        raise RuntimeError("target_args can only be used when spawning --target")

    if not allow_runtime:
        report = {
            "schema": "ghidra-re.frida-objc-heap.v1",
            "ok": True,
            "status": "skipped",
            "created_at": utc_now(),
            "target": str(target or ""),
            "attach_pid": attach_pid,
            "attach_name": attach_name_pattern,
            "resolved_attach_pid": None,
            "target_args": target_argv,
            "classes": class_list,
            "getters": getter_list,
            "include_ivars": include_ivars,
            "max_instances": max_instances,
            "require_instance": require_instance,
            "trace": trace,
            "command": [],
            "events": [],
            "message": "Runtime ObjC heap inspection skipped; pass --allow-runtime to spawn or attach with Frida.",
        }
        return _write_report(report_dir, report)

    frida = known_frida_tool("frida") or find_tool("frida")
    if not frida:
        report = _base_runtime_report(
            target=str(target or ""),
            attach_pid=attach_pid,
            attach_name=attach_name_pattern,
            resolved_attach_pid=None,
            target_args=target_argv,
            classes=class_list,
            getters=getter_list,
            include_ivars=include_ivars,
            max_instances=max_instances,
            require_instance=require_instance,
            trace=trace,
            command=[],
            result={},
            events=[],
        )
        report["status"] = "blocked"
        report["error"] = "frida CLI not found"
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
                getters=getter_list,
                include_ivars=include_ivars,
                max_instances=max_instances,
                require_instance=require_instance,
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
    events = parse_objc_heap_events(combined_text)
    done_ok = any(event.get("kind") == "done" and event.get("ok") for event in events)
    instances = [event for event in events if event.get("kind") == "instance"]
    timeout_with_evidence = result.get("returncode") == 124 and bool(events)
    ok = (result.get("returncode") == 0 or timeout_with_evidence) and done_ok
    if require_instance:
        ok = ok and bool(instances)
    status = "passed" if ok else "blocked"
    if done_ok and require_instance and not instances:
        status = "no-instances"

    report = _base_runtime_report(
        target=str(target or ""),
        attach_pid=resolved_attach_pid,
        attach_name=attach_name_pattern,
        resolved_attach_pid=resolved_attach_pid if attach_name_pattern else None,
        target_args=target_argv,
        classes=class_list,
        getters=getter_list,
        include_ivars=include_ivars,
        max_instances=max_instances,
        require_instance=require_instance,
        trace=trace,
        command=command,
        result=result,
        events=events,
    )
    report["ok"] = ok
    report["status"] = status
    report["event_count"] = len(events)
    report["instance_count"] = len(instances)
    return _write_report(report_dir, report)


def generate_objc_heap_script(
    *,
    classes: Sequence[str],
    getters: Sequence[str],
    output: str | Path,
    max_instances: int = 8,
    include_ivars: bool = False,
) -> dict:
    output_path = Path(output)
    script = _render_objc_heap_script(classes, getters, max_instances=max_instances, include_ivars=include_ivars)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(script, encoding="utf-8")
    return {
        "ok": True,
        "output": str(output_path),
        "classes": list(classes),
        "getters": list(getters),
        "max_instances": max_instances,
        "include_ivars": include_ivars,
    }


def parse_objc_heap_events(text: str) -> list[dict[str, Any]]:
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


def _render_objc_heap_script(
    classes: Sequence[str],
    getters: Sequence[str],
    *,
    max_instances: int,
    include_ivars: bool,
) -> str:
    class_json = json.dumps(list(classes), sort_keys=True)
    getter_json = json.dumps(list(getters), sort_keys=True)
    max_value = max(1, int(max_instances))
    include_value = "true" if include_ivars else "false"
    return f"""const GHIDRA_CLASSES = {class_json};
const GHIDRA_GETTERS = {getter_json};
const GHIDRA_MAX_INSTANCES = {max_value};
const GHIDRA_INCLUDE_IVARS = {include_value};
const EVENT_PREFIX = "{EVENT_PREFIX}";

function emit(kind, payload) {{
  console.log(EVENT_PREFIX + JSON.stringify(Object.assign({{ kind: kind }}, payload || {{}})));
}}

function shortError(error) {{
  if (!error) return "";
  try {{ return String(error.stack || error.message || error); }}
  catch (_) {{ return "<unprintable error>"; }}
}}

function describe(value) {{
  try {{
    if (value === null || value === undefined) return {{ kind: "null", text: String(value) }};
    if (typeof value === "boolean" || typeof value === "number" || typeof value === "string") {{
      return {{ kind: typeof value, text: String(value), value: value }};
    }}
    if (value.handle !== undefined) {{
      var className = null;
      var text = null;
      try {{ className = value.$className || null; }} catch (_) {{}}
      try {{ text = value.toString(); }} catch (error) {{ text = "<toString error: " + shortError(error) + ">"; }}
      return {{ kind: "objc", className: className, text: text, handle: value.handle.toString() }};
    }}
    return {{ kind: typeof value, text: value.toString ? value.toString() : String(value) }};
  }} catch (error) {{
    return {{ kind: "describe-error", error: shortError(error) }};
  }}
}}

function ivarSnapshot(object) {{
  var result = {{}};
  if (!GHIDRA_INCLUDE_IVARS) return result;
  try {{
    var ivars = object.$ivars;
    Object.keys(ivars).sort().forEach(function (key) {{
      try {{
        result[key] = describe(ivars[key]);
      }} catch (error) {{
        result[key] = {{ kind: "ivar-error", error: shortError(error) }};
      }}
    }});
  }} catch (error) {{
    result = {{ error: shortError(error) }};
  }}
  return result;
}}

function responds(object, selectorName) {{
  try {{
    return object.respondsToSelector_(ObjC.selector(selectorName)) ? true : false;
  }} catch (_) {{
    return false;
  }}
}}

function callGetter(object, selectorName) {{
  if (selectorName.indexOf(":") !== -1) {{
    return {{ getter: selectorName, ok: false, status: "requires-arguments" }};
  }}
  if (!responds(object, selectorName)) {{
    return {{ getter: selectorName, ok: false, status: "does-not-respond" }};
  }}
  try {{
    if (object[selectorName] === undefined || typeof object[selectorName] !== "function") {{
      return {{ getter: selectorName, ok: false, status: "missing-js-wrapper" }};
    }}
    return {{ getter: selectorName, ok: true, result: describe(object[selectorName]()) }};
  }} catch (error) {{
    return {{ getter: selectorName, ok: false, status: "threw", error: shortError(error) }};
  }}
}}

function inspectObject(className, object, index) {{
  emit("instance", {{
    className: className,
    index: index,
    object: describe(object),
    ivars: ivarSnapshot(object),
    getters: GHIDRA_GETTERS.map(function (getter) {{ return callGetter(object, getter); }})
  }});
}}

function chooseClass(className, done) {{
  var klass = ObjC.classes[className];
  if (!klass) {{
    emit("class-complete", {{ className: className, present: false, observedCount: 0, emittedCount: 0, truncated: false }});
    done();
    return;
  }}
  var count = 0;
  var truncated = false;
  ObjC.choose(klass, {{
    onMatch: function (object) {{
      count += 1;
      if (count <= GHIDRA_MAX_INSTANCES) {{
        inspectObject(className, object, count);
      }} else {{
        truncated = true;
        return "stop";
      }}
    }},
    onComplete: function () {{
      emit("class-complete", {{
        className: className,
        present: true,
        observedCount: count,
        emittedCount: Math.min(count, GHIDRA_MAX_INSTANCES),
        truncated: truncated
      }});
      done();
    }}
  }});
}}

function runClasses(index) {{
  if (index >= GHIDRA_CLASSES.length) {{
    emit("done", {{ ok: true }});
    return;
  }}
  chooseClass(GHIDRA_CLASSES[index], function () {{
    setTimeout(function () {{ runClasses(index + 1); }}, 50);
  }});
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
    runClasses(0);
  }} catch (error) {{
    emit("done", {{ ok: false, status: "exception", error: shortError(error) }});
  }}
}});
"""


def _base_runtime_report(**kwargs: Any) -> dict:
    return {
        "schema": "ghidra-re.frida-objc-heap.v1",
        "ok": False,
        "status": "blocked",
        "created_at": utc_now(),
        **kwargs,
    }


def _report_dir(output_dir: str | Path | None) -> Path:
    path = Path(output_dir) if output_dir else cfg.logs_dir / "frida" / f"objc-heap-{timestamp()}"
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
        if any(needle in command for needle in ["cerberus_re_skill", "frida_objc_heap", "mission_harness.py"]):
            continue
        if regex.search(command):
            return pid
    return None


def _frida_quiet_timeout(timeout_seconds: float) -> str:
    return f"{max(0.1, timeout_seconds - 0.5):g}"


def _write_report(report_dir: Path, report: dict) -> dict:
    json_path = report_dir / "frida-objc-heap.json"
    markdown_path = report_dir / "frida-objc-heap.md"
    report["json_report"] = str(json_path)
    report["markdown_report"] = str(markdown_path)
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_path.write_text(_render_markdown(report), encoding="utf-8")
    return report


def _render_markdown(report: dict) -> str:
    lines = [
        f"# Frida ObjC Heap - {'PASS' if report.get('ok') else report.get('status', 'BLOCKED').upper()}",
        "",
        f"- Schema: `{report.get('schema', '')}`",
        f"- Created: `{report.get('created_at', '')}`",
        f"- Status: `{report.get('status', '')}`",
        f"- Target: `{report.get('target', '')}`",
        f"- Attach PID: `{report.get('attach_pid')}`",
        f"- Attach name: `{report.get('attach_name', '')}`",
        f"- Classes: `{report.get('classes', [])}`",
        f"- Getters: `{report.get('getters', [])}`",
        f"- Include ivars: `{report.get('include_ivars', False)}`",
        f"- Max instances: `{report.get('max_instances', '')}`",
        f"- Event count: `{report.get('event_count', len(report.get('events', [])))}`",
        f"- Instance count: `{report.get('instance_count', 0)}`",
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
