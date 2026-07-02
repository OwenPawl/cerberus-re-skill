"""Frida ObjC secure-archive readback artifacts."""

from __future__ import annotations

import base64
import hashlib
import json
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


EVENT_PREFIX = "GHIDRA_FRIDA_OBJC_ARCHIVE "


def write_objc_archive_artifact(
    *,
    archive_path: str | Path,
    class_name: str,
    getters: Sequence[str] | None = None,
    target: str | Path | None = None,
    attach_pid: int | None = None,
    attach_name: str = "",
    output_dir: str | Path | None = None,
    allow_runtime: bool = False,
    timeout_seconds: float = 10.0,
    target_args: Sequence[str] | None = None,
    runner: Any | None = None,
) -> dict:
    """Secure-unarchive host bytes inside an ObjC process and inspect no-arg getters."""

    archive = Path(archive_path)
    if not archive.exists():
        raise RuntimeError(f"archive does not exist: {archive}")
    decoded_class = str(class_name or "").strip()
    if not decoded_class:
        raise RuntimeError("class_name is required")

    archive_bytes = archive.read_bytes()
    archive_sha256 = hashlib.sha256(archive_bytes).hexdigest()
    getter_list = [str(item).strip() for item in (getters or []) if str(item).strip()]
    target_argv = [str(arg) for arg in (target_args or [])]
    report_dir = _report_dir(output_dir)
    trace_js = report_dir / "frida_objc_archive.js"
    trace = generate_objc_archive_script(
        archive_bytes=archive_bytes,
        class_name=decoded_class,
        getters=getter_list,
        output=trace_js,
    )

    attach_name_pattern = str(attach_name or "").strip()
    modes = [target is not None, attach_pid is not None, bool(attach_name_pattern)]
    if sum(1 for active in modes if active) != 1:
        raise RuntimeError("exactly one of target, attach_pid, or attach_name is required")
    if (attach_pid is not None or attach_name_pattern) and target_argv:
        raise RuntimeError("target_args can only be used when spawning --target")

    base = {
        "schema": "ghidra-re.frida-objc-archive.v1",
        "created_at": utc_now(),
        "target": str(target or ""),
        "attach_pid": attach_pid,
        "attach_name": attach_name_pattern,
        "resolved_attach_pid": None,
        "target_args": target_argv,
        "archive_path": str(archive),
        "archive_size": len(archive_bytes),
        "archive_sha256": archive_sha256,
        "class_name": decoded_class,
        "getters": getter_list,
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
                "message": "Runtime ObjC archive readback skipped; pass --allow-runtime to spawn or attach with Frida.",
            },
        )

    frida = known_frida_tool("frida") or find_tool("frida")
    if not frida:
        return _write_report(
            report_dir,
            {
                **base,
                "ok": False,
                "status": "blocked",
                "command": [],
                "events": [],
                "error": "frida CLI not found",
            },
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
                    "result": {
                        "returncode": 124,
                        "stdout": "",
                        "stderr": f"timed out waiting for process matching {attach_name_pattern!r}",
                        "command": [],
                    },
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
    combined_text = f"{result.get('stdout', '')}\n{result.get('stderr', '')}"
    events = parse_objc_archive_events(combined_text)
    readback = _summarize_readback(events)
    timeout_with_evidence = result.get("returncode") == 124 and bool(events)
    ok = (result.get("returncode") == 0 or timeout_with_evidence) and readback["done_ok"] and bool(
        readback["decoded_object_count"]
    )
    status = "blocked"
    if readback["done_ok"] and readback["primary_suppressed_count"] and not readback["decoded_object_count"]:
        status = "suppressed_without_primary_readback"
    elif readback["done_ok"] and not readback["decoded_object_count"]:
        status = "decode-failed"
    elif ok:
        if readback["trailing_read_count"]:
            status = "passed_with_trailing_events"
        elif readback["suppressed_replay_count"]:
            status = "passed_with_suppressed_replay"
        else:
            status = "passed"

    report = {
        **base,
        **readback,
        "ok": ok,
        "status": status,
        "attach_pid": resolved_attach_pid,
        "resolved_attach_pid": resolved_attach_pid if attach_name_pattern else None,
        "command": command,
        "result": result,
        "events": events,
        "event_count": len(events),
    }
    return _write_report(report_dir, report)


def generate_objc_archive_script(
    *,
    archive_bytes: bytes,
    class_name: str,
    getters: Sequence[str],
    output: str | Path,
) -> dict:
    output_path = Path(output)
    encoded = base64.b64encode(archive_bytes).decode("ascii")
    script = _render_objc_archive_script(encoded, class_name, getters)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(script, encoding="utf-8")
    return {
        "ok": True,
        "output": str(output_path),
        "archive_size": len(archive_bytes),
        "archive_sha256": hashlib.sha256(archive_bytes).hexdigest(),
        "class_name": class_name,
        "getters": list(getters),
    }


def parse_objc_archive_events(text: str) -> list[dict[str, Any]]:
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


def _summarize_readback(events: list[dict[str, Any]]) -> dict[str, Any]:
    done_index = next(
        (index for index, event in enumerate(events) if event.get("kind") == "done"),
        None,
    )
    primary = events if done_index is None else events[:done_index]
    trailing = [] if done_index is None else events[done_index + 1:]
    decoded = [event for event in primary if event.get("kind") == "decode" and event.get("ok")]
    return {
        "done_ok": done_index is not None and bool(events[done_index].get("ok")),
        "decoded_object_count": len(decoded),
        "primary_suppressed_count": sum(1 for event in primary if event.get("kind") == "suppressed"),
        "trailing_event_count": len(trailing),
        "trailing_read_count": sum(1 for event in trailing if event.get("kind") in {"decode", "getter"}),
        "suppressed_replay_count": sum(1 for event in trailing if event.get("kind") == "suppressed"),
    }


def _render_objc_archive_script(encoded: str, class_name: str, getters: Sequence[str]) -> str:
    encoded_json = json.dumps(encoded)
    class_json = json.dumps(class_name)
    getter_json = json.dumps(list(getters), sort_keys=True)
    guard_material = json.dumps(
        {"archive": encoded, "class": class_name, "getters": list(getters)},
        sort_keys=True,
    )
    guard_key = "ghidra_re_objc_archive_" + hashlib.sha256(guard_material.encode("utf-8")).hexdigest()
    return f"""const GHIDRA_ARCHIVE_BASE64 = {encoded_json};
const GHIDRA_ARCHIVE_CLASS = {class_json};
const GHIDRA_GETTERS = {getter_json};
const EVENT_PREFIX = "{EVENT_PREFIX}";
const RUN_GUARD = "{guard_key}";

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

function globalExport(name) {{
  if (Module.findGlobalExportByName) return Module.findGlobalExportByName(name);
  return Module.findExportByName(null, name);
}}

function claimProcessReadback() {{
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
    var klass = ObjC.classes[GHIDRA_ARCHIVE_CLASS];
    if (!klass) {{
      emit("decode", {{ ok: false, status: "missing-class", className: GHIDRA_ARCHIVE_CLASS }});
      emit("done", {{ ok: true }});
      return;
    }}
    if (!claimProcessReadback()) {{
      emit("suppressed", {{ ok: true, status: "already-executed" }});
      emit("done", {{ ok: true, status: "already-executed" }});
      return;
    }}
    var text = ObjC.classes.NSString.stringWithString_(GHIDRA_ARCHIVE_BASE64);
    var data = ObjC.classes.NSData.alloc().initWithBase64EncodedString_options_(text, 0);
    var errorSlot = Memory.alloc(Process.pointerSize);
    errorSlot.writePointer(ptr(0));
    var object = ObjC.classes.NSKeyedUnarchiver
      .unarchivedObjectOfClass_fromData_error_(klass, data, errorSlot);
    var errorPointer = errorSlot.readPointer();
    if (!object || object.isNull()) {{
      var errorDescription = null;
      if (!errorPointer.isNull()) {{
        errorDescription = describe(new ObjC.Object(errorPointer));
      }}
      emit("decode", {{ ok: false, status: "unarchive-failed", className: GHIDRA_ARCHIVE_CLASS, error: errorDescription }});
      emit("done", {{ ok: true }});
      return;
    }}
    emit("decode", {{
      ok: true,
      className: GHIDRA_ARCHIVE_CLASS,
      archiveLength: Number(data.length()),
      object: describe(object)
    }});
    GHIDRA_GETTERS.forEach(function (getter) {{
      emit("getter", callGetter(object, getter));
    }});
    emit("done", {{ ok: true }});
  }} catch (error) {{
    emit("done", {{ ok: false, status: "exception", error: shortError(error) }});
  }}
}});
"""


def _report_dir(output_dir: str | Path | None) -> Path:
    path = Path(output_dir) if output_dir else cfg.logs_dir / "frida" / f"objc-archive-{timestamp()}"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _write_report(report_dir: Path, report: dict) -> dict:
    json_path = report_dir / "frida-objc-archive.json"
    markdown_path = report_dir / "frida-objc-archive.md"
    report["json_report"] = str(json_path)
    report["markdown_report"] = str(markdown_path)
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_path.write_text(_render_markdown(report), encoding="utf-8")
    return report


def _render_markdown(report: dict) -> str:
    lines = [
        f"# Frida ObjC Archive - {'PASS' if report.get('ok') else report.get('status', 'BLOCKED').upper()}",
        "",
        f"- Schema: `{report.get('schema', '')}`",
        f"- Created: `{report.get('created_at', '')}`",
        f"- Status: `{report.get('status', '')}`",
        f"- Target: `{report.get('target', '')}`",
        f"- Attach PID: `{report.get('attach_pid')}`",
        f"- Attach name: `{report.get('attach_name', '')}`",
        f"- Archive: `{report.get('archive_path', '')}`",
        f"- Archive SHA-256: `{report.get('archive_sha256', '')}`",
        f"- Class: `{report.get('class_name', '')}`",
        f"- Getters: `{report.get('getters', [])}`",
        f"- Event count: `{report.get('event_count', len(report.get('events', [])))}`",
        f"- Decoded objects: `{report.get('decoded_object_count', 0)}`",
        f"- Primary suppressions: `{report.get('primary_suppressed_count', 0)}`",
        f"- Trailing events: `{report.get('trailing_event_count', 0)}`",
        f"- Trailing reads: `{report.get('trailing_read_count', 0)}`",
        f"- Suppressed replays: `{report.get('suppressed_replay_count', 0)}`",
    ]
    if report.get("message"):
        lines.extend(["", "## Message", "", f"- {report['message']}"])
    return "\n".join(lines).rstrip() + "\n"
