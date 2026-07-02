"""Build guarded no-call XPC connection evidence artifacts."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from cerberus_re_skill.core.config import cfg
from cerberus_re_skill.core.utils import utc_now
from cerberus_re_skill.modules.xpc_service_selection import best_xpc_service


XPC_CONNECTION_EVIDENCE_SCHEMA = "ghidra-re.xpc-connection-evidence.v1"


def build_xpc_connection_evidence(
    targets: list[str],
    *,
    xpc_dossier_path: str | Path | None = None,
    xpc_method_inventory_path: str | Path | None = None,
    interfaces: list[str] | None = None,
    framework_loads: list[str] | None = None,
    output: str | Path | None = None,
    markdown_output: str | Path | None = None,
    harness_output_dir: str | Path | None = None,
    compile_harnesses: bool = False,
    run_harnesses: bool = False,
    timeout_seconds: float = 5.0,
    limit: int = 6,
) -> dict[str, Any]:
    """Create no-call connection harnesses and optional compile/run evidence."""
    parsed_targets = [_parse_target(target) for target in targets]
    if not parsed_targets:
        raise RuntimeError("at least one target is required")
    normalized_framework_loads = [_normalize_framework_load(value) for value in framework_loads or [] if str(value).strip()]
    inventory = _load_json(Path(xpc_method_inventory_path), "xpc method inventory") if xpc_method_inventory_path else {}
    dossier = _load_json(Path(xpc_dossier_path), "xpc interface dossier") if xpc_dossier_path else {}
    selected = _selected_connection_targets(parsed_targets, inventory, dossier, interfaces or [], limit)

    out_dir = Path(harness_output_dir) if harness_output_dir else cfg.exports_dir / "xpc_connection_harnesses"
    out_dir.mkdir(parents=True, exist_ok=True)
    connections = []
    for index, item in enumerate(selected, start=1):
        item = {**item, "framework_loads": normalized_framework_loads}
        harness_path = out_dir / f"{index:02d}_{_safe_name(item['service'])}_{_safe_name(item['interface'])}_ConnectionEvidence.m"
        binary_path = harness_path.with_suffix("")
        source = _render_connection_harness(item)
        harness_path.write_text(source, encoding="utf-8")
        record: dict[str, Any] = {
            **item,
            "rank": index,
            "framework_loads": normalized_framework_loads,
            "harness_source": str(harness_path),
            "harness_binary": str(binary_path),
            "safety": {
                "remote_methods_invoked": False,
                "remote_proxy_logged": False,
                "private_frameworks_loaded": bool(normalized_framework_loads),
                "connection_resumed": True,
                "connection_invalidated": True,
            },
            "compile": {"attempted": False},
            "run": {"attempted": False},
        }
        if compile_harnesses or run_harnesses:
            record["compile"] = _compile_harness(harness_path, binary_path)
        if run_harnesses:
            if not record["compile"].get("ok"):
                record["run"] = {"attempted": False, "status": "compile_failed"}
            else:
                record["run"] = _run_harness(binary_path, out_dir, index, timeout_seconds)
        connections.append(record)

    summary = {
        "connection_count": len(connections),
        "harness_source_count": len(connections),
        "compile_attempt_count": sum(1 for item in connections if item["compile"].get("attempted")),
        "compile_ok_count": sum(1 for item in connections if item["compile"].get("ok")),
        "run_attempt_count": sum(1 for item in connections if item["run"].get("attempted")),
        "run_ok_count": sum(1 for item in connections if item["run"].get("ok")),
        "blocked_count": sum(1 for item in connections if item["run"].get("blocker_classification") not in (None, "none_observed")),
        "framework_load_count": len(normalized_framework_loads),
        "remote_protocol_registered_count": sum(
            1 for item in connections if item.get("run", {}).get("remote_protocol_registered") is True
        ),
    }
    report = {
        "schema": XPC_CONNECTION_EVIDENCE_SCHEMA,
        "ok": True,
        "created_at": utc_now(),
        "inputs": {
            "targets": [{"project": project, "program": program} for project, program in parsed_targets],
            "xpc_dossier": str(xpc_dossier_path) if xpc_dossier_path else None,
            "xpc_method_inventory": str(xpc_method_inventory_path) if xpc_method_inventory_path else None,
            "interfaces": interfaces or [],
            "framework_loads": normalized_framework_loads,
            "compile_harnesses": compile_harnesses,
            "run_harnesses": run_harnesses,
            "timeout_seconds": timeout_seconds,
        },
        "summary": summary,
        "connections": connections,
    }
    out_path = Path(output) if output else cfg.exports_dir / "xpc_connection_evidence.json"
    md_path = Path(markdown_output) if markdown_output else cfg.exports_dir / "xpc_connection_evidence.md"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    md_path.write_text(_render_markdown(report), encoding="utf-8")
    return {
        "ok": True,
        "output": str(out_path),
        "markdown_output": str(md_path),
        **summary,
    }


def _selected_connection_targets(
    targets: list[tuple[str, str]],
    inventory: dict[str, Any],
    dossier: dict[str, Any],
    interfaces: list[str],
    limit: int,
) -> list[dict[str, Any]]:
    target_set = {f"{project}:{program}" for project, program in targets}
    selected: list[dict[str, Any]] = []
    for interface_spec in interfaces:
        project, program, interface, service = _parse_interface_spec(interface_spec, targets)
        selected.append(
            {
                "target": f"{project}:{program}",
                "project": project,
                "program": program,
                "interface": interface,
                "service": service,
                "source": "explicit",
            }
        )
    if inventory:
        for item in inventory.get("interfaces", []):
            if not isinstance(item, dict):
                continue
            target = str(item.get("target") or "")
            if target not in target_set:
                continue
            project, program = target.split(":", 1)
            interface = str(item.get("interface") or "")
            services = item.get("graph_context", {}).get("services", []) if isinstance(item.get("graph_context"), dict) else []
            service = _best_service(interface, services)
            if interface and service:
                selected.append(
                    {
                        "target": target,
                        "project": project,
                        "program": program,
                        "interface": interface,
                        "service": service,
                        "method_count": item.get("method_count", 0),
                        "source": "xpc-method-inventory",
                    }
                )
            if len(selected) >= limit:
                break
    if dossier and len(selected) < limit:
        for candidate in dossier.get("candidates", []):
            if not isinstance(candidate, dict):
                continue
            target = str(candidate.get("target") or "")
            if target not in target_set:
                continue
            project, program = target.split(":", 1)
            interface = str(candidate.get("interface") or "")
            service = _best_service(interface, candidate.get("services", []))
            if interface and service:
                selected.append(
                    {
                        "target": target,
                        "project": project,
                        "program": program,
                        "interface": interface,
                        "service": service,
                        "score": candidate.get("score"),
                        "source": "xpc-interface-dossier",
                    }
                )
            if len(selected) >= limit:
                break
    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for item in selected:
        key = (item["target"], item["interface"], item["service"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped[: max(1, limit)]


def _normalize_framework_load(value: str) -> str:
    """Preserve Apple image paths as portable POSIX identifiers on all hosts."""
    return str(value).strip().replace("\\", "/")


def _parse_interface_spec(spec: str, targets: list[tuple[str, str]]) -> tuple[str, str, str, str]:
    parts = spec.split("=")
    if len(parts) == 3:
        target, interface, service = parts
        if ":" not in target:
            raise RuntimeError(f"explicit connection target must be project:program=Interface=service: {spec}")
        project, program = target.split(":", 1)
        return project, program, interface, service
    if len(parts) == 2:
        interface, service = parts
        project, program = targets[0]
        return project, program, interface, service
    raise RuntimeError(f"explicit connection must be Interface=service or project:program=Interface=service: {spec}")


def _best_service(interface: str, services: Any) -> str:
    return best_xpc_service(interface, services)


def _compile_harness(source: Path, binary: Path) -> dict[str, Any]:
    command = ["/usr/bin/clang", "-fobjc-arc", "-framework", "Foundation", str(source), "-o", str(binary)]
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    return {
        "attempted": True,
        "ok": result.returncode == 0,
        "exit_code": result.returncode,
        "command": command,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
    }


def _run_harness(binary: Path, out_dir: Path, index: int, timeout_seconds: float) -> dict[str, Any]:
    stdout_path = out_dir / f"{index:02d}_{binary.name}.stdout.log"
    stderr_path = out_dir / f"{index:02d}_{binary.name}.stderr.log"
    try:
        result = subprocess.run([str(binary)], text=True, capture_output=True, check=False, timeout=timeout_seconds)
        stdout_path.write_text(result.stdout, encoding="utf-8")
        stderr_path.write_text(result.stderr, encoding="utf-8")
        classification = _classify_run(result.returncode, result.stdout, result.stderr)
        return {
            "attempted": True,
            "ok": result.returncode == 0,
            "exit_code": result.returncode,
            "status": classification["status"],
            "blocker_classification": classification["blocker_classification"],
            "observations": classification["observations"],
            "framework_load_attempt_count": classification["framework_load_attempt_count"],
            "framework_load_ok_count": classification["framework_load_ok_count"],
            "remote_protocol_registered": classification["remote_protocol_registered"],
            "stdout": str(stdout_path),
            "stderr": str(stderr_path),
        }
    except subprocess.TimeoutExpired as exc:
        stdout_path.write_text(exc.stdout or "", encoding="utf-8")
        stderr_path.write_text(exc.stderr or "", encoding="utf-8")
        return {
            "attempted": True,
            "ok": False,
            "exit_code": None,
            "status": "timeout",
            "blocker_classification": "timeout",
            "observations": [f"timed out after {timeout_seconds:g}s"],
            "stdout": str(stdout_path),
            "stderr": str(stderr_path),
        }


def _classify_run(exit_code: int, stdout: str, stderr: str) -> dict[str, Any]:
    text = f"{stdout}\n{stderr}"
    observations: list[str] = []
    framework_load_attempt_count = text.count("Loaded framework ") + text.count("Failed to load framework ")
    framework_load_ok_count = text.count("Loaded framework ")
    if "Created XPC connection" in text:
        observations.append("connection object created and resumed")
    if "Loaded framework " in text:
        observations.append("requested framework/image load succeeded")
    if "Failed to load framework " in text:
        observations.append("requested framework/image load failed")
    if "Protocol before framework loads: missing" in text and "Protocol after framework loads: registered" in text:
        observations.append("framework load registered previously missing ObjC protocol")
    if "Configured remoteObjectInterface with protocol" in text:
        observations.append("remote protocol registered and assigned to connection")
    if "No ObjC protocol named" in text:
        observations.append("remote protocol not registered in harness process")
    if "Remote proxy placeholder acquired without description" in text:
        observations.append("remote proxy placeholder acquired without logging proxy object")
    if "No-call connection evidence complete" in text:
        observations.append("harness invalidated connection without invoking remote methods")
    lowered = text.lower()
    remote_protocol_registered = True if "Configured remoteObjectInterface with protocol" in text else None
    if "No ObjC protocol named" in text:
        remote_protocol_registered = False
    if "nsinvalidargumentexception" in lowered or "uncaught exception" in lowered:
        return {
            "status": "harness_crashed",
            "blocker_classification": "harness_exception",
            "observations": observations,
            "framework_load_attempt_count": framework_load_attempt_count,
            "framework_load_ok_count": framework_load_ok_count,
            "remote_protocol_registered": remote_protocol_registered,
        }
    if "xpc connection interrupted" in lowered or "xpc connection invalidated" in lowered:
        observations.append("connection handler fired during no-call window")
    if "No ObjC protocol named" in text:
        return {
            "status": "blocked",
            "blocker_classification": "remote_protocol_not_registered",
            "observations": observations,
            "framework_load_attempt_count": framework_load_attempt_count,
            "framework_load_ok_count": framework_load_ok_count,
            "remote_protocol_registered": remote_protocol_registered,
        }
    if "bootstrap" in lowered or "couldn" in lowered and "communicate" in lowered:
        return {
            "status": "blocked",
            "blocker_classification": "bootstrap_lookup_or_service_unavailable",
            "observations": observations,
            "framework_load_attempt_count": framework_load_attempt_count,
            "framework_load_ok_count": framework_load_ok_count,
            "remote_protocol_registered": remote_protocol_registered,
        }
    if "entitlement" in lowered or "not entitled" in lowered or "denied" in lowered:
        return {
            "status": "blocked",
            "blocker_classification": "entitlement_or_policy_denied",
            "observations": observations,
            "framework_load_attempt_count": framework_load_attempt_count,
            "framework_load_ok_count": framework_load_ok_count,
            "remote_protocol_registered": remote_protocol_registered,
        }
    status = "connection_object_created_no_call" if exit_code == 0 else "nonzero_exit"
    blocker = "none_observed" if exit_code == 0 else "unknown_nonzero_exit"
    return {
        "status": status,
        "blocker_classification": blocker,
        "observations": observations,
        "framework_load_attempt_count": framework_load_attempt_count,
        "framework_load_ok_count": framework_load_ok_count,
        "remote_protocol_registered": remote_protocol_registered,
    }


def _render_connection_harness(item: dict[str, Any]) -> str:
    framework_loads = _objc_array_literal(item.get("framework_loads", []))
    return f"""// Generated by ghidra-re guarded XPC connection evidence.
// Target: {item['target']}
// Interface: {item['interface']}
// Service: {item['service']}
//
// Safety default: this harness creates/resumes/invalidates an NSXPCConnection
// and acquires a proxy placeholder, but never invokes a remote method.

#import <Foundation/Foundation.h>
#import <dlfcn.h>

int main(int argc, const char * argv[]) {{
    @autoreleasepool {{
        @try {{
            NSString *serviceName = @"{_objc_escape(item['service'])}";
            NSString *interfaceName = @"{_objc_escape(item['interface'])}";
            NSArray<NSString *> *frameworkLoads = {framework_loads};
            NSLog(@"Starting no-call XPC connection evidence for %@ / %@", serviceName, interfaceName);
            Protocol *protocolBeforeLoads = NSProtocolFromString(interfaceName);
            NSLog(@"Protocol before framework loads: %@", protocolBeforeLoads ? @"registered" : @"missing");
            for (NSString *frameworkPath in frameworkLoads) {{
                void *handle = dlopen(frameworkPath.UTF8String, RTLD_NOW | RTLD_LOCAL);
                if (handle) {{
                    NSLog(@"Loaded framework %@", frameworkPath);
                }} else {{
                    NSLog(@"Failed to load framework %@: %s", frameworkPath, dlerror());
                }}
            }}

            NSXPCConnection *connection = [[NSXPCConnection alloc] initWithMachServiceName:serviceName options:0];
            Protocol *remoteProtocol = NSProtocolFromString(interfaceName);
            NSLog(@"Protocol after framework loads: %@", remoteProtocol ? @"registered" : @"missing");
            if (remoteProtocol) {{
                connection.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:remoteProtocol];
                NSLog(@"Configured remoteObjectInterface with protocol %@", interfaceName);
            }} else {{
                NSLog(@"No ObjC protocol named %@ was registered; leaving remoteObjectInterface unset", interfaceName);
            }}
            connection.interruptionHandler = ^{{
                NSLog(@"XPC connection interrupted");
            }};
            connection.invalidationHandler = ^{{
                NSLog(@"XPC connection invalidated");
            }};

            [connection resume];
            NSLog(@"Created XPC connection to %@", serviceName);

            id proxy = [connection remoteObjectProxyWithErrorHandler:^(NSError *error) {{
                NSLog(@"Remote proxy error: %@", error);
            }}];
            if (proxy) {{
                NSLog(@"Remote proxy placeholder acquired without description");
            }}

            [connection invalidate];
            NSLog(@"No-call connection evidence complete");
            return 0;
        }} @catch (NSException *exception) {{
            NSLog(@"Harness exception: %@ %@", exception.name, exception.reason);
            return 70;
        }}
    }}
}}
"""


def _parse_target(target: str) -> tuple[str, str]:
    if ":" not in target:
        raise RuntimeError(f"target must be formatted as project:program: {target}")
    project, program = target.split(":", 1)
    if not project or not program:
        raise RuntimeError(f"target must include both project and program: {target}")
    return project, program


def _safe_name(value: str) -> str:
    return "".join(ch if ch.isalnum() else "_" for ch in value).strip("_") or "xpc_connection"


def _objc_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _objc_array_literal(values: Any) -> str:
    strings = [str(value) for value in values if str(value)]
    if not strings:
        return "@[]"
    return "@[" + ", ".join(f'@"{_objc_escape(value)}"' for value in strings) + "]"


def _load_json(path: Path, label: str) -> dict[str, Any]:
    if not path.exists():
        raise RuntimeError(f"{label} not found: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{label} is not valid JSON: {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"{label} must be a JSON object: {path}")
    return payload


def _render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# XPC Connection Evidence",
        "",
        f"- Schema: `{report['schema']}`",
        f"- Connections: {report['summary']['connection_count']}",
        f"- Harness sources: {report['summary']['harness_source_count']}",
        f"- Compile ok: {report['summary']['compile_ok_count']}/{report['summary']['compile_attempt_count']}",
        f"- Run ok: {report['summary']['run_ok_count']}/{report['summary']['run_attempt_count']}",
        f"- Blocked: {report['summary']['blocked_count']}",
        "",
    ]
    for item in report["connections"]:
        run = item.get("run", {})
        lines.append(f"## {item['interface']}")
        lines.append("")
        lines.append(f"- Target: `{item['target']}`")
        lines.append(f"- Service: `{item['service']}`")
        lines.append(f"- Source: `{item['source']}`")
        lines.append(f"- Harness: `{item['harness_source']}`")
        for framework in item.get("framework_loads", []):
            lines.append(f"- Framework load: `{framework}`")
        if item.get("compile", {}).get("attempted"):
            lines.append(f"- Compile: `{item['compile'].get('ok')}` exit={item['compile'].get('exit_code')}")
        if run.get("attempted"):
            lines.append(f"- Run: `{run.get('status')}` blocker=`{run.get('blocker_classification')}` exit={run.get('exit_code')}")
            if run.get("remote_protocol_registered") is not None:
                lines.append(f"- Remote protocol registered: `{run.get('remote_protocol_registered')}`")
            for observation in run.get("observations", []):
                lines.append(f"- Observation: {observation}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
