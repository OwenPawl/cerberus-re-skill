"""Build no-call safe-read dossiers for XPC interface follow-up."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cerberus_re_skill.core.config import cfg
from cerberus_re_skill.core.utils import utc_now
from cerberus_re_skill.modules.xpc_service_selection import best_xpc_service


XPC_SAFE_READ_DOSSIER_SCHEMA = "ghidra-re.xpc-safe-read-dossier.v1"


def build_xpc_safe_read_dossier(
    targets: list[str],
    *,
    xpc_method_inventory_path: str | Path,
    access_policy_path: str | Path | None = None,
    connection_evidence_path: str | Path | None = None,
    completion_shapes_path: str | Path | None = None,
    runtime_evidence: list[str] | None = None,
    interfaces: list[str] | None = None,
    output: str | Path | None = None,
    markdown_output: str | Path | None = None,
    limit: int = 8,
) -> dict[str, Any]:
    """Merge XPC method inventory and live no-call evidence into a safe-read dossier."""
    parsed_targets = [_parse_target(target) for target in targets]
    if not parsed_targets:
        raise RuntimeError("at least one target is required")

    inventory = _load_json(Path(xpc_method_inventory_path), "xpc method inventory")
    access_policy = _load_json(Path(access_policy_path), "access policy") if access_policy_path else {}
    connection_evidence = _load_json(Path(connection_evidence_path), "xpc connection evidence") if connection_evidence_path else {}
    if connection_evidence_path:
        connection_evidence["_artifact_path"] = str(connection_evidence_path)
    completion_shapes = _load_json(Path(completion_shapes_path), "xpc completion shapes") if completion_shapes_path else {}
    if completion_shapes_path:
        completion_shapes["_artifact_path"] = str(completion_shapes_path)
    runtime_items = _load_runtime_evidence(runtime_evidence or [])
    target_set = {f"{project}:{program}" for project, program in parsed_targets}
    service_overrides = _interface_service_overrides(interfaces or [])

    selected = _selected_inventory_items(inventory, target_set, interfaces or [], limit)
    dossiers = [
        _interface_dossier(
            item,
            access_policy=access_policy,
            connection_evidence=connection_evidence,
            completion_shapes=completion_shapes,
            service_overrides=service_overrides,
        )
        for item in selected
    ]
    summary = {
        "interface_count": len(dossiers),
        "safe_read_candidate_count": sum(len(item["safe_read_candidates"]) for item in dossiers),
        "blocked_read_candidate_count": sum(len(item["blocked_read_candidates"]) for item in dossiers),
        "connection_no_call_ok_count": sum(1 for item in dossiers if item.get("connection_evidence", {}).get("run_ok")),
        "runtime_evidence_count": len(runtime_items),
        "allowed_class_backed_interface_count": sum(
            1 for item in dossiers if int(item.get("allowed_class_backed_method_count") or 0) > 0
        ),
        "completion_shape_backed_interface_count": sum(
            1 for item in dossiers if int(item.get("completion_shape_backed_method_count") or 0) > 0
        ),
        "completion_shape_backed_method_count": sum(
            int(item.get("completion_shape_backed_method_count") or 0) for item in dossiers
        ),
    }
    report = {
        "schema": XPC_SAFE_READ_DOSSIER_SCHEMA,
        "ok": True,
        "created_at": utc_now(),
        "inputs": {
            "targets": [{"project": project, "program": program} for project, program in parsed_targets],
            "xpc_method_inventory": str(xpc_method_inventory_path),
            "access_policy": str(access_policy_path) if access_policy_path else None,
            "connection_evidence": str(connection_evidence_path) if connection_evidence_path else None,
            "completion_shapes": str(completion_shapes_path) if completion_shapes_path else None,
            "runtime_evidence": runtime_evidence or [],
            "interfaces": interfaces or [],
        },
        "summary": summary,
        "access_policy_summary": _access_policy_summary(access_policy),
        "runtime_evidence": runtime_items,
        "interfaces": dossiers,
    }

    out_path = Path(output) if output else cfg.exports_dir / "xpc_safe_read_dossier.json"
    md_path = Path(markdown_output) if markdown_output else cfg.exports_dir / "xpc_safe_read_dossier.md"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    md_path.write_text(_render_markdown(report), encoding="utf-8")
    return {
        "ok": True,
        "output": str(out_path),
        "markdown_output": str(md_path),
        **summary,
    }


def _selected_inventory_items(
    inventory: dict[str, Any],
    target_set: set[str],
    interfaces: list[str],
    limit: int,
) -> list[dict[str, Any]]:
    items = [item for item in inventory.get("interfaces", []) if isinstance(item, dict)]
    explicit: list[dict[str, Any]] = []
    if interfaces:
        requested = {_interface_name(spec) for spec in interfaces}
        for item in items:
            if str(item.get("target") or "") not in target_set:
                continue
            if str(item.get("interface") or "") in requested:
                explicit.append(item)
        return explicit[: max(1, limit)]

    ranked = []
    for item in items:
        if str(item.get("target") or "") not in target_set:
            continue
        candidates = item.get("method_candidates", [])
        strict_reads = [
            method
            for method in candidates
            if isinstance(method, dict) and _strict_read_safety(method)["category"] == "safe_read"
        ]
        if strict_reads:
            ranked.append((len(strict_reads), int(item.get("method_count") or 0), item))
    ranked.sort(key=lambda value: (-value[0], -value[1], str(value[2].get("interface") or "")))
    return [item for _, _, item in ranked[: max(1, limit)]]


def _interface_name(spec: str) -> str:
    parts = spec.split("=")
    if len(parts) == 3:
        return parts[1]
    if len(parts) == 2:
        return parts[0]
    return spec


def _interface_service_overrides(specs: list[str]) -> dict[str, str]:
    overrides = {}
    for spec in specs:
        parts = spec.split("=")
        if len(parts) == 3:
            overrides[parts[1]] = parts[2]
        elif len(parts) == 2:
            overrides[parts[0]] = parts[1]
    return {key: value for key, value in overrides.items() if key and value}


def _interface_dossier(
    item: dict[str, Any],
    *,
    access_policy: dict[str, Any],
    connection_evidence: dict[str, Any],
    completion_shapes: dict[str, Any],
    service_overrides: dict[str, str],
) -> dict[str, Any]:
    services = item.get("graph_context", {}).get("services", []) if isinstance(item.get("graph_context"), dict) else []
    interface = str(item.get("interface") or "")
    service = service_overrides.get(interface) or _best_service(interface, services)
    connection = _matching_connection(connection_evidence, str(item.get("target") or ""), interface, service)
    completion_shape_index = _completion_shapes_for_interface(completion_shapes, item)
    safe_reads = []
    blocked_reads = []
    for method in item.get("method_candidates", []) if isinstance(item.get("method_candidates"), list) else []:
        if not isinstance(method, dict):
            continue
        strict = _strict_read_safety(method)
        method_record = _method_record(
            method,
            strict,
            access_policy=access_policy,
            allowed_class_backed=_method_allowed_class_backed(method, item),
            connection=connection,
            completion_shape=completion_shape_index.get(str(method.get("selector") or ""), {}),
        )
        if strict["category"] == "safe_read":
            safe_reads.append(method_record)
        elif _looks_read_candidate(method):
            blocked_reads.append(method_record)

    return {
        "target": item.get("target"),
        "project": item.get("project"),
        "program": item.get("program"),
        "interface": item.get("interface"),
        "service": service,
        "service_candidates": [str(value) for value in services if value],
        "method_count": item.get("method_count", 0),
        "allowed_class_backed_method_count": item.get("allowed_class_backed_method_count", 0),
        "completion_shape_backed_method_count": sum(
            1
            for method in safe_reads + blocked_reads
            if method.get("completion_contract", {}).get("source") == "xpc_completion_shapes"
            and method.get("completion_contract_verified")
        ),
        "configuration_context": item.get("configuration_context", {}),
        "connection_evidence": connection,
        "safe_read_candidates": safe_reads,
        "blocked_read_candidates": blocked_reads[:12],
        "harness_policy": {
            "remote_methods_invoked": False,
            "default": "no_call_only_until_allowed_classes_entitlements_and_input_shapes_are_recovered",
            "required_before_remote_invocation": _required_before_remote_invocation(safe_reads, item, connection),
        },
    }


def _method_record(
    method: dict[str, Any],
    strict: dict[str, Any],
    *,
    access_policy: dict[str, Any],
    allowed_class_backed: bool,
    connection: dict[str, Any],
    completion_shape: dict[str, Any],
) -> dict[str, Any]:
    selector = str(method.get("selector") or "")
    signature = method.get("signature_hint", {}) if isinstance(method.get("signature_hint"), dict) else {}
    hints = method.get("input_shape_hints", []) if isinstance(method.get("input_shape_hints"), list) else []
    argument_roles = [_argument_role(hint) for hint in hints if isinstance(hint, dict)]
    requires_access_specifier = "accessspecifier" in selector.lower() or any(
        role.get("role") == "access_specifier" for role in argument_roles
    )
    completion = (
        _completion_contract_from_completion_shapes(completion_shape)
        or _completion_contract(selector, access_policy)
        or _completion_contract_from_allowed_classes(method)
    )
    completion_verified = _completion_contract_verified(completion)
    has_completion = bool(signature.get("reply_block_likely")) or any(
        role.get("role") in {"completion_block", "reply_block"} for role in argument_roles
    )
    blockers = list(strict["blockers"])
    if strict["category"] == "safe_read":
        if not allowed_class_backed:
            blockers.append("allowed_class_behavior_unrecovered")
        if requires_access_specifier:
            blockers.append("access_specifier_policy_required")
        if has_completion and not completion_verified:
            blockers.append("completion_shape_unverified")
        if not connection.get("run_ok"):
            blockers.append("no_call_connection_unverified")
        if connection and connection.get("remote_protocol_registered") is False:
            blockers.append("remote_protocol_not_registered_in_harness_process")

    return {
        "selector": selector,
        "score": method.get("score"),
        "argument_count": signature.get("argument_count"),
        "argument_roles": argument_roles,
        "completion_contract": completion,
        "completion_contract_verified": completion_verified,
        "allowed_class_evidence": _allowed_class_evidence_summary(method),
        "requires_access_specifier": requires_access_specifier,
        "strict_safety": strict,
        "blockers": _unique(blockers),
        "remote_invocation_default": "blocked_no_call_only" if blockers else "candidate_requires_final_runtime_gate",
        "source_safety": method.get("safety_classification", {}),
    }


def _method_allowed_class_backed(method: dict[str, Any], item: dict[str, Any]) -> bool:
    backing = method.get("configuration_backing", {}) if isinstance(method.get("configuration_backing"), dict) else {}
    if backing.get("allowed_class_evidence_count") is not None:
        return bool(backing.get("allowed_class_evidence_count"))
    return bool(int(item.get("allowed_class_backed_method_count") or 0))


def _allowed_class_evidence_summary(method: dict[str, Any]) -> dict[str, Any]:
    backing = method.get("configuration_backing", {}) if isinstance(method.get("configuration_backing"), dict) else {}
    return {
        "evidence_count": backing.get("allowed_class_evidence_count", 0),
        "argument_allowed_classes": backing.get("argument_allowed_classes", []),
        "reply_allowed_classes": backing.get("reply_allowed_classes", []),
    }


def _completion_contract_from_allowed_classes(method: dict[str, Any]) -> dict[str, Any]:
    backing = method.get("configuration_backing", {}) if isinstance(method.get("configuration_backing"), dict) else {}
    reply = backing.get("reply_allowed_classes", []) if isinstance(backing.get("reply_allowed_classes"), list) else []
    reply = [item for item in reply if isinstance(item, dict) and item.get("classes")]
    if not reply:
        return {}
    parts = []
    for item in reply:
        index = item.get("argument_index")
        classes = ", ".join(str(value) for value in item.get("classes", []) if value)
        parts.append(f"reply[{index}] {classes}")
    return {
        "source": "nsxpc_allowed_classes",
        "completion": "; ".join(parts),
        "reply_allowed_classes": reply,
    }


def _completion_shapes_for_interface(completion_shapes: dict[str, Any], item: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if not completion_shapes:
        return {}
    target = str(item.get("target") or "")
    interface = str(item.get("interface") or "")
    result: dict[str, dict[str, Any]] = {}
    for entry in completion_shapes.get("interfaces", []) if isinstance(completion_shapes, dict) else []:
        if not isinstance(entry, dict):
            continue
        if str(entry.get("interface") or "") != interface:
            continue
        entry_target = str(entry.get("target") or "")
        if entry_target and target and entry_target != target:
            continue
        for method in entry.get("methods", []) if isinstance(entry.get("methods"), list) else []:
            if not isinstance(method, dict) or not method.get("selector"):
                continue
            copied = dict(method)
            copied["_artifact_path"] = completion_shapes.get("_artifact_path") or ""
            result[str(method["selector"])] = copied
    return result


def _completion_contract_from_completion_shapes(method_shape: dict[str, Any]) -> dict[str, Any]:
    shape = method_shape.get("completion_shape", {}) if isinstance(method_shape.get("completion_shape"), dict) else {}
    if not shape:
        return {}
    reply_arguments = shape.get("reply_arguments", []) if isinstance(shape.get("reply_arguments"), list) else []
    residual_gaps = shape.get("residual_gaps", []) if isinstance(shape.get("residual_gaps"), list) else []
    return {
        "source": "xpc_completion_shapes",
        "artifact": method_shape.get("_artifact_path") or "",
        "completion": shape.get("completion") or "",
        "confidence": shape.get("confidence"),
        "shape_source": shape.get("source"),
        "protocol_types": method_shape.get("protocol_types"),
        "reply_arguments": reply_arguments,
        "residual_gaps": residual_gaps,
        "static_block_descriptor_count": len(
            method_shape.get("static_block_evidence", {}).get("block_descriptors", [])
        )
        if isinstance(method_shape.get("static_block_evidence"), dict)
        else 0,
    }


def _completion_contract_verified(completion: dict[str, Any]) -> bool:
    if not completion:
        return False
    if completion.get("source") == "xpc_completion_shapes":
        return bool(completion.get("reply_arguments")) and not completion.get("residual_gaps")
    return bool(completion.get("completion"))


def _argument_role(hint: dict[str, Any]) -> dict[str, Any]:
    label = str(hint.get("label") or "")
    role = str(hint.get("role") or "unknown")
    types = [str(value) for value in hint.get("type_hints", []) if value]
    lowered = label.lower()
    if role in {"completion_block", "reply_block"}:
        return {"position": hint.get("position"), "label": label, "role": role, "type_hints": types or ["block"]}
    if "accessspecifier" in lowered or "accesstoken" in lowered or "authorization" in lowered:
        role = "access_context"
        types = types or ["NSObject", "NSString"]
    elif "phrase" in lowered:
        role = "phrase"
        types = types or ["NSString"]
    elif "limit" in lowered or "numberof" in lowered or "count" in lowered:
        role = "count"
        types = types or ["NSUInteger", "NSInteger"]
    return {"position": hint.get("position"), "label": label, "role": role, "type_hints": types}


def _strict_read_safety(method: dict[str, Any]) -> dict[str, Any]:
    selector = str(method.get("selector") or "")
    lowered = selector.lower()
    source = method.get("safety_classification", {}) if isinstance(method.get("safety_classification"), dict) else {}
    reasons = []
    blockers = []
    if source.get("category") != "safe_read":
        blockers.append(f"source_safety_{source.get('category') or 'unknown'}")
    state_words = [
        "add",
        "update",
        "delete",
        "remove",
        "set",
        "create",
        "save",
        "write",
        "run",
        "open",
        "enable",
        "disable",
        "register",
        "invalidate",
        "sync",
        "migration",
        "migrate",
        "reindex",
    ]
    for word in state_words:
        if _word_boundary(lowered, word):
            blockers.append(f"state_keyword_{word}")
    if lowered.startswith("request"):
        blockers.append("request_prefix_not_strict_read")
    read_prefixes = ("get", "fetch", "list", "enumerate", "is", "can", "has", "current")
    if not lowered.startswith(read_prefixes):
        blockers.append("missing_strict_read_prefix")
    if blockers:
        category = "blocked"
        reasons.append("not_strictly_replay_safe_read")
    else:
        category = "safe_read"
        reasons.append("strict_read_prefix_without_state_keywords")
    if source.get("reasons"):
        reasons.extend(str(reason) for reason in source.get("reasons", []) if reason)
    return {"category": category, "reasons": _unique(reasons), "blockers": _unique(blockers)}


def _looks_read_candidate(method: dict[str, Any]) -> bool:
    selector = str(method.get("selector") or "").lower()
    source = method.get("safety_classification", {}) if isinstance(method.get("safety_classification"), dict) else {}
    return source.get("category") == "safe_read" or any(
        word in selector for word in ("get", "fetch", "list", "is", "can", "has", "current", "request")
    )


def _word_boundary(value: str, word: str) -> bool:
    return (
        value.startswith(word)
        or f":{word}" in value
        or f"_{word}" in value
        or f"{word}:" in value
        or f"{word}with" in value
    )


def _completion_contract(selector: str, access_policy: dict[str, Any]) -> dict[str, Any]:
    requirements = access_policy.get("safe_read_requirements") if isinstance(access_policy, dict) else {}
    shapes = requirements.get("completion_shapes", []) if isinstance(requirements, dict) else []
    for item in shapes if isinstance(shapes, list) else []:
        if not isinstance(item, dict):
            continue
        contract_selector = str(item.get("selector") or "")
        if contract_selector and (selector == contract_selector or contract_selector in selector):
            return dict(item)
    return {}


def _access_policy_summary(access_policy: dict[str, Any]) -> dict[str, Any]:
    if not access_policy:
        return {}
    requirements = access_policy.get("safe_read_requirements", {})
    return {
        "list_selector": requirements.get("list_selector") if isinstance(requirements, dict) else None,
        "count_selector": requirements.get("count_selector") if isinstance(requirements, dict) else None,
        "access_policy": requirements.get("access_policy") if isinstance(requirements, dict) else None,
        "direct_xpc_status": requirements.get("direct_xpc_status") if isinstance(requirements, dict) else None,
        "factory_shape_count": len(access_policy.get("factory_shapes", [])) if isinstance(access_policy.get("factory_shapes"), list) else 0,
        "entitlement_predicate_count": len(access_policy.get("entitlement_predicates", []))
        if isinstance(access_policy.get("entitlement_predicates"), list)
        else 0,
    }


def _matching_connection(connection_evidence: dict[str, Any], target: str, interface: str, service: str) -> dict[str, Any]:
    for item in connection_evidence.get("connections", []) if isinstance(connection_evidence, dict) else []:
        if not isinstance(item, dict):
            continue
        if item.get("target") != target or item.get("interface") != interface:
            continue
        if service and item.get("service") != service:
            continue
        run = item.get("run", {}) if isinstance(item.get("run"), dict) else {}
        compile_result = item.get("compile", {}) if isinstance(item.get("compile"), dict) else {}
        logs = _connection_log_text(run)
        remote_protocol_registered = None
        if "Configured remoteObjectInterface with protocol" in logs:
            remote_protocol_registered = True
        elif "No ObjC protocol named" in logs:
            remote_protocol_registered = False
        elif run.get("remote_protocol_registered") is not None:
            remote_protocol_registered = bool(run.get("remote_protocol_registered"))
        return {
            "artifact": connection_evidence.get("_artifact_path") or "",
            "service": item.get("service"),
            "harness_source": item.get("harness_source"),
            "framework_loads": item.get("framework_loads", []),
            "compile_ok": bool(compile_result.get("ok")),
            "run_ok": bool(run.get("ok")),
            "run_status": run.get("status"),
            "blocker_classification": run.get("blocker_classification"),
            "observations": run.get("observations", []),
            "remote_protocol_registered": remote_protocol_registered,
            "proxy_placeholder_acquired": "Remote proxy placeholder acquired without description" in logs,
        }
    return {}


def _connection_log_text(run: dict[str, Any]) -> str:
    chunks = []
    for key in ("stdout", "stderr"):
        path_text = run.get(key)
        if not path_text:
            continue
        path = Path(str(path_text))
        if not path.exists():
            continue
        try:
            chunks.append(path.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
    return "\n".join(chunks)


def _required_before_remote_invocation(
    safe_reads: list[dict[str, Any]],
    item: dict[str, Any],
    connection: dict[str, Any],
) -> list[str]:
    requirements = []
    if int(item.get("allowed_class_backed_method_count") or 0) == 0:
        requirements.append("recover NSXPCInterface allowed classes for arguments and replies")
    if not connection.get("run_ok"):
        requirements.append("compile and run a no-call connection harness for the exact service/interface")
    if connection and connection.get("remote_protocol_registered") is False:
        requirements.append("declare or load the remote ObjC protocol before assigning remoteObjectInterface")
    if any(method.get("requires_access_specifier") for method in safe_reads):
        requirements.append("construct the least-privilege access-context shape and verify entitlement behavior")
    if any("completion_shape_unverified" in method.get("blockers", []) for method in safe_reads):
        requirements.append("recover completion block argument classes/shapes before remote invocation")
    return _unique(requirements)


def _load_runtime_evidence(specs: list[str]) -> list[dict[str, Any]]:
    items = []
    for spec in specs:
        label, path_text = _split_mapping(spec, "runtime evidence")
        path = Path(path_text)
        payload = _load_json(path, "runtime evidence")
        items.append(_runtime_summary(label, path, payload))
    return items


def _runtime_summary(label: str, path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    schema = str(payload.get("schema") or "")
    if schema == "ghidra-re.lldb-trace-validation.v1":
        trace = payload.get("trace", {}) if isinstance(payload.get("trace"), dict) else {}
        return {
            "label": label,
            "path": str(path),
            "kind": "lldb-trace-validation",
            "ok": bool(payload.get("ok")),
            "status": payload.get("trace_status"),
            "hit_count": payload.get("hit_count"),
            "runtime_hit_count": payload.get("runtime_hit_count"),
            "symbols": trace.get("symbols_requested", []),
        }
    if schema == "ghidra-re.frida-runtime-recheck.v1":
        summary = payload.get("frida_event_summary", {}) if isinstance(payload.get("frida_event_summary"), dict) else {}
        return {
            "label": label,
            "path": str(path),
            "kind": "frida-runtime-recheck",
            "ok": bool(payload.get("ok")),
            "status": payload.get("status"),
            "hit_count": payload.get("runtime_hit_count"),
            "runtime_hit_count": payload.get("runtime_hit_count"),
            "symbols": summary.get("installed_symbols", []),
            "readiness_observed": payload.get("readiness_observed"),
        }
    if "allowed-classes-probe" in schema:
        summary = payload.get("summary", {}) if isinstance(payload.get("summary"), dict) else {}
        return {
            "label": label,
            "path": str(path),
            "kind": "nsxpc-allowed-classes-probe",
            "schema": schema,
            "ok": bool(payload.get("ok")),
            "status": "allowed_classes_recovered" if payload.get("ok") else payload.get("error"),
            "hit_count": summary.get("non_empty_allowed_class_entry_count"),
            "runtime_hit_count": summary.get("allowed_class_entry_count"),
            "interface_source": payload.get("interface_source"),
            "connection_created": payload.get("connection_created"),
            "remote_methods_invoked": payload.get("remote_methods_invoked"),
        }
    if schema == "ghidra-re.xpc-completion-shapes.v1":
        summary = payload.get("summary", {}) if isinstance(payload.get("summary"), dict) else {}
        return {
            "label": label,
            "path": str(path),
            "kind": "xpc-completion-shapes",
            "schema": schema,
            "ok": bool(payload.get("ok")),
            "status": "completion_shapes_recovered" if summary.get("reply_shape_count") else "completion_shapes_unrecovered",
            "hit_count": summary.get("completion_method_count"),
            "runtime_hit_count": summary.get("reply_shape_count"),
            "primitive_reply_count": summary.get("primitive_reply_count"),
            "static_block_descriptor_count": summary.get("static_block_descriptor_count"),
        }
    return {
        "label": label,
        "path": str(path),
        "kind": "unknown",
        "schema": schema,
        "ok": bool(payload.get("ok")),
        "status": payload.get("status") or payload.get("trace_status"),
    }


def _split_mapping(spec: str, label: str) -> tuple[str, str]:
    if "=" not in spec:
        raise RuntimeError(f"{label} must be formatted as id=path: {spec}")
    left, right = spec.split("=", 1)
    left = left.strip()
    right = right.strip()
    if not left or not right:
        raise RuntimeError(f"{label} must include id and path: {spec}")
    return left, right


def _best_service(interface: str, services: Any) -> str:
    return best_xpc_service(interface, services)


def _parse_target(target: str) -> tuple[str, str]:
    if ":" not in target:
        raise RuntimeError(f"target must be formatted as project:program: {target}")
    project, program = target.split(":", 1)
    if not project or not program:
        raise RuntimeError(f"target must include both project and program: {target}")
    return project, program


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


def _unique(values: list[str]) -> list[str]:
    result = []
    for value in values:
        if value and value not in result:
            result.append(value)
    return result


def _render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# XPC Safe-Read Dossier",
        "",
        f"- Schema: `{report['schema']}`",
        f"- Interfaces: {summary['interface_count']}",
        f"- Strict safe-read candidates: {summary['safe_read_candidate_count']}",
        f"- Blocked read-like candidates: {summary['blocked_read_candidate_count']}",
        f"- No-call connection OK: {summary['connection_no_call_ok_count']}",
        f"- Runtime evidence artifacts: {summary['runtime_evidence_count']}",
        f"- Completion-shape-backed methods: {summary.get('completion_shape_backed_method_count', 0)}",
        "",
    ]
    policy = report.get("access_policy_summary", {})
    if policy:
        lines.extend(
            [
                "## Access Policy",
                "",
                f"- Policy: {policy.get('access_policy') or 'unavailable'}",
                f"- Direct XPC status: `{policy.get('direct_xpc_status') or 'unavailable'}`",
                f"- List selector: `{policy.get('list_selector') or 'unavailable'}`",
                f"- Count selector: `{policy.get('count_selector') or 'unavailable'}`",
                "",
            ]
        )
    if report.get("runtime_evidence"):
        lines.extend(["## Runtime Evidence", ""])
        for item in report["runtime_evidence"]:
            lines.append(
                f"- `{item['label']}` {item['kind']} status=`{item.get('status')}` "
                f"hits={item.get('hit_count')} path=`{item['path']}`"
            )
        lines.append("")
    for item in report["interfaces"]:
        lines.append(f"## {item['interface']}")
        lines.append("")
        lines.append(f"- Target: `{item['target']}`")
        lines.append(f"- Service: `{item.get('service') or 'unavailable'}`")
        lines.append(f"- Allowed-class-backed methods: {item.get('allowed_class_backed_method_count', 0)}")
        connection = item.get("connection_evidence", {})
        if connection:
            lines.append(
                f"- No-call connection: `{connection.get('run_status')}` "
                f"blocker=`{connection.get('blocker_classification')}`"
            )
            if connection.get("remote_protocol_registered") is False:
                lines.append("- Harness note: remote ObjC protocol was not registered in the harness process.")
        requirements = item.get("harness_policy", {}).get("required_before_remote_invocation", [])
        for requirement in requirements:
            lines.append(f"- Required before remote invocation: {requirement}")
        if item.get("safe_read_candidates"):
            lines.append("")
            lines.append("### Strict Safe-Read Candidates")
            for method in item["safe_read_candidates"][:12]:
                blockers = ", ".join(f"`{blocker}`" for blocker in method.get("blockers", [])) or "`none`"
                completion = method.get("completion_contract", {}).get("completion") or "unverified"
                lines.append(f"- `{method['selector']}` completion={completion}; blockers: {blockers}")
        if item.get("blocked_read_candidates"):
            lines.append("")
            lines.append("### Blocked Read-Like Candidates")
            for method in item["blocked_read_candidates"][:8]:
                blockers = ", ".join(f"`{blocker}`" for blocker in method.get("blockers", [])) or "`none`"
                lines.append(f"- `{method['selector']}` blockers: {blockers}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
