"""Recover XPC surface hints from existing export bundles."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from cerberus_re_skill.core.config import cfg


XPC_TERMS = (
    "xpc",
    "listener",
    "listenerendpoint",
    "interfacewithprotocol",
    "machservicename",
    "servicename",
    "remoteobjectproxy",
    "exportedinterface",
    "exportedobject",
)

APPLE_EXTENSION_POINT_SERVICE_IDENTIFIERS = {
    "com.apple.authentication-services-credential-provider-ui",
    "com.apple.broadcast-services-setupui",
    "com.apple.broadcast-services-upload",
    "com.apple.intents-service",
    "com.apple.safari.sharedlinks-service",
    "com.apple.services",
    "com.apple.share-services",
    "com.apple.ui-services",
    "com.apple.usernotifications.service",
}


def build_xpc_surface(
    project: str,
    program: str,
    bundle_dir: str | Path | None = None,
    objc_metadata_path: str | Path | None = None,
    strings_path: str | Path | None = None,
    symbols_path: str | Path | None = None,
    output: str | Path | None = None,
    markdown_output: str | Path | None = None,
) -> dict[str, Any]:
    """Build an XPC surface report from already-exported JSON artifacts."""
    export_dir = cfg.export_dir(project, program)
    bundle_path = Path(bundle_dir) if bundle_dir else None
    input_dir = bundle_path or export_dir
    output_dir = bundle_path or export_dir
    objc_path = Path(objc_metadata_path) if objc_metadata_path else input_dir / "objc_metadata.json"
    str_path = Path(strings_path) if strings_path else input_dir / "strings.json"
    sym_path = Path(symbols_path) if symbols_path else input_dir / "symbols.json"
    out_path = Path(output) if output else output_dir / "xpc_surface.json"
    md_path = Path(markdown_output) if markdown_output else output_dir / "xpc_surface.md"

    input_status = _input_status(
        {
            "objc_metadata": objc_path,
            "strings": str_path,
            "symbols": sym_path,
        }
    )
    warnings = _input_warnings(input_status)
    objc = _load_json(objc_path)
    strings = _load_json(str_path)
    symbols = _load_json(sym_path)

    xpc_classes = _name_hits(_objc_names(objc, "classes") + _objc_names(objc, "interface_classes"))
    xpc_protocols = _protocol_hits(objc)
    xpc_selectors = _name_hits(_objc_names(objc, "selectors"))
    xpc_ivars = _name_hits(_objc_names(objc, "ivars"))
    xpc_symbols = _symbol_hits(symbols)
    service_names = _service_name_hits(strings)
    method_hints = _method_hints(xpc_symbols, xpc_selectors)
    reverse_dns_service_hints = _reverse_dns_service_hints(strings, has_xpc_context=_has_xpc_context(method_hints))
    distributed_methods = _distributed_method_hits(xpc_symbols, strings)

    report = {
        "ok": True,
        "project": project,
        "program": program,
        "inputs": {
            "bundle_dir": str(bundle_path) if bundle_path else None,
            "objc_metadata": str(objc_path),
            "strings": str(str_path),
            "symbols": str(sym_path),
        },
        "input_status": input_status,
        "warnings": warnings,
        "summary": {
            "xpc_class_count": len(xpc_classes),
            "xpc_protocol_count": len(xpc_protocols),
            "xpc_selector_count": len(xpc_selectors),
            "xpc_ivar_count": len(xpc_ivars),
            "xpc_symbol_count": len(xpc_symbols),
            "service_name_count": len(service_names),
            "reverse_dns_service_hint_count": len(reverse_dns_service_hints),
            "listener_method_count": len(method_hints["listener_methods"]),
            "connection_method_count": len(method_hints["connection_methods"]),
            "distributed_method_count": len(distributed_methods),
            "missing_input_count": len(warnings),
        },
        "xpc_classes": xpc_classes,
        "xpc_protocols": xpc_protocols,
        "xpc_selectors": xpc_selectors[:500],
        "xpc_ivars": xpc_ivars[:500],
        "service_names": service_names[:500],
        "reverse_dns_service_hints": reverse_dns_service_hints[:500],
        "method_hints": method_hints,
        "distributed_methods": distributed_methods,
        "xpc_symbols": xpc_symbols[:1000],
        "topology_hints": _topology_hints(
            service_names,
            reverse_dns_service_hints,
            method_hints,
            xpc_protocols,
            distributed_methods,
        ),
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    md_path.write_text(_render_markdown(report), encoding="utf-8")
    return {
        "ok": True,
        "output": str(out_path),
        "markdown_output": str(md_path),
        "warnings": warnings,
        **report["summary"],
    }


def _objc_names(payload: dict[str, Any], key: str) -> list[str]:
    values = payload.get(key, [])
    names = []
    if not isinstance(values, list):
        return names
    for item in values:
        if isinstance(item, str):
            names.append(item)
        elif isinstance(item, dict):
            for candidate_key in ("name", "raw_name", "selector"):
                candidate = item.get(candidate_key)
                if candidate:
                    names.append(str(candidate))
                    break
    return names


def _input_status(paths: dict[str, Path]) -> dict[str, dict[str, Any]]:
    status = {}
    for name, path in paths.items():
        exists = path.exists()
        status[name] = {
            "path": str(path),
            "exists": exists,
            "size": path.stat().st_size if exists else 0,
        }
    return status


def _input_warnings(input_status: dict[str, dict[str, Any]]) -> list[str]:
    warnings = []
    for name, status in input_status.items():
        if not status.get("exists"):
            warnings.append(f"missing {name} input: {status.get('path')}")
    return warnings


def _name_hits(names: list[str]) -> list[str]:
    seen = set()
    hits = []
    for name in names:
        lowered = _normalise(name)
        if lowered in seen:
            continue
        if _is_xpc_related(name):
            seen.add(lowered)
            hits.append(name)
    return sorted(hits, key=str.lower)


def _protocol_hits(objc: dict[str, Any]) -> list[dict[str, Any]]:
    protocols = []
    for source_key in ("protocols", "recovered_protocols", "protocol_refs"):
        values = objc.get(source_key, [])
        if not isinstance(values, list):
            continue
        for item in values:
            if isinstance(item, str):
                raw = item
                name = _clean_protocol_name(item)
            elif isinstance(item, dict):
                raw_value = str(item.get("raw_name") or item.get("name") or "")
                name = _clean_protocol_name(str(item.get("name") or raw_value))
                raw = str(item.get("raw_name") or item.get("name") or "")
            else:
                continue
            if not name or "xpc" not in name.lower() and "xpc" not in raw.lower():
                continue
            protocols.append({"name": name, "raw_name": raw, "source": source_key})
    return _dedupe_dicts(protocols, ("name", "source"))


def _symbol_hits(symbols: dict[str, Any]) -> list[dict[str, Any]]:
    hits = []
    for source_key in ("symbols", "imports", "exports"):
        values = symbols.get(source_key, [])
        if not isinstance(values, list):
            continue
        for item in values:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "")
            if not name or not (
                _is_xpc_related(name)
                or _is_distributed_method_descriptor(name)
                or _is_swift_distributed_symbolic(name)
            ):
                continue
            hits.append(
                {
                    "name": name,
                    "address": item.get("address"),
                    "source": source_key,
                    "symbol_type": item.get("symbol_type"),
                    "xref_count": item.get("xref_count"),
                    "sample_xrefs": item.get("sample_xrefs", [])[:5]
                    if isinstance(item.get("sample_xrefs"), list)
                    else [],
                }
            )
    return _dedupe_dicts(hits, ("name", "address", "source"))


def _service_name_hits(strings: dict[str, Any]) -> list[dict[str, Any]]:
    hits = []
    values = strings.get("strings", [])
    if not isinstance(values, list):
        return hits
    for item in values:
        if not isinstance(item, dict):
            continue
        value = str(item.get("value") or "")
        if not _looks_like_service_name(value):
            continue
        xrefs = item.get("xrefs", [])
        hits.append(
            {
                "value": value,
                "address": item.get("address"),
                "xref_count": item.get("xref_count"),
                "referenced_from": _referenced_from(xrefs),
            }
        )
    return _dedupe_dicts(sorted(hits, key=lambda item: str(item["value"]).lower()), ("value", "address"))


def _reverse_dns_service_hints(strings: dict[str, Any], *, has_xpc_context: bool) -> list[dict[str, Any]]:
    hints = []
    values = strings.get("strings", [])
    if not isinstance(values, list):
        return hints
    for item in values:
        if not isinstance(item, dict):
            continue
        value = str(item.get("value") or "")
        if _looks_like_service_name(value) or not _looks_like_reverse_dns_name(value):
            continue
        reason = _reverse_dns_service_hint_reason(
            value,
            int(item.get("xref_count") or 0),
            has_xpc_context=has_xpc_context,
        )
        if not reason:
            continue
        hints.append(
            {
                "value": value,
                "address": item.get("address"),
                "xref_count": item.get("xref_count"),
                "confidence": "low",
                "reason": reason,
                "referenced_from": _referenced_from(item.get("xrefs", [])),
            }
        )
    return _dedupe_dicts(sorted(hints, key=lambda item: str(item["value"]).lower()), ("value", "address"))


def _method_hints(symbols: list[dict[str, Any]], selectors: list[str]) -> dict[str, list[dict[str, Any]]]:
    names = [{"name": selector, "source": "selector"} for selector in selectors]
    names.extend({"name": str(symbol.get("name")), "source": str(symbol.get("source"))} for symbol in symbols)
    listener = []
    connection = []
    interface = []
    for item in names:
        name = item["name"]
        lowered = name.lower()
        entry = {"name": name, "source": item["source"]}
        if "listener" in lowered or "shouldacceptnewconnection" in lowered:
            listener.append(entry)
        if "xpcconnection" in lowered or "machservicename" in lowered or "servicename" in lowered:
            connection.append(entry)
        if "interfacewithprotocol" in lowered or "xpcinterface" in lowered or "exportedinterface" in lowered:
            interface.append(entry)
    return {
        "listener_methods": _dedupe_dicts(listener, ("name", "source"))[:500],
        "connection_methods": _dedupe_dicts(connection, ("name", "source"))[:500],
        "interface_methods": _dedupe_dicts(interface, ("name", "source"))[:500],
    }


def _distributed_method_hits(
    symbols: list[dict[str, Any]], strings: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    hits = []
    for symbol in symbols:
        name = str(symbol.get("name") or "")
        if _is_distributed_method_descriptor(name):
            protocol, method = _split_distributed_descriptor(name)
            descriptor_kind = (
                "distributed_thunk" if "distributed_thunk_method_descriptor_for_" in name else "method_descriptor"
            )
        elif _is_swift_distributed_symbolic(name):
            protocol, method = _split_swift_symbolic_request_signature(name)
            descriptor_kind = "symbolic_request_signature"
        else:
            continue
        hits.append(
            {
                "name": name,
                "protocol": protocol,
                "method": method,
                "address": symbol.get("address"),
                "source": symbol.get("source"),
                "descriptor_kind": descriptor_kind,
                "xref_count": symbol.get("xref_count"),
                "sample_xrefs": symbol.get("sample_xrefs", [])[:5]
                if isinstance(symbol.get("sample_xrefs"), list)
                else [],
            }
        )
    hits.extend(_distributed_method_string_hits(strings or {}))
    hits.sort(key=lambda item: str(item.get("address") or "").startswith("EXTERNAL:"))
    return _dedupe_dicts(hits, ("protocol", "method", "descriptor_kind"))[:500]


def _is_distributed_method_descriptor(name: str) -> bool:
    lowered = name.lower()
    if "method_descriptor_for_" not in lowered:
        return False
    return "xpcdistributed" in lowered or "distributed_thunk" in lowered


def _is_swift_distributed_symbolic(name: str) -> bool:
    if not name.startswith("_symbolic"):
        return False
    lowered = name.lower()
    return "requestv_" in lowered and "responseo_" in lowered and "errorp" in lowered and "actorc" in lowered


def _split_distributed_descriptor(name: str) -> tuple[str, str]:
    marker = "method_descriptor_for_"
    if marker not in name:
        return "", name
    tail = name.split(marker, 1)[1]
    open_paren = tail.find("(")
    if open_paren > 0:
        owner_and_method = tail[:open_paren]
        if "." not in owner_and_method:
            return "", tail
        protocol, method_name = owner_and_method.rsplit(".", 1)
        return protocol, method_name + tail[open_paren:]
    if "." not in tail:
        return "", tail
    protocol, method = tail.rsplit(".", 1)
    return protocol, method


def _distributed_method_string_hits(strings: dict[str, Any]) -> list[dict[str, Any]]:
    values = strings.get("strings", [])
    if not isinstance(values, list):
        return []
    hits = []
    for item in values:
        if not isinstance(item, dict):
            continue
        value = str(item.get("value") or "")
        parsed = _parse_swift_distributed_thunk_string(value)
        if not parsed:
            continue
        owner, method = parsed
        hits.append(
            {
                "name": value,
                "protocol": owner,
                "method": method,
                "address": item.get("address"),
                "source": "strings",
                "descriptor_kind": "distributed_thunk_string",
                "xref_count": item.get("xref_count"),
                "sample_xrefs": _referenced_from(item.get("xrefs", [])),
            }
        )
    return hits


def _parse_swift_distributed_thunk_string(value: str) -> tuple[str, str] | None:
    if not value.startswith("$s") or "YaKFTE" not in value:
        return None
    match = re.search(
        r"(?P<owner>[A-Za-z0-9_]*Actor)C(?P<length>\d+)(?P<method>[A-Za-z_][A-Za-z0-9_]*)y",
        value,
    )
    if not match:
        return None
    method = match.group("method")
    try:
        expected_length = int(match.group("length"))
    except ValueError:
        expected_length = 0
    if expected_length and len(method) < expected_length:
        return None
    if expected_length:
        method = method[:expected_length]
    return _trim_swift_length_component(match.group("owner")), method


def _split_swift_symbolic_request_signature(name: str) -> tuple[str, str]:
    actor_match = re.search(r"_AA(?P<actor>[^_]*Actor)C_", name)
    actor = _trim_swift_length_component(actor_match.group("actor")) if actor_match else "unknown"
    family = _last_swift_length_component_before(name, "O7RequestV")
    if not family:
        return actor, name
    return actor, f"{family}.Request"


def _trim_swift_length_component(value: str) -> str:
    candidates = []
    for match in re.finditer(r"\d+", value):
        candidate = value[match.end() :]
        if candidate.endswith("Actor") and candidate[:1].isupper() and candidate != "Actor":
            candidates.append(candidate)
    if candidates:
        return min(candidates, key=len)
    return re.sub(r"^\d+", "", value)


def _last_swift_length_component_before(value: str, suffix: str) -> str:
    suffix_index = value.rfind(suffix)
    if suffix_index <= 0:
        return ""
    prefix = value[:suffix_index]
    for match in reversed(list(re.finditer(r"\d+", prefix))):
        try:
            expected_length = int(match.group(0))
        except ValueError:
            continue
        if expected_length <= 0:
            continue
        component_start = match.end()
        component = prefix[component_start : component_start + expected_length]
        if (
            len(component) == expected_length
            and component_start + expected_length == len(prefix)
            and component[:1].isupper()
        ):
            return component
    return ""


def _topology_hints(
    service_names: list[dict[str, Any]],
    reverse_dns_service_hints: list[dict[str, Any]],
    method_hints: dict[str, list[dict[str, Any]]],
    protocols: list[dict[str, Any]],
    distributed_methods: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "probable_services": service_names[:100],
        "probable_service_hints": reverse_dns_service_hints[:100],
        "probable_listeners": method_hints["listener_methods"][:100],
        "probable_clients": method_hints["connection_methods"][:100],
        "probable_interfaces": protocols[:100] + method_hints["interface_methods"][:100],
        "probable_distributed_methods": distributed_methods[:100],
    }


def _referenced_from(xrefs: Any) -> list[dict[str, Any]]:
    if not isinstance(xrefs, list):
        return []
    refs = []
    for ref in xrefs[:10]:
        if not isinstance(ref, dict):
            continue
        refs.append(
            {
                "from_address": ref.get("from_address"),
                "from_function": ref.get("from_function"),
                "ref_type": ref.get("ref_type"),
            }
        )
    return refs


def _looks_like_service_name(value: str) -> bool:
    lowered = value.lower()
    if len(value) > 240 or len(value) < 4:
        return False
    if _looks_like_extension_point_identifier(lowered):
        return False
    if " " in value or "\n" in value or "\t" in value:
        return False
    if ":" in value:
        return False
    if "$" in value:
        return False
    if value.startswith("_") and lowered.endswith(("machservicenamekey", "servicenamekey")):
        return False
    if value.startswith("_") and "machservicename" not in lowered:
        return False
    if "machservicename" in lowered:
        return True
    if lowered.endswith(".xpc") or ".xpc." in lowered:
        return True
    if not lowered.startswith(("com.apple.", "org.", "net.")):
        return False
    if "xpc" in lowered or ".service" in lowered or "-service" in lowered:
        return True
    return False


def _looks_like_reverse_dns_name(value: str) -> bool:
    lowered = value.lower()
    if len(value) > 240 or len(value) < 8:
        return False
    if any(separator in value for separator in (" ", "\n", "\t", ":", "$")):
        return False
    if value.startswith("_"):
        return False
    if not lowered.startswith(("com.apple.", "org.", "net.")):
        return False
    return lowered.count(".") >= 2


def _reverse_dns_service_hint_reason(value: str, xref_count: int, *, has_xpc_context: bool) -> str:
    lowered = value.lower()
    if lowered.startswith(("com.apple.private.", "com.apple.security.", "com.apple.developer.")):
        return ""
    if _looks_like_extension_point_identifier(lowered):
        return ""
    service_tokens = (
        "agent",
        "daemon",
        "downloads",
        "exec",
        "helper",
        "kext",
        "mach",
        "registrar",
        "runner",
        "sampling",
        "service",
        "xpc",
    )
    tail = lowered.rsplit(".", 1)[-1]
    if any(token in tail for token in service_tokens):
        return "service-like reverse-DNS suffix"
    if has_xpc_context and xref_count > 0 and not lowered.startswith("com.apple.security."):
        return "referenced reverse-DNS string in binary with XPC connection evidence"
    return ""


def _looks_like_extension_point_identifier(lowered: str) -> bool:
    return lowered in APPLE_EXTENSION_POINT_SERVICE_IDENTIFIERS


def _has_xpc_context(method_hints: dict[str, list[dict[str, Any]]]) -> bool:
    return any(
        bool(method_hints.get(key))
        for key in ("listener_methods", "connection_methods", "interface_methods")
    )


def _is_xpc_related(name: str) -> bool:
    lowered = _normalise(name)
    return any(term in lowered for term in XPC_TERMS)


def _normalise(value: str) -> str:
    return value.lower().replace("_", "").replace(":", "").replace("-", "")


def _clean_protocol_name(value: str) -> str:
    name = value
    for prefix in (
        "__OBJC_$_PROTOCOL_INSTANCE_METHODS_OPT_",
        "__OBJC_$_PROTOCOL_INSTANCE_METHODS_",
        "__OBJC_$_PROTOCOL_CLASS_METHODS_",
        "__OBJC_$_PROTOCOL_METHOD_TYPES_",
        "__OBJC_$_PROTOCOL_REFS_",
        "__OBJC_LABEL_PROTOCOL_$_",
        "__OBJC_PROTOCOL_REFERENCE_$_",
        "__OBJC_PROTOCOL_$_",
        "__OBJC_CLASS_PROTOCOLS_$_",
    ):
        if name.startswith(prefix):
            return name[len(prefix) :]
    return name


def _dedupe_dicts(items: list[dict[str, Any]], keys: tuple[str, ...]) -> list[dict[str, Any]]:
    seen = set()
    result = []
    for item in items:
        marker = tuple(str(item.get(key)) for key in keys)
        if marker in seen:
            continue
        seen.add(marker)
        result.append(item)
    return result


def _render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        f"# XPC Surface: {report['project']} / {report['program']}",
        "",
        "## Summary",
        "",
    ]
    for key, value in summary.items():
        lines.append(f"- `{key}`: {value}")
    if report.get("warnings"):
        lines.extend(["", "## Input Warnings", ""])
        for warning in report["warnings"]:
            lines.append(f"- {warning}")
    lines.extend(["", "## Probable Services", ""])
    for item in report["topology_hints"]["probable_services"][:25]:
        refs = item.get("referenced_from") or []
        ref_text = ""
        if refs:
            ref = refs[0]
            ref_text = f" from `{ref.get('from_function') or ref.get('from_address')}`"
        lines.append(f"- `{item['value']}` at `{item.get('address')}`{ref_text}")
    lines.extend(["", "## Reverse-DNS Service Hints", ""])
    for item in report["topology_hints"].get("probable_service_hints", [])[:25]:
        refs = item.get("referenced_from") or []
        ref_text = ""
        if refs:
            ref = refs[0]
            ref_text = f" from `{ref.get('from_function') or ref.get('from_address')}`"
        lines.append(
            f"- `{item['value']}` at `{item.get('address')}` "
            f"({item.get('confidence')}, {item.get('reason')}){ref_text}"
        )
    lines.extend(["", "## Probable Listeners", ""])
    for item in report["topology_hints"]["probable_listeners"][:25]:
        lines.append(f"- `{item['name']}` ({item['source']})")
    lines.extend(["", "## Probable Interfaces", ""])
    for item in report["topology_hints"]["probable_interfaces"][:25]:
        name = item.get("name") if isinstance(item, dict) else str(item)
        source = item.get("source") if isinstance(item, dict) else "unknown"
        lines.append(f"- `{name}` ({source})")
    lines.extend(["", "## Swift Distributed Methods", ""])
    for item in report["topology_hints"].get("probable_distributed_methods", [])[:25]:
        method = item.get("method") or item.get("name")
        protocol = item.get("protocol") or "unknown"
        kind = item.get("descriptor_kind") or item.get("source") or "unknown"
        lines.append(f"- `{method}` on `{protocol}` ({kind})")
    lines.append("")
    return "\n".join(lines)


def _load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError(f"failed to parse JSON at {path}: {exc}") from exc
    return data if isinstance(data, dict) else {}
