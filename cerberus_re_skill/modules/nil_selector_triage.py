"""Triage selectors that are present but return nil/default values."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cerberus_re_skill.core.config import cfg
from cerberus_re_skill.core.utils import utc_now


NIL_SELECTOR_TRIAGE_SCHEMA = "ghidra-re.nil-selector-triage.v1"


def build_nil_selector_triage(
    *,
    artifacts: list[str] | None = None,
    function_inventory: str | Path | None = None,
    strings: str | Path | None = None,
    dossiers: list[str] | None = None,
    output: str | Path | None = None,
    markdown_output: str | Path | None = None,
) -> dict[str, Any]:
    """Build a static/runtime triage report for present nil-returning selectors."""
    artifact_items = _load_mapped_items(artifacts or [], "artifact")
    if not artifact_items:
        raise RuntimeError("at least one action artifact is required")
    inventory_payload = _load_json(Path(function_inventory), "function inventory") if function_inventory else {}
    strings_payload = _load_json(Path(strings), "strings") if strings else {}
    dossier_items = _load_dossiers(dossiers or [])
    observations = _collect_observations(artifact_items)
    candidates = _rank_candidates(observations, inventory_payload, strings_payload, dossier_items)
    report = {
        "schema": NIL_SELECTOR_TRIAGE_SCHEMA,
        "ok": True,
        "created_at": utc_now(),
        "inputs": {
            "artifacts": [{"id": item["id"], "path": item["path"]} for item in artifact_items],
            "function_inventory": str(function_inventory or ""),
            "strings": str(strings or ""),
            "dossiers": [{"id": item["id"], "path": item["path"]} for item in dossier_items],
        },
        "summary": _summary(candidates),
        "candidates": candidates,
    }

    out_path = Path(output) if output else cfg.exports_dir / "nil_selector_triage.json"
    md_path = Path(markdown_output) if markdown_output else cfg.exports_dir / "nil_selector_triage.md"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    md_path.write_text(_render_markdown(report), encoding="utf-8")
    return {
        "ok": True,
        "output": str(out_path),
        "markdown_output": str(md_path),
        **report["summary"],
    }


def _load_mapped_items(specs: list[str], label: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for spec in specs:
        item_id, path_text = _split_mapping(spec, label)
        path = Path(path_text)
        items.append({"id": item_id, "path": str(path), "payload": _load_json(path, label)})
    return items


def _split_mapping(spec: str, label: str) -> tuple[str, str]:
    if "=" not in spec:
        raise RuntimeError(f"{label} must be formatted as id=path: {spec}")
    left, right = spec.split("=", 1)
    left = left.strip()
    right = right.strip()
    if not left or not right:
        raise RuntimeError(f"{label} must include id and path: {spec}")
    return left, right


def _load_json(path: Path, label: str) -> dict[str, Any]:
    if not path.exists():
        raise RuntimeError(f"{label} does not exist: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError(f"{label} must be a JSON object: {path}")
    return payload


def _load_dossiers(specs: list[str]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for spec in specs:
        item_id, path_text = _split_mapping(spec, "dossier")
        path = Path(path_text)
        context = {}
        decompile_text = ""
        context_path = path / "context.json" if path.is_dir() else path
        decompile_path = path / "decompile.c" if path.is_dir() else path.with_name("decompile.c")
        if context_path.exists():
            loaded = json.loads(context_path.read_text(encoding="utf-8"))
            context = loaded if isinstance(loaded, dict) else {}
        if decompile_path.exists():
            decompile_text = decompile_path.read_text(encoding="utf-8", errors="replace")
        items.append(
            {
                "id": item_id,
                "path": str(path),
                "context": context,
                "function_name": ((context.get("function") or {}).get("name") if isinstance(context.get("function"), dict) else ""),
                "decompile_quality": _decompile_quality(decompile_text),
            }
        )
    return items


def _collect_observations(artifact_items: list[dict[str, Any]]) -> dict[tuple[str, str], dict[str, Any]]:
    observations: dict[tuple[str, str], dict[str, Any]] = {}
    for item in artifact_items:
        payload = item["payload"]
        for node, context in _walk_nodes(payload):
            if isinstance(node, dict) and node.get("selector") and _truthy(node.get("method_present")):
                result = node.get("result")
                if _nilish(result):
                    _add_observation(observations, node, context, item, "object_probe_nil", result)
            if isinstance(node, dict) and node.get("getter"):
                read_before = node.get("read_before")
                read_after = node.get("read_after")
                if _nilish(read_before) or read_before in (0, "0"):
                    selector = str(node.get("getter") or "")
                    pseudo = {"selector": selector, "argument_slot": node.get("argument_slot"), "method_present": node.get("getter_present")}
                    kind = "setter_backed_read_before_nil" if _nilish(read_before) else "setter_backed_default_zero"
                    _add_observation(observations, pseudo, context, item, kind, read_before, mutation=node, read_after=read_after)
    return observations


def _walk_nodes(payload: Any, context: dict[str, Any] | None = None):
    context = dict(context or {})
    if isinstance(payload, dict):
        next_context = dict(context)
        for key in ("class_name", "identifier", "context_slots", "workflow_mode", "variable_source_mode", "method_type_encodings"):
            if key in payload:
                next_context[key] = payload.get(key)
        yield payload, next_context
        for value in payload.values():
            yield from _walk_nodes(value, next_context)
    elif isinstance(payload, list):
        for value in payload:
            yield from _walk_nodes(value, context)


def _add_observation(
    observations: dict[tuple[str, str], dict[str, Any]],
    node: dict[str, Any],
    context: dict[str, Any],
    item: dict[str, Any],
    kind: str,
    observed_value: Any,
    *,
    mutation: dict[str, Any] | None = None,
    read_after: Any = None,
) -> None:
    selector = str(node.get("selector") or "")
    if not selector:
        return
    class_name = str(context.get("class_name") or _class_from_selector(selector) or "")
    key = (class_name, selector)
    record = observations.setdefault(
        key,
        {
            "class_name": class_name,
            "selector": selector,
            "identifier": context.get("identifier") or "",
            "observations": [],
            "context_slot_variants": [],
            "mutation_evidence": [],
            "method_type_evidence": [],
        },
    )
    slots = context.get("context_slots") if isinstance(context.get("context_slots"), dict) else {}
    method_type = _method_type_from_evidence(context.get("method_type_encodings"), class_name, selector)
    if mutation and not method_type:
        method_type = _normalized_method_type(mutation.get("getter_method_type"))
    record["observations"].append(
        {
            "kind": kind,
            "source_id": item["id"],
            "source_path": item["path"],
            "observed_value": observed_value,
            "argument_slot": node.get("argument_slot"),
            "workflow_mode": context.get("workflow_mode"),
            "variable_source_mode": context.get("variable_source_mode"),
            "method_type": method_type,
        }
    )
    if method_type and method_type not in record["method_type_evidence"]:
        record["method_type_evidence"].append(method_type)
    record["context_slot_variants"].append(_context_slot_variant(slots))
    if mutation:
        setter_method_type = _normalized_method_type(mutation.get("setter_method_type"))
        record["mutation_evidence"].append(
            {
                "source_id": item["id"],
                "operation": mutation.get("operation"),
                "setter": mutation.get("setter"),
                "getter": mutation.get("getter"),
                "read_before": mutation.get("read_before"),
                "read_after": read_after,
                "setter_present": mutation.get("setter_present"),
                "getter_present": mutation.get("getter_present"),
                "getter_method_type": method_type,
                "setter_method_type": setter_method_type,
                "set_exception": mutation.get("set_exception"),
                "read_after_exception": mutation.get("read_after_exception"),
            }
        )


def _context_slot_variant(slots: dict[str, Any]) -> dict[str, Any]:
    constructed = sorted(name for name, value in slots.items() if isinstance(value, dict) and _truthy(value.get("constructed")))
    absent = sorted(name for name, value in slots.items() if isinstance(value, dict) and not _truthy(value.get("constructed")))
    return {"constructed": constructed, "absent": absent}


def _rank_candidates(
    observations: dict[tuple[str, str], dict[str, Any]],
    inventory_payload: dict[str, Any],
    strings_payload: dict[str, Any],
    dossiers: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    functions = inventory_payload.get("functions") if isinstance(inventory_payload.get("functions"), list) else []
    strings = strings_payload.get("strings") if isinstance(strings_payload.get("strings"), list) else []
    candidates = []
    for record in observations.values():
        static_matches = _static_matches(record["class_name"], record["selector"], functions)
        dossier_matches = _dossier_matches(record["class_name"], record["selector"], dossiers)
        string_hits = _string_hits(record["class_name"], record["selector"], strings)
        classification = _classification(record)
        score = _score(record, classification, static_matches, dossier_matches)
        candidates.append(
            {
                **record,
                "classification": classification,
                "score": score,
                "static_matches": static_matches,
                "static_match_count": len(static_matches),
                "string_evidence": string_hits,
                "dossier_evidence": dossier_matches,
                "next_runtime_recheck": _next_runtime_recheck(record, classification),
            }
        )
    return sorted(candidates, key=lambda item: (-int(item.get("score") or 0), item.get("class_name", ""), item.get("selector", "")))


def _static_matches(class_name: str, selector: str, functions: list[Any]) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for item in functions:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "")
        if _function_matches(class_name, selector, name):
            matches.append(
                {
                    "name": name,
                    "entry": item.get("entry") or item.get("address"),
                    "signature": item.get("signature"),
                    "callee_count": item.get("callee_count"),
                    "caller_count": item.get("caller_count"),
                    "is_thunk": item.get("is_thunk"),
                    "body_size": item.get("body_size"),
                }
            )
    return matches


def _dossier_matches(class_name: str, selector: str, dossiers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    matches = []
    for item in dossiers:
        name = str(item.get("function_name") or item.get("id") or "")
        if _function_matches(class_name, selector, name):
            matches.append(
                {
                    "id": item.get("id"),
                    "path": item.get("path"),
                    "function_name": item.get("function_name"),
                    "decompile_quality": item.get("decompile_quality"),
                }
            )
    return matches


def _string_hits(class_name: str, selector: str, strings: list[Any]) -> dict[str, Any]:
    needles = [class_name, selector, selector.rstrip(":")]
    samples = []
    for item in strings:
        value = str(item.get("value") if isinstance(item, dict) else item)
        if any(needle and needle in value for needle in needles):
            samples.append(value)
        if len(samples) >= 12:
            break
    return {"sample_count": len(samples), "samples": samples}


def _classification(record: dict[str, Any]) -> str:
    mutations = record.get("mutation_evidence") if isinstance(record.get("mutation_evidence"), list) else []
    if any(_non_nilish(item.get("read_after")) for item in mutations if isinstance(item, dict)):
        if any(item.get("read_before") in (0, "0") for item in mutations if isinstance(item, dict)):
            if _record_has_scalar_return(record):
                return "scalar_default_integer_storage_backed"
            return "scalar_default_or_probe_shape_mismatch"
        return "nil_until_initialized_storage_backed"
    if any(obs.get("kind") == "object_probe_nil" for obs in record.get("observations", []) if isinstance(obs, dict)):
        if _record_has_scalar_return(record):
            return "scalar_default_or_probe_shape_mismatch"
        return "present_nil_needs_context_or_parameter"
    return "needs_review"


def _score(record: dict[str, Any], classification: str, static_matches: list[dict[str, Any]], dossier_matches: list[dict[str, Any]]) -> int:
    score = 40
    if classification == "nil_until_initialized_storage_backed":
        score += 30
    elif classification == "scalar_default_integer_storage_backed":
        score += 28
    elif classification == "present_nil_needs_context_or_parameter":
        score += 24
    elif classification == "scalar_default_or_probe_shape_mismatch":
        score += 12
    if static_matches:
        score += 12
    if dossier_matches:
        score += 6
    if any("authstub_only" == item.get("decompile_quality") for item in dossier_matches):
        score -= 4
    return score


def _next_runtime_recheck(record: dict[str, Any], classification: str) -> dict[str, Any]:
    selector = record.get("selector")
    class_name = record.get("class_name")
    if classification == "nil_until_initialized_storage_backed":
        return {
            "priority": "high",
            "symbol": f"-[{class_name} {selector}]",
            "goal": "repeat controlled Frida getter/setter capture under explicit input and variable-source slots",
        }
    if classification == "scalar_default_integer_storage_backed":
        return {
            "priority": "high",
            "symbol": f"-[{class_name} {selector}]",
            "goal": "preserve scalar-aware getter/setter evidence with LLDB/Frida and avoid object-return nil probes",
        }
    if classification == "present_nil_needs_context_or_parameter":
        return {
            "priority": "medium",
            "symbol": f"-[{class_name} {selector}]",
            "goal": "add the smallest missing local context or parameter seed before treating nil as by-design",
        }
    return {"priority": "low", "symbol": f"-[{class_name} {selector}]", "goal": "review probe signature before runtime work"}


def _summary(candidates: list[dict[str, Any]]) -> dict[str, Any]:
    classes = sorted({item.get("class_name") for item in candidates if item.get("class_name")})
    classifications = {}
    for item in candidates:
        classifications[item["classification"]] = classifications.get(item["classification"], 0) + 1
    return {
        "candidate_count": len(candidates),
        "class_count": len(classes),
        "classes": classes,
        "static_match_count": sum(1 for item in candidates if item.get("static_match_count")),
        "authstub_only_dossier_count": sum(
            1
            for item in candidates
            for dossier in item.get("dossier_evidence", [])
            if dossier.get("decompile_quality") == "authstub_only"
        ),
        "nil_until_initialized_storage_backed_count": classifications.get("nil_until_initialized_storage_backed", 0),
        "scalar_default_integer_storage_backed_count": classifications.get("scalar_default_integer_storage_backed", 0),
        "present_nil_needs_context_or_parameter_count": classifications.get("present_nil_needs_context_or_parameter", 0),
        "scalar_default_or_probe_shape_mismatch_count": classifications.get("scalar_default_or_probe_shape_mismatch", 0),
        "top_candidate": f"-[{candidates[0]['class_name']} {candidates[0]['selector']}]" if candidates else "",
        "top_score": candidates[0]["score"] if candidates else 0,
    }


def _render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# Nil Selector Triage",
        "",
        f"- Schema: `{report['schema']}`",
        f"- Candidates: {summary['candidate_count']}",
        f"- Static matches: {summary['static_match_count']}",
        f"- Storage-backed nils: {summary['nil_until_initialized_storage_backed_count']}",
        f"- Scalar storage-backed defaults: {summary['scalar_default_integer_storage_backed_count']}",
        f"- Context/parameter nils: {summary['present_nil_needs_context_or_parameter_count']}",
        f"- Scalar/probe-shape mismatches: {summary['scalar_default_or_probe_shape_mismatch_count']}",
        f"- Authstub-only dossiers: {summary['authstub_only_dossier_count']}",
        f"- Top candidate: `{summary['top_candidate']}` (score={summary['top_score']})",
        "",
        "## Candidates",
    ]
    for item in report["candidates"]:
        lines.append(
            f"- `-[{item['class_name']} {item['selector']}]`: classification=`{item['classification']}`, "
            f"score={item['score']}, static_matches={item['static_match_count']}, "
            f"next=`{item['next_runtime_recheck']['priority']}`"
        )
    lines.append("")
    return "\n".join(lines)


def _decompile_quality(text: str) -> str:
    if not text:
        return "missing"
    body = "\n".join(line for line in text.splitlines() if not line.startswith("//"))
    if "outlined_authstub_objc_retain_x0" in body and "objc_msgSend" not in body:
        return "authstub_only"
    if "objc_msgSend" in body:
        return "objc_message_flow"
    return "available"


def _normalize_selector(selector: str) -> str:
    return selector.replace(":", "").replace("_", "").replace(" ", "").lower()


def _function_matches(class_name: str, selector: str, function_name: str) -> bool:
    if class_name.lower() not in function_name.lower():
        return False
    normalized_name = _normalize_selector(function_name)
    exact_underscore = _normalize_selector(f"{class_name}_{selector}")
    exact_objc = _normalize_selector(f"{class_name}{selector}")
    return exact_underscore in normalized_name or exact_objc in normalized_name


def _method_type_from_evidence(value: Any, class_name: str, selector: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    candidates: list[Any] = []
    if isinstance(value.get(class_name), list):
        candidates.extend(value.get(class_name) or [])
    for items in value.values():
        if isinstance(items, list):
            candidates.extend(items)
    for item in candidates:
        normalized = _normalized_method_type(item)
        if normalized.get("selector") == selector:
            return normalized
    return {}


def _normalized_method_type(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    selector = str(value.get("selector") or "")
    if not selector:
        return {}
    return {
        "selector": selector,
        "present": _truthy(value.get("present") if "present" in value else value.get("exists")),
        "type_encoding": str(value.get("type_encoding") or ""),
        "return_type": str(value.get("return_type") or ""),
        "return_shape": _return_shape(value),
        "argument_count": value.get("argument_count"),
        "argument_types": value.get("argument_types") if isinstance(value.get("argument_types"), list) else [],
        "argument_shapes": value.get("argument_shapes") if isinstance(value.get("argument_shapes"), list) else [],
    }


def _return_shape(value: dict[str, Any]) -> str:
    shape = str(value.get("return_shape") or "")
    if shape:
        return shape
    return _shape_for_objc_type(str(value.get("return_type") or _return_type_from_encoding(str(value.get("type_encoding") or ""))))


def _return_type_from_encoding(encoding: str) -> str:
    return encoding[:1] if encoding else ""


def _shape_for_objc_type(type_text: str) -> str:
    canonical = type_text.lstrip("rnNoORV")
    if not canonical:
        return ""
    prefix = canonical[0]
    if prefix == "@":
        return "object"
    if prefix == "#":
        return "class"
    if prefix == ":":
        return "selector"
    if prefix == "v":
        return "void"
    if prefix == "B":
        return "bool"
    if prefix in "cislqCISLQ":
        return "integer"
    if prefix in "fd":
        return "floating"
    if prefix == "^":
        return "pointer"
    if prefix == "*":
        return "char_pointer"
    if prefix == "{":
        return "struct"
    return "unknown"


def _record_has_scalar_return(record: dict[str, Any]) -> bool:
    scalar_shapes = {"integer", "bool", "floating"}
    for item in record.get("method_type_evidence", []):
        if isinstance(item, dict) and item.get("return_shape") in scalar_shapes:
            return True
    for item in record.get("mutation_evidence", []):
        if not isinstance(item, dict):
            continue
        getter_type = item.get("getter_method_type")
        if isinstance(getter_type, dict) and getter_type.get("return_shape") in scalar_shapes:
            return True
    return False


def _class_from_selector(selector: str) -> str:
    if selector.startswith("-[") and " " in selector:
        return selector[2:].split(" ", 1)[0]
    return ""


def _truthy(value: Any) -> bool:
    return value is True or str(value).lower() in {"true", "1", "yes"}


def _nilish(value: Any) -> bool:
    return value is None or str(value).lower() in {"nil", "null", "none", "0x0"}


def _non_nilish(value: Any) -> bool:
    return not _nilish(value)
