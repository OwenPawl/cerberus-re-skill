"""Normalize function identity across headless exports, bridge payloads, and traces."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


SCHEMA = "ghidra-re.function-identity.v1"


def normalize_function_identity(
    function: dict[str, Any],
    *,
    source: str,
    project: str = "",
    program: str = "",
    program_path: str = "",
) -> dict[str, Any]:
    """Return a stable identity record for a function-like payload."""
    ref = function.get("function_ref") if isinstance(function.get("function_ref"), dict) else {}
    entry_value = function.get("entry") or function.get("address") or ref.get("entry")
    entry_int = parse_int(entry_value)
    entry = hex_addr(entry_int)
    resolved_program_path = str(program_path or function.get("program_path") or ref.get("program_path") or "")
    resolved_program = str(program or function.get("program") or function.get("program_name") or "")
    namespace = str(function.get("namespace") or "")
    name = str(function.get("name") or function.get("function_name") or "")
    symbol = symbol_form(namespace=namespace, name=name)
    identity_key = build_identity_key(
        project=project,
        program=resolved_program,
        program_path=resolved_program_path,
        entry=entry,
    )

    return {
        "schema": SCHEMA,
        "source": source,
        "identity_key": identity_key,
        "project": project,
        "program": resolved_program,
        "program_path": resolved_program_path,
        "entry": entry,
        "entry_raw": "" if entry_value is None else str(entry_value),
        "address": entry,
        "namespace": namespace,
        "name": name,
        "symbol": symbol,
        "signature": str(function.get("signature") or ""),
        "body_size": function.get("body_size") or _body_size(function.get("body")),
        "is_external": bool(function.get("is_external", function.get("external", False))),
        "is_thunk": bool(function.get("is_thunk", function.get("thunk", False))),
        "is_inline": bool(function.get("is_inline", False)),
    }


def build_function_identity_report(
    *,
    project: str,
    program: str,
    headless_path: str | Path,
    live_path: str | Path,
    output: str | Path | None = None,
) -> dict[str, Any]:
    """Compare headless function inventory identities with live bridge function payloads."""
    headless_file = Path(headless_path)
    live_file = Path(live_path)
    headless_payload = _load_json(headless_file)
    live_payload = _load_json(live_file)

    headless = identities_from_payload(
        headless_payload,
        source="headless",
        project=project,
        program=program or str(headless_payload.get("program_name") or ""),
    )
    live = identities_from_payload(
        live_payload,
        source="bridge",
        project=project,
        program=program or str(live_payload.get("program_name") or ""),
    )

    headless_by_entry = {item["entry"]: item for item in headless if item.get("entry")}
    live_by_entry = {item["entry"]: item for item in live if item.get("entry")}
    shared_entries = sorted(set(headless_by_entry) & set(live_by_entry), key=lambda value: parse_int(value) or 0)

    changed = []
    for entry in shared_entries:
        left = headless_by_entry[entry]
        right = live_by_entry[entry]
        field_changes = {}
        for field in ["name", "namespace", "symbol", "signature", "body_size", "is_external", "is_thunk", "is_inline"]:
            left_value = left.get(field)
            right_value = right.get(field)
            if right_value in ("", None) and field in {"namespace", "signature", "symbol"}:
                continue
            if left_value != right_value:
                field_changes[field] = {"headless": left_value, "bridge": right_value}
        if field_changes:
            changed.append({"entry": entry, "changes": field_changes})

    report = {
        "ok": True,
        "schema": "ghidra-re.function-identity-report.v1",
        "project": project,
        "program": program,
        "headless_path": str(headless_file),
        "live_path": str(live_file),
        "headless_count": len(headless),
        "live_count": len(live),
        "matched_count": len(shared_entries),
        "missing_in_live": [headless_by_entry[entry] for entry in sorted(set(headless_by_entry) - set(live_by_entry))],
        "extra_in_live": [live_by_entry[entry] for entry in sorted(set(live_by_entry) - set(headless_by_entry))],
        "changed": changed,
    }

    if output:
        out_path = Path(output)
    else:
        out_path = headless_file.with_name("function_identity_report.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    report["output"] = str(out_path)
    return report


def identities_from_payload(
    payload: dict[str, Any],
    *,
    source: str,
    project: str = "",
    program: str = "",
    program_path: str = "",
) -> list[dict[str, Any]]:
    functions = _extract_functions(payload)
    return [
        normalize_function_identity(
            function,
            source=source,
            project=project,
            program=program,
            program_path=program_path,
        )
        for function in functions
    ]


def symbol_form(namespace: str, name: str) -> str:
    if namespace and name and namespace not in {"/", "Global", "global", "stub"}:
        if name.startswith(("+[", "-[")):
            return name
        if ":" in name:
            return f"-[{namespace} {name}]"
    return name


def build_identity_key(*, project: str, program: str, program_path: str, entry: str | None) -> str:
    location = program_path or ":".join(part for part in [project, program] if part)
    if not location:
        location = "unknown-program"
    return f"{location}@{entry or 'unknown-entry'}"


def parse_int(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(text, 16)
    except ValueError:
        try:
            return int(text, 10)
        except ValueError:
            return None


def hex_addr(value: int | None) -> str:
    return "" if value is None else f"0x{value:x}"


def _extract_functions(payload: dict[str, Any]) -> list[dict[str, Any]]:
    if isinstance(payload.get("result"), dict):
        return _extract_functions(payload["result"])
    if isinstance(payload.get("functions"), list):
        return [item for item in payload["functions"] if isinstance(item, dict)]
    if isinstance(payload.get("matches"), list):
        return [item for item in payload["matches"] if isinstance(item, dict)]
    if isinstance(payload.get("function"), dict):
        return [payload["function"]]
    if payload.get("entry") or payload.get("function_ref"):
        return [payload]
    return []


def _body_size(body: Any) -> int | None:
    if isinstance(body, list):
        ranges = body
    elif isinstance(body, dict):
        ranges = body.get("ranges")
    else:
        return None
    if not isinstance(ranges, list):
        return None
    total = 0
    for item in ranges:
        if not isinstance(item, dict):
            continue
        if item.get("length") is not None:
            length = parse_int(item.get("length"))
            if length is not None:
                total += length
                continue
        start = parse_int(item.get("start"))
        end = parse_int(item.get("end"))
        if start is not None and end is not None and end >= start:
            total += end - start + 1
    return total or None


def _load_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError(f"failed to parse JSON at {path}: {exc}") from exc
