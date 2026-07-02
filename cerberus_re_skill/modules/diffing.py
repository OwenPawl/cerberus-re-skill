"""Compare two Ghidra export bundles."""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from cerberus_re_skill.core.config import cfg


INTERESTING_TERMS = (
    "auth",
    "bounds",
    "check",
    "deny",
    "error",
    "exception",
    "guard",
    "permission",
    "policy",
    "sandbox",
    "security",
    "validate",
)


def diff_exports(
    project_a: str,
    program_a: str,
    project_b: str,
    program_b: str,
    function_inventory_a: str | Path | None = None,
    function_inventory_b: str | Path | None = None,
    output: str | Path | None = None,
) -> dict[str, Any]:
    """Diff two function inventories and write a structured report."""
    export_a = cfg.export_dir(project_a, program_a)
    export_b = cfg.export_dir(project_b, program_b)
    inv_a = Path(function_inventory_a) if function_inventory_a else export_a / "function_inventory.json"
    inv_b = Path(function_inventory_b) if function_inventory_b else export_b / "function_inventory.json"
    out_path = (
        Path(output)
        if output
        else cfg.exports_dir / f"{project_a}__{program_a}__vs__{project_b}__{program_b}_diff.json"
    )

    payload_a = _load_required_json(inv_a, "left function inventory")
    payload_b = _load_required_json(inv_b, "right function inventory")
    _apply_fingerprints(payload_a, inv_a.with_name("function_fingerprints.json"))
    _apply_fingerprints(payload_b, inv_b.with_name("function_fingerprints.json"))
    funcs_a = _function_groups(payload_a.get("functions", []))
    funcs_b = _function_groups(payload_b.get("functions", []))
    total_a = sum(len(group) for group in funcs_a.values())
    total_b = sum(len(group) for group in funcs_b.values())

    names_a = set(funcs_a)
    names_b = set(funcs_b)
    added_names = sorted(names_b - names_a)
    removed_names = sorted(names_a - names_b)
    common_names = sorted(names_a & names_b)

    modified = []
    unchanged = 0
    added = []
    removed = []
    duplicate_groups = []
    for name in common_names:
        left_group = funcs_a[name]
        right_group = funcs_b[name]
        if len(left_group) > 1 or len(right_group) > 1:
            duplicate_groups.append(name)
        pairs, removed_group, added_group = _align_function_group(left_group, right_group)
        removed.extend(_function_summary(func) for func in removed_group)
        added.extend(_function_summary(func) for func in added_group)
        for left, right in pairs:
            changes = _function_changes(left, right)
            if changes:
                modified.append(
                    {
                        "name": name,
                        "before": _function_summary(left),
                        "after": _function_summary(right),
                        "changes": changes,
                        "patch_relevance": _patch_relevance(name, changes),
                        "semantic_rank": _semantic_rank(name, changes),
                    }
                )
            else:
                unchanged += 1

    for name in added_names:
        added.extend(_function_summary(func) for func in funcs_b[name])
    for name in removed_names:
        removed.extend(_function_summary(func) for func in funcs_a[name])

    report = {
        "ok": True,
        "left": {
            "project": project_a,
            "program": program_a,
            "function_inventory": str(inv_a),
            "function_count": total_a,
            "unique_name_count": len(funcs_a),
        },
        "right": {
            "project": project_b,
            "program": program_b,
            "function_inventory": str(inv_b),
            "function_count": total_b,
            "unique_name_count": len(funcs_b),
        },
        "summary": {
            "added_count": len(added),
            "removed_count": len(removed),
            "modified_count": len(modified),
            "unchanged_count": unchanged,
            "duplicate_name_groups": len(duplicate_groups),
            "matched_by": "function_name_then_entry_fingerprint_or_structure",
        },
        "added": added[:500],
        "removed": removed[:500],
        "modified": sorted(
            modified,
            key=lambda item: (
                -item["patch_relevance"]["score"],
                item["name"],
            ),
        )[:500],
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    return {
        "ok": True,
        "output": str(out_path),
        **report["summary"],
    }


def _function_groups(functions: Any) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = defaultdict(list)
    if not isinstance(functions, list):
        return {}
    for func in functions:
        if not isinstance(func, dict):
            continue
        name = func.get("name")
        if not name:
            continue
        result[str(name)].append(func)
    return dict(result)


def _align_function_group(
    left_group: list[dict[str, Any]],
    right_group: list[dict[str, Any]],
) -> tuple[list[tuple[dict[str, Any], dict[str, Any]]], list[dict[str, Any]], list[dict[str, Any]]]:
    left_remaining = list(left_group)
    right_remaining = list(right_group)
    pairs: list[tuple[dict[str, Any], dict[str, Any]]] = []

    # Same-export and same-build comparisons can align duplicate labels by entry.
    for left in list(left_remaining):
        left_entry = left.get("entry")
        if left_entry is None:
            continue
        match = next((right for right in right_remaining if right.get("entry") == left_entry), None)
        if match is None:
            continue
        pairs.append((left, match))
        left_remaining.remove(left)
        right_remaining.remove(match)

    # Cross-version duplicate labels prefer the mnemonic fingerprint when the
    # export bundle has it, then fall back to coarser function structure.
    for left in list(left_remaining):
        left_key = _structure_key(left)
        match = next((right for right in right_remaining if _structure_key(right) == left_key), None)
        if match is None:
            continue
        pairs.append((left, match))
        left_remaining.remove(left)
        right_remaining.remove(match)

    left_remaining.sort(key=_sort_key)
    right_remaining.sort(key=_sort_key)
    while left_remaining and right_remaining:
        pairs.append((left_remaining.pop(0), right_remaining.pop(0)))

    return pairs, left_remaining, right_remaining


def _structure_key(func: dict[str, Any]) -> tuple[Any, ...]:
    return (
        func.get("mnemonic_sha256"),
        func.get("signature"),
        func.get("return_type"),
        func.get("body_size"),
        func.get("caller_count"),
        func.get("callee_count"),
        func.get("parameter_count"),
        func.get("artifact_type"),
        func.get("block"),
    )


def _sort_key(func: dict[str, Any]) -> tuple[str, str, tuple[Any, ...]]:
    return (
        str(func.get("entry") or ""),
        str(func.get("signature") or ""),
        tuple(str(value) for value in _structure_key(func)),
    )


def _function_changes(left: dict[str, Any], right: dict[str, Any]) -> dict[str, dict[str, Any]]:
    changes = {}
    for key in (
        "signature",
        "return_type",
        "calling_convention",
        "body_size",
        "caller_count",
        "callee_count",
        "parameter_count",
        "mnemonic_count",
        "mnemonic_sha256",
        "artifact_type",
        "is_thunk",
        "is_inline",
        "has_var_args",
        "no_return",
    ):
        if left.get(key) != right.get(key):
            changes[key] = {"before": left.get(key), "after": right.get(key)}
    return changes


def _function_summary(func: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "name",
        "entry",
        "signature",
        "return_type",
        "body_size",
        "caller_count",
        "callee_count",
        "parameter_count",
        "mnemonic_count",
        "mnemonic_sha256",
        "artifact_type",
        "block",
    )
    return {key: func.get(key) for key in keys if key in func}


def _patch_relevance(name: str, changes: dict[str, dict[str, Any]]) -> dict[str, Any]:
    reasons = []
    score = 0
    lowered = name.lower()
    matched_terms = [term for term in INTERESTING_TERMS if term in lowered]
    if matched_terms:
        score += 20 + len(matched_terms)
        reasons.append(f"name_terms:{','.join(matched_terms)}")
    if "body_size" in changes:
        before = changes["body_size"].get("before") or 0
        after = changes["body_size"].get("after") or 0
        if isinstance(before, int) and isinstance(after, int):
            delta = after - before
            if abs(delta) >= 32:
                score += min(abs(delta) // 16, 20)
                reasons.append(f"body_size_delta:{delta}")
    if "callee_count" in changes:
        score += 5
        reasons.append("callee_count_changed")
    if "parameter_count" in changes or "signature" in changes:
        score += 10
        reasons.append("interface_changed")
    return {"score": score, "reasons": reasons}


def _semantic_rank(name: str, changes: dict[str, dict[str, Any]]) -> dict[str, Any]:
    categories = []
    lowered = name.lower()
    security_terms = [term for term in INTERESTING_TERMS if term in lowered]
    if security_terms:
        categories.append({"kind": "security_relevant_name", "evidence": security_terms})
    if any(field in changes for field in ["signature", "return_type", "parameter_count", "has_var_args"]):
        categories.append({"kind": "interface_boundary_changed", "evidence": sorted(changes)})
    if any(field in changes for field in ["callee_count", "caller_count", "mnemonic_sha256", "mnemonic_count"]):
        categories.append({"kind": "control_flow_or_body_changed", "evidence": sorted(changes)})
    if any(field in changes for field in ["no_return", "is_thunk", "is_inline", "artifact_type"]):
        categories.append({"kind": "compiler_or_analysis_shape_changed", "evidence": sorted(changes)})

    score = _patch_relevance(name, changes)["score"]
    if any(item["kind"] == "security_relevant_name" for item in categories):
        score += 15
    if any(item["kind"] == "interface_boundary_changed" for item in categories):
        score += 10
    if any(item["kind"] == "control_flow_or_body_changed" for item in categories):
        score += 5

    if score >= 35:
        risk = "high"
    elif score >= 15:
        risk = "medium"
    elif categories:
        risk = "low"
    else:
        risk = "none"
    return {
        "risk": risk,
        "score": score,
        "categories": categories,
    }


def _load_required_json(path: Path, label: str) -> dict[str, Any]:
    if not path.exists():
        raise RuntimeError(f"missing {label}: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError(f"failed to parse JSON at {path}: {exc}") from exc


def _load_optional_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _apply_fingerprints(inventory: dict[str, Any], fingerprint_path: Path) -> None:
    fingerprints = _load_optional_json(fingerprint_path)
    by_entry = {
        str(item.get("entry")): item
        for item in fingerprints.get("functions", [])
        if isinstance(item, dict) and item.get("entry")
    }
    if not by_entry:
        return
    for func in inventory.get("functions", []):
        if not isinstance(func, dict):
            continue
        match = by_entry.get(str(func.get("entry")))
        if not match:
            continue
        for key in ("mnemonic_count", "mnemonic_sha256"):
            if key in match:
                func[key] = match[key]
