from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

from cerberus_re_skill.core.config import cfg


DEFAULT_JSON_FILES = (
    "program_summary.json",
    "symbols.json",
    "strings.json",
    "objc_metadata.json",
    "swift_metadata.json",
    "function_inventory.json",
)

COMMON_LIST_KEYS = (
    "field_descriptors",
    "capture_descriptors",
    "symbols",
    "imports",
    "exports",
    "objc_related",
    "swift_related",
    "strings",
    "functions",
    "classes",
    "interface_classes",
    "metaclasses",
    "selectors",
    "selector_strings",
    "protocol_refs",
    "recovered_protocols",
    "ivars",
    "memory_blocks",
    "metadata_methods",
    "protocol_requirements",
    "associated_conformances",
    "code_candidates",
    "async_relationships",
    "runtime_artifacts",
    "property_records",
    "types",
    "protocol_conformances",
    "metadata_accessors",
    "async_entrypoints",
    "type_descriptors",
    "dispatch_thunks",
    "protocol_witnesses",
    "outlined_helpers",
    "aliases",
)

AGGREGATE_ROOT_KEYS = COMMON_LIST_KEYS + ("alias_map", "metadata_sections")


@dataclass(frozen=True)
class InputBundle:
    label: str
    path: Path
    source: str


def build_term_index(
    inputs: list[str],
    terms: list[str],
    *,
    output: str | None = None,
    markdown_output: str | None = None,
    max_samples: int = 10,
    ignore_case: bool = False,
    json_files: tuple[str, ...] = DEFAULT_JSON_FILES,
) -> dict[str, Any]:
    """Build a bounded term index over exported ghidra-re JSON bundles."""

    cleaned_terms = [term for term in (t.strip() for t in terms) if term]
    if not cleaned_terms:
        raise ValueError("at least one --term is required")
    if not inputs:
        raise ValueError("at least one input bundle is required")
    if max_samples < 1:
        raise ValueError("max_samples must be >= 1")

    bundles = [_resolve_input_bundle(raw) for raw in inputs]
    created_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    result: dict[str, Any] = {
        "schema": "ghidra-re.term-index.v1",
        "ok": True,
        "created_at": created_at,
        "terms": cleaned_terms,
        "ignore_case": ignore_case,
        "max_samples": max_samples,
        "input_count": len(bundles),
        "inputs": [],
        "warnings": [],
    }

    for bundle in bundles:
        indexed = _index_bundle(
            bundle,
            cleaned_terms,
            max_samples=max_samples,
            ignore_case=ignore_case,
            json_files=json_files,
        )
        result["inputs"].append(indexed)

    result["term_totals"] = _term_totals(result["inputs"], cleaned_terms)

    out_path = Path(output) if output else Path("term_index.json").resolve()
    md_path = Path(markdown_output) if markdown_output else out_path.with_suffix(".md")
    result["output"] = str(out_path)
    result["markdown_output"] = str(md_path)
    result["warning_count"] = _warning_count(result)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(render_term_index_markdown(result), encoding="utf-8")
    return result


def render_term_index_markdown(result: dict[str, Any]) -> str:
    lines: list[str] = [
        "# Term Index",
        "",
        f"- Created: `{result.get('created_at', '')}`",
        f"- Inputs: `{result.get('input_count', 0)}`",
        f"- Terms: `{', '.join(result.get('terms', []))}`",
        f"- Match mode: `{'case-insensitive' if result.get('ignore_case') else 'case-sensitive'}`",
        "",
        "## Totals",
        "",
    ]
    totals = result.get("term_totals", {})
    if totals:
        for term in result.get("terms", []):
            lines.append(f"- `{term}`: `{totals.get(term, 0)}`")
    else:
        lines.append("- No terms matched.")
    lines.append("")

    for bundle in result.get("inputs", []):
        lines.extend(
            [
                f"## {bundle.get('label', '<unknown>')}",
                "",
                f"- Path: `{bundle.get('path', '')}`",
                f"- Exists: `{bundle.get('exists', False)}`",
                f"- Files scanned: `{bundle.get('file_count', 0)}`",
                "",
            ]
        )
        if bundle.get("warning"):
            lines.extend([f"- Warning: `{bundle.get('warning')}`", ""])
        counts = bundle.get("term_counts", {})
        if counts:
            for term in result.get("terms", []):
                lines.append(f"- `{term}`: `{counts.get(term, 0)}`")
        else:
            lines.append("- No selected terms hit.")
        lines.append("")

        samples = bundle.get("samples", [])
        if samples:
            lines.append("### Samples")
            lines.append("")
            for sample in samples:
                value = _markdown_snippet(sample.get("snippet", ""))
                lines.append(
                    f"- `{sample.get('term', '')}` in "
                    f"`{sample.get('file', '')}:{sample.get('path', '')}`: {value}"
                )
            lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _resolve_input_bundle(raw: str) -> InputBundle:
    if "=" in raw:
        label, value = raw.split("=", 1)
        label = label.strip()
        path = Path(value).expanduser()
        if not label:
            label = path.name or "bundle"
        return InputBundle(label=label, path=path, source="explicit")
    if ":" in raw and not raw.startswith("/") and not raw.startswith("~"):
        project, program = raw.split(":", 1)
        path = cfg.export_dir(project, program)
        return InputBundle(label=raw, path=path, source="project_program")
    path = Path(raw).expanduser()
    return InputBundle(label=path.name or str(path), path=path, source="path")


def _index_bundle(
    bundle: InputBundle,
    terms: list[str],
    *,
    max_samples: int,
    ignore_case: bool,
    json_files: tuple[str, ...],
) -> dict[str, Any]:
    term_counts = {term: 0 for term in terms}
    samples: list[dict[str, Any]] = []
    files: list[dict[str, Any]] = []
    exists = bundle.path.exists()
    indexed: dict[str, Any] = {
        "label": bundle.label,
        "path": str(bundle.path),
        "source": bundle.source,
        "exists": exists,
        "file_count": 0,
        "term_counts": term_counts,
        "samples": samples,
        "files": files,
    }
    if not exists:
        indexed["warning"] = "input path does not exist"
        return indexed

    for file_name in json_files:
        path = bundle.path / file_name
        if not path.exists():
            continue
        file_record = {"file": file_name, "path": str(path), "ok": True, "record_count": 0}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:  # pragma: no cover - defensive for malformed external exports
            file_record.update({"ok": False, "error": str(exc)})
            files.append(file_record)
            continue
        for record_path, record in _iter_records(data):
            file_record["record_count"] += 1
            text = _record_text(record)
            if not text:
                continue
            matched_terms = _matching_terms(text, terms, ignore_case=ignore_case)
            if not matched_terms:
                continue
            for term in matched_terms:
                term_counts[term] += 1
                if len(samples) < max_samples:
                    samples.append(
                        {
                            "term": term,
                            "file": file_name,
                            "path": record_path,
                            "snippet": _snippet(text, term, ignore_case=ignore_case),
                            "record_summary": _record_summary(record),
                        }
                    )
        files.append(file_record)

    indexed["file_count"] = len(files)
    if not files:
        indexed["warning"] = "input path contains no indexed JSON files"
    return indexed


def _iter_records(data: Any) -> list[tuple[str, Any]]:
    if isinstance(data, dict):
        records: list[tuple[str, Any]] = []
        root_record = {key: value for key, value in data.items() if key not in AGGREGATE_ROOT_KEYS}
        if root_record:
            records.append(("$", root_record))
        for key in COMMON_LIST_KEYS:
            value = data.get(key)
            if isinstance(value, list):
                records.extend((f"{key}[{index}]", item) for index, item in enumerate(value))
        if records:
            return records
        return [("$", data)]
    if isinstance(data, list):
        return [(f"[{index}]", item) for index, item in enumerate(data)]
    return [("$", data)]


def _record_text(record: Any) -> str:
    values: list[str] = []

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)
        elif value is not None:
            values.append(str(value))

    walk(record)
    return " ".join(values)


def _matching_terms(text: str, terms: list[str], *, ignore_case: bool) -> list[str]:
    haystack = text.lower() if ignore_case else text
    return [term for term in terms if (term.lower() if ignore_case else term) in haystack]


def _snippet(text: str, term: str, *, ignore_case: bool) -> str:
    haystack = text.lower() if ignore_case else text
    needle = term.lower() if ignore_case else term
    index = haystack.find(needle)
    if index < 0:
        return text[:240]
    start = max(0, index - 90)
    end = min(len(text), index + len(term) + 150)
    prefix = "..." if start else ""
    suffix = "..." if end < len(text) else ""
    return prefix + text[start:end] + suffix


def _record_summary(record: Any) -> dict[str, Any]:
    if not isinstance(record, dict):
        return {"value": str(record)[:240]}
    wanted = (
        "name",
        "function",
        "entry",
        "address",
        "value",
        "symbol_type",
        "namespace",
        "artifact_type",
        "xref_count",
        "kind",
        "field_count",
        "capture_type_count",
    )
    return {key: record[key] for key in wanted if key in record}


def _term_totals(inputs: list[dict[str, Any]], terms: list[str]) -> dict[str, int]:
    totals = {term: 0 for term in terms}
    for bundle in inputs:
        counts = bundle.get("term_counts", {})
        for term in terms:
            totals[term] += int(counts.get(term, 0))
    return totals


def _warning_count(result: dict[str, Any]) -> int:
    count = len(result.get("warnings", []))
    for bundle in result.get("inputs", []):
        if bundle.get("warning"):
            count += 1
        for file_record in bundle.get("files", []):
            if not file_record.get("ok", False):
                count += 1
    return count


def _markdown_snippet(value: str) -> str:
    text = value.replace("\n", " ").strip()
    if len(text) > 220:
        text = text[:217] + "..."
    return f"`{text}`" if text else "`<empty>`"
