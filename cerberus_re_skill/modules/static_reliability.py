"""Static reliability contracts for Apple exports and import diagnostics."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from cerberus_re_skill.core.utils import utc_now, write_json_atomic


APPLE_BUNDLE_SCHEMA = "ghidra-re.apple-bundle-manifest.v1"
APPLE_BUNDLE_MANIFEST = "bundle_manifest.json"
APPLE_BUNDLE_FILES = (
    "program_summary.json",
    "objc_metadata.json",
    "swift_metadata.json",
    "function_inventory.json",
    "function_fingerprints.json",
    "symbols.json",
    "strings.json",
)
SWIFT_SYMBOL_SIDECAR_SCHEMA = "ghidra-re.swift-symbol-aliases.v1"
SWIFT_SYMBOL_SIDECAR = "swift_symbol_aliases.json"
GHIDRA_SYMBOL_NAME_LIMIT = 2000
_UNRESOLVED_PATTERN = re.compile(r"\[([^\]]+)\].*-> not found in project")


class StaticReliabilityError(RuntimeError):
    """Raised when a static artifact cannot satisfy its reliability contract."""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        os.close(descriptor)


def _atomic_copy(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=destination.parent,
    )
    temporary = Path(temporary_name)
    try:
        with source.open("rb") as input_handle, os.fdopen(descriptor, "wb") as output_handle:
            shutil.copyfileobj(input_handle, output_handle)
            output_handle.flush()
            os.fsync(output_handle.fileno())
        os.replace(temporary, destination)
        _fsync_directory(destination.parent)
    finally:
        temporary.unlink(missing_ok=True)


def _bundle_file_records(directory: Path) -> list[dict[str, Any]]:
    records = []
    for name in APPLE_BUNDLE_FILES:
        path = directory / name
        if not path.is_file():
            raise StaticReliabilityError(f"Apple bundle is missing required file: {name}")
        try:
            with path.open(encoding="utf-8") as handle:
                json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            raise StaticReliabilityError(f"Apple bundle file is not valid JSON: {name}: {exc}") from exc
        records.append(
            {
                "name": name,
                "size": path.stat().st_size,
                "sha256": _sha256_file(path),
            }
        )
    return records


def _bundle_id(records: list[dict[str, Any]]) -> str:
    canonical = json.dumps(records, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


@contextmanager
def apple_bundle_staging(destination: str | Path) -> Iterator[Path]:
    """Yield a private sibling directory and remove it after the export attempt."""
    final = Path(destination).expanduser().resolve()
    final.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{final.name}.staging-", dir=final.parent))
    try:
        yield staging
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def publish_apple_bundle(staging: str | Path, destination: str | Path) -> dict[str, Any]:
    """Publish a staged bundle with an in-progress marker and complete manifest last."""
    source = Path(staging).expanduser().resolve()
    final = Path(destination).expanduser().resolve()
    records = _bundle_file_records(source)
    bundle_id = _bundle_id(records)
    final.mkdir(parents=True, exist_ok=True)
    manifest_path = final / APPLE_BUNDLE_MANIFEST
    write_json_atomic(
        manifest_path,
        {
            "schema": APPLE_BUNDLE_SCHEMA,
            "status": "publishing",
            "bundle_id": bundle_id,
            "expected_files": list(APPLE_BUNDLE_FILES),
        },
    )
    for record in records:
        _atomic_copy(source / record["name"], final / record["name"])
    manifest = {
        "schema": APPLE_BUNDLE_SCHEMA,
        "status": "complete",
        "bundle_id": bundle_id,
        "published_at": utc_now(),
        "files": records,
    }
    write_json_atomic(manifest_path, manifest)
    return manifest


def validate_apple_bundle(directory: str | Path) -> dict[str, Any]:
    """Require a complete manifest whose hashes match every standard bundle file."""
    root = Path(directory).expanduser().resolve()
    manifest_path = root / APPLE_BUNDLE_MANIFEST
    try:
        with manifest_path.open(encoding="utf-8") as handle:
            manifest = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise StaticReliabilityError(f"Apple bundle manifest is unavailable: {exc}") from exc
    if not isinstance(manifest, dict) or manifest.get("schema") != APPLE_BUNDLE_SCHEMA:
        raise StaticReliabilityError("Apple bundle manifest schema is invalid")
    if manifest.get("status") != "complete":
        raise StaticReliabilityError(
            f"Apple bundle is not complete: status={manifest.get('status')!r}"
        )
    records = manifest.get("files")
    if not isinstance(records, list) or [item.get("name") for item in records] != list(
        APPLE_BUNDLE_FILES
    ):
        raise StaticReliabilityError("Apple bundle manifest file inventory is invalid")
    actual_records = _bundle_file_records(root)
    if records != actual_records or manifest.get("bundle_id") != _bundle_id(actual_records):
        raise StaticReliabilityError("Apple bundle files do not match the complete manifest")
    return manifest


def unresolved_dependency_path(line: str) -> str:
    match = _UNRESOLVED_PATTERN.search(line)
    return match.group(1).strip() if match else ""


def classify_dyld_dependency(path: str) -> str:
    if path.startswith("/usr/lib/swift/"):
        return "swift_runtime"
    if path.startswith("/System/Library/PrivateFrameworks/"):
        return "private"
    if path.startswith("/System/Library/Frameworks/") or path.startswith("/usr/lib/"):
        return "system"
    return "other"


def filter_expected_dyld_warnings(text: str) -> tuple[str, int]:
    """Remove expected single-image dependency lines while preserving other output."""
    kept = []
    suppressed = 0
    for line in text.splitlines(keepends=True):
        path = unresolved_dependency_path(line)
        if path and classify_dyld_dependency(path) != "other":
            suppressed += 1
            continue
        kept.append(line)
    return "".join(kept), suppressed


def summarize_import_diagnostics(log_text: str, script_log_text: str) -> dict[str, Any]:
    paths_by_category: dict[str, list[str]] = {
        "system": [],
        "private": [],
        "swift_runtime": [],
        "other": [],
    }
    unresolved_count = 0
    symbol_length_failures = 0
    for line in log_text.splitlines():
        path = unresolved_dependency_path(line)
        if path:
            unresolved_count += 1
            paths_by_category[classify_dyld_dependency(path)].append(path)
        if "Symbol name exceeds maximum length" in line:
            symbol_length_failures += 1
    groups = {}
    for category, paths in paths_by_category.items():
        unique = sorted(set(paths))
        groups[category] = {"count": len(paths), "unique_count": len(unique), "examples": unique[:5]}
    expected_count = sum(len(paths_by_category[key]) for key in ("system", "private", "swift_runtime"))
    return {
        "unresolved_count": unresolved_count,
        "unresolved_system": len(paths_by_category["system"]),
        "unresolved_private": len(paths_by_category["private"]),
        "unresolved_swift_runtime": len(paths_by_category["swift_runtime"]),
        "unresolved_other": len(paths_by_category["other"]),
        "unresolved_unique_count": len({path for paths in paths_by_category.values() for path in paths}),
        "expected_unresolved_count": expected_count,
        "unresolved_groups": groups if unresolved_count else {},
        "symbol_length_failures": symbol_length_failures,
        "demangle_failures": sum(
            1 for line in script_log_text.splitlines() if "Unable to demangle:" in line
        ),
    }


def stable_swift_symbol_alias(name: str) -> str:
    digest = hashlib.sha256(name.encode("utf-8")).hexdigest()
    prefix = re.sub(r"[^A-Za-z0-9_$]", "_", name[:96]).rstrip("_") or "swift_symbol"
    return f"{prefix}__cerberus_{digest[:24]}"


def parse_overlength_swift_symbols(
    nm_output: str,
    *,
    maximum_length: int = GHIDRA_SYMBOL_NAME_LIMIT,
) -> list[str]:
    symbols = set()
    for line in nm_output.splitlines():
        parts = line.strip().split()
        if not parts:
            continue
        name = parts[-1]
        normalized = name[1:] if name.startswith("_") else name
        if len(name) > maximum_length and (
            normalized.startswith("$s")
            or normalized.startswith("$S")
            or normalized.startswith("_T")
            or normalized.startswith("symbolic_$s")
        ):
            symbols.add(name)
    return sorted(symbols)


def build_swift_symbol_sidecar(
    binary: str | Path,
    *,
    warning_count: int,
    nm_output: str | None,
    nm_tool: str = "",
    error: str = "",
) -> dict[str, Any]:
    source = Path(binary).expanduser().resolve()
    symbols = parse_overlength_swift_symbols(nm_output or "") if nm_output is not None else []
    aliases = [
        {
            "stable_alias": stable_swift_symbol_alias(name),
            "original_name": name,
            "original_length": len(name),
            "original_sha256": hashlib.sha256(name.encode("utf-8")).hexdigest(),
        }
        for name in symbols
    ]
    if nm_output is None:
        status = "unavailable"
    elif aliases:
        status = "complete"
    else:
        status = "no_matching_symbols"
    return {
        "schema": SWIFT_SYMBOL_SIDECAR_SCHEMA,
        "status": status,
        "binary": str(source),
        "binary_sha256": _sha256_file(source),
        "ghidra_symbol_name_limit": GHIDRA_SYMBOL_NAME_LIMIT,
        "ghidra_overlength_warning_count": warning_count,
        "preserved_symbol_count": len(aliases),
        "nm_tool": nm_tool,
        "error": error,
        "aliases": aliases,
    }


def write_swift_symbol_sidecar(path: str | Path, payload: dict[str, Any]) -> Path:
    destination = Path(path).expanduser().resolve()
    write_json_atomic(destination, payload)
    return destination
