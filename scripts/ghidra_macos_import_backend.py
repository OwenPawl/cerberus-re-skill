#!/usr/bin/env python3

import ctypes
import hashlib
import json
import os
import pathlib
import shutil
import sys
from typing import Any, Dict, List, Optional


DSC_EXTRACTOR_BUNDLE = "/usr/lib/dsc_extractor.bundle"


def load_registry(path: pathlib.Path) -> List[Dict[str, Any]]:
    if not path.is_file():
        return []
    payload = json.loads(path.read_text(encoding="utf-8"))
    return list(payload.get("sources", []))


def normalize_framework_executable_path(raw: str) -> str:
    path = raw.rstrip("/")
    for suffix in (".framework", ".xpc", ".appex"):
        if path.endswith(suffix):
            name = pathlib.PurePosixPath(path).name[: -len(suffix)]
            return f"{path}/{name}"
    return path


def executable_relative_candidates(requested_path: str) -> List[pathlib.PurePosixPath]:
    normalized = pathlib.PurePosixPath(normalize_framework_executable_path(requested_path))
    candidates = [normalized]
    parts = list(normalized.parts)
    if ".framework" in normalized.as_posix():
        framework_name = normalized.parent.name
        if framework_name.endswith(".framework"):
            binary_name = framework_name[: -len(".framework")]
            framework_dir = pathlib.PurePosixPath(*parts[:-1])
            candidates.append(framework_dir / "Versions" / "A" / binary_name)
    return [candidate for candidate in dict.fromkeys(candidates)]


def ensure_cached_copy(resolved: pathlib.Path, cache_root: pathlib.Path, source_name: str, relative_path: str) -> pathlib.Path:
    target = cache_root / source_name / pathlib.Path(*pathlib.PurePosixPath(relative_path).parts)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        return target
    shutil.copy2(resolved, target)
    return target


def locate_dyld_cache(root: pathlib.Path) -> Optional[pathlib.Path]:
    candidates = [
        root / "System/Library/dyld/dyld_shared_cache_arm64e",
        root / "System/Library/dyld/dyld_shared_cache_arm64",
        root / "System/Library/dyld/dyld_shared_cache_x86_64h",
        root / "System/Library/dyld/dyld_shared_cache_x86_64",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def cache_identity(path: pathlib.Path) -> str:
    stat = path.stat()
    seed = f"{path}:{stat.st_size}:{stat.st_mtime_ns}".encode("utf-8")
    return hashlib.sha256(seed).hexdigest()[:16]


def extract_dyld_cache(cache_file: pathlib.Path, output_dir: pathlib.Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    marker = output_dir / ".complete"
    if marker.is_file():
        return
    if not pathlib.Path(DSC_EXTRACTOR_BUNDLE).is_file():
        raise RuntimeError(f"dsc extractor bundle not found: {DSC_EXTRACTOR_BUNDLE}")
    bundle = ctypes.CDLL(DSC_EXTRACTOR_BUNDLE)
    callback_type = ctypes.CFUNCTYPE(None, ctypes.c_uint32, ctypes.c_uint32)
    callback = callback_type(lambda current, total: None)
    extractor = bundle.dyld_shared_cache_extract_dylibs_progress
    extractor.argtypes = [ctypes.c_char_p, ctypes.c_char_p, callback_type]
    extractor.restype = ctypes.c_int
    result = extractor(
        str(cache_file).encode("utf-8"),
        str(output_dir).encode("utf-8"),
        callback,
    )
    if result != 0:
        raise RuntimeError(f"dsc extraction failed for {cache_file} with code {result}")
    marker.write_text(json.dumps({"cache_file": str(cache_file)}), encoding="utf-8")


def source_candidates(registry: List[Dict[str, Any]], source_name: str) -> List[Dict[str, Any]]:
    candidates = [{"name": "local-root", "root": "/", "platform": "macos-host", "copy": "direct"}]
    candidates.extend(registry)
    if source_name:
        candidates = [item for item in candidates if item.get("name") == source_name]
    return candidates


def _existing_extract_candidate(
    extract_root: pathlib.Path,
    relative_candidates: List[pathlib.PurePosixPath],
) -> tuple[pathlib.Path, pathlib.PurePosixPath] | tuple[None, None]:
    for relative_candidate in relative_candidates:
        relative_parts = [part for part in relative_candidate.parts if part not in ("", "/")]
        candidate = extract_root.joinpath(*relative_parts)
        if candidate.is_file():
            return candidate, relative_candidate
    return None, None


def resolve_from_sources(requested_path: str, cache_root: pathlib.Path, registry: List[Dict[str, Any]],
                         copy_mode: str, source_name: str, allow_extract: bool = True) -> Dict[str, Any]:
    normalized = normalize_framework_executable_path(requested_path)
    relative_candidates = executable_relative_candidates(requested_path)
    if not relative_candidates:
        raise RuntimeError(f"invalid framework path: {requested_path}")

    direct_path = pathlib.Path(normalized)
    if direct_path.is_file():
        return {
            "requested_path": requested_path,
            "resolved_path": str(direct_path),
            "strategy": "direct",
            "source_name": "local-root",
            "source_root": "/",
            "cache_identity": "",
        }

    for source in source_candidates(registry, source_name):
        root = pathlib.Path(source.get("root", ""))
        if not root.exists():
            continue
        for relative_candidate in relative_candidates:
            relative_parts = [part for part in relative_candidate.parts if part not in ("", "/")]
            candidate = root.joinpath(*relative_parts)
            if candidate.is_file():
                resolved = candidate if copy_mode == "direct" else ensure_cached_copy(
                    candidate,
                    cache_root,
                    source.get("name", "source"),
                    relative_candidate.as_posix().lstrip("/"),
                )
                return {
                    "requested_path": requested_path,
                    "resolved_path": str(resolved),
                    "strategy": "source-copy" if copy_mode != "direct" else "source-direct",
                    "source_name": source.get("name", "source"),
                    "source_root": str(root),
                    "cache_identity": "",
                    "resolved_relative_path": relative_candidate.as_posix(),
                }

    for source in source_candidates(registry, source_name):
        root = pathlib.Path(source.get("root", ""))
        if not root.exists():
            continue
        cache_file = locate_dyld_cache(root)
        if not cache_file:
            continue
        identity = cache_identity(cache_file)
        extract_root = cache_root / source.get("name", "source") / "_dyld_extract" / identity / "root"
        existing_candidate, existing_relative = _existing_extract_candidate(extract_root, relative_candidates)
        if existing_candidate is not None and existing_relative is not None:
            return {
                "requested_path": requested_path,
                "resolved_path": str(existing_candidate),
                "strategy": "dyld-extract-existing",
                "source_name": source.get("name", "source"),
                "source_root": str(root),
                "cache_identity": identity,
                "dyld_cache_path": str(cache_file),
                "extract_root": str(extract_root),
                "resolved_relative_path": existing_relative.as_posix(),
            }
        if not allow_extract:
            raise RuntimeError(
                "would require dyld cache extraction for "
                f"{requested_path}; cache_file={cache_file}; extract_root={extract_root}"
            )
        extract_dyld_cache(cache_file, extract_root)
        for relative_candidate in relative_candidates:
            relative_parts = [part for part in relative_candidate.parts if part not in ("", "/")]
            candidate = extract_root.joinpath(*relative_parts)
            if candidate.is_file():
                return {
                    "requested_path": requested_path,
                    "resolved_path": str(candidate),
                    "strategy": "dyld-extract",
                    "source_name": source.get("name", "source"),
                    "source_root": str(root),
                    "cache_identity": identity,
                    "dyld_cache_path": str(cache_file),
                    "extract_root": str(extract_root),
                    "resolved_relative_path": relative_candidate.as_posix(),
                }

    raise RuntimeError(f"could not resolve or extract {requested_path}")


def main() -> int:
    if len(sys.argv) < 5:
        print(
            "Usage: ghidra_macos_import_backend.py resolve <requested_path> <source_registry_json> <cache_root> [copy_mode] [source_name] [--no-extract]",
            file=sys.stderr,
        )
        return 1

    mode = sys.argv[1]
    if mode != "resolve":
        print(f"unsupported mode: {mode}", file=sys.stderr)
        return 1

    requested_path = sys.argv[2]
    registry_path = pathlib.Path(sys.argv[3])
    cache_root = pathlib.Path(sys.argv[4])
    copy_mode = sys.argv[5] if len(sys.argv) > 5 else "cache"
    source_name = sys.argv[6] if len(sys.argv) > 6 else ""
    allow_extract = "--no-extract" not in sys.argv[7:]

    registry = load_registry(registry_path)
    try:
        payload = resolve_from_sources(requested_path, cache_root, registry, copy_mode, source_name, allow_extract=allow_extract)
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
