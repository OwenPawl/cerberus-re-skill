"""Source registry support for source:name:/path imports."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from cerberus_re_skill.core.config import cfg


def init_registry() -> Path:
    path = cfg.source_registry_file
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        _write_registry(path, {"version": 1, "sources": []})
    return path


def list_sources() -> dict[str, Any]:
    path = init_registry()
    payload = _load_registry(path)
    return {"ok": True, "registry": str(path), "sources": payload.get("sources", [])}


def add_source(
    name: str,
    root: str | Path,
    *,
    platform: str = "macos-image",
    copy: str = "cache",
) -> dict[str, Any]:
    if not name:
        raise RuntimeError("source name is required")
    root_path = Path(root).expanduser()
    if not root_path.exists():
        raise RuntimeError(f"source root not found: {root_path}")
    if copy not in {"cache", "direct"}:
        raise RuntimeError("copy must be 'cache' or 'direct'")
    path = init_registry()
    payload = _load_registry(path)
    sources = [item for item in payload.get("sources", []) if item.get("name") != name]
    record = {"name": name, "root": str(root_path), "platform": platform, "copy": copy}
    sources.append(record)
    sources.sort(key=lambda item: item.get("name", ""))
    payload = {"version": 1, "sources": sources}
    _write_registry(path, payload)
    return {"ok": True, "registry": str(path), "source": record}


def resolve_source(
    name: str,
    requested_path: str,
    *,
    copy: str = "",
    no_extract: bool = False,
) -> dict[str, Any]:
    if not name:
        raise RuntimeError("source name is required")
    path = init_registry()
    payload = _load_registry(path)
    source = next((item for item in payload.get("sources", []) if item.get("name") == name), None)
    if not source:
        raise RuntimeError(f"source not found: {name}")
    copy_mode = copy or source.get("copy", "cache") or "cache"
    backend = cfg.skill_root / "scripts" / "ghidra_macos_import_backend.py"
    command = [
        sys.executable,
        str(backend),
        "resolve",
        requested_path,
        str(path),
        str(cfg.sources_cache_dir),
        copy_mode,
        name,
    ]
    if no_extract:
        command.append("--no-extract")
    result = subprocess.run(
        command,
        shell=False,
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        detail = result.stderr.decode(errors="replace").strip() or result.stdout.decode(errors="replace").strip()
        raise RuntimeError(detail or f"source resolve failed with exit code {result.returncode}")
    resolved = json.loads(result.stdout.decode(errors="replace"))
    return {"ok": True, "registry": str(path), "source": source, "resolution": resolved}


def _load_registry(path: Path) -> dict[str, Any]:
    text = ""
    try:
        text = path.read_text(encoding="utf-8")
        payload = json.loads(text)
    except Exception:
        payload = _load_recoverable_registry_prefix(text)
    if isinstance(payload, list):
        payload = {"version": 1, "sources": payload}
    elif not isinstance(payload, dict):
        payload = {"version": 1, "sources": []}
    payload.setdefault("version", 1)
    sources = payload.get("sources", [])
    if not isinstance(sources, list):
        sources = []
    payload["sources"] = [item for item in sources if isinstance(item, dict) and item.get("name")]
    return payload


def _load_recoverable_registry_prefix(text: str) -> Any:
    if not text.strip():
        return {"version": 1, "sources": []}
    try:
        payload, _end = json.JSONDecoder().raw_decode(text)
        return payload
    except Exception:
        return {"version": 1, "sources": []}


def _write_registry(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)
