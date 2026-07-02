"""Per-project lock coordination for Ghidra headless operations."""

from __future__ import annotations

import json
import os
import shutil
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from cerberus_re_skill.core.config import cfg
from cerberus_re_skill.core.utils import sanitize_name, utc_now


DEFAULT_TIMEOUT_SECONDS = 600
DEFAULT_STALE_SECONDS = 1800


def lock_path(project_name: str, project_location: str | Path | None = None) -> Path:
    key_source = str(project_location or project_name)
    key = sanitize_name(key_source)
    return cfg.config_home / "headless-locks" / f"{key}.lockdir"


@contextmanager
def project_headless_lock(
    project_name: str,
    project_location: str | Path | None = None,
    *,
    operation: str = "headless",
    timeout_seconds: int | None = None,
    stale_seconds: int | None = None,
) -> Iterator[Path]:
    path = acquire_project_headless_lock(
        project_name,
        project_location,
        operation=operation,
        timeout_seconds=timeout_seconds,
        stale_seconds=stale_seconds,
    )
    try:
        yield path
    finally:
        release_project_headless_lock(path)


def acquire_project_headless_lock(
    project_name: str,
    project_location: str | Path | None = None,
    *,
    operation: str = "headless",
    timeout_seconds: int | None = None,
    stale_seconds: int | None = None,
) -> Path:
    timeout = _int_env("GHIDRA_HEADLESS_LOCK_TIMEOUT", timeout_seconds, DEFAULT_TIMEOUT_SECONDS)
    stale_after = _int_env("GHIDRA_HEADLESS_LOCK_STALE_SECONDS", stale_seconds, DEFAULT_STALE_SECONDS)
    path = lock_path(project_name, project_location)
    path.parent.mkdir(parents=True, exist_ok=True)
    started = time.time()
    while True:
        try:
            path.mkdir()
            _write_metadata(path, project_name, project_location, operation)
            return path
        except FileExistsError:
            if _is_stale(path, stale_after):
                shutil.rmtree(path, ignore_errors=True)
                continue
            if time.time() - started >= timeout:
                raise RuntimeError(
                    f"timed out waiting for Ghidra headless project lock at {path}; "
                    "avoid running same-project headless operations in parallel"
                )
            time.sleep(1)


def release_project_headless_lock(path: str | Path) -> None:
    shutil.rmtree(Path(path), ignore_errors=True)


def _write_metadata(
    path: Path,
    project_name: str,
    project_location: str | Path | None,
    operation: str,
) -> None:
    payload = {
        "project_name": project_name,
        "project_location": str(project_location or ""),
        "operation": operation,
        "pid": os.getpid(),
        "created_at": utc_now(),
    }
    (path / "owner.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _is_stale(path: Path, stale_seconds: int) -> bool:
    try:
        return (time.time() - path.stat().st_mtime) >= stale_seconds
    except FileNotFoundError:
        return False


def _int_env(name: str, value: int | None, default: int) -> int:
    if value is not None:
        return int(value)
    raw = os.environ.get(name)
    if raw:
        try:
            return int(raw)
        except ValueError:
            return default
    return default
