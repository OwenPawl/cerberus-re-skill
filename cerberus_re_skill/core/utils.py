"""Utility functions: JSON read/write, timestamps, name sanitization, flag parsing."""

from __future__ import annotations

import datetime
import json
import os
import re
import tempfile
import uuid
from pathlib import Path
from typing import Any


def utc_now() -> str:
    """Return current UTC time as ISO-8601 string with Z suffix."""
    return (
        datetime.datetime.now(datetime.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def timestamp() -> str:
    """Return a filesystem-safe timestamp string."""
    return datetime.datetime.now().strftime("%Y%m%d-%H%M%S")


def new_uuid() -> str:
    """Return a new lowercase UUID string."""
    return str(uuid.uuid4())


def load_json(path: Path, default: Any = None) -> Any:
    """Load JSON from path, returning default if file does not exist."""
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: Any) -> None:
    """Write payload as JSON to path, creating parent directories as needed."""
    write_json_atomic(path, payload)


def write_json_atomic(
    path: Path,
    payload: Any,
    *,
    indent: int | None = 2,
    ensure_ascii: bool = False,
) -> None:
    """Atomically write a JSON artifact and validate it before replacement."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=str(path.parent),
        text=True,
    )
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=indent, ensure_ascii=ensure_ascii)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        with tmp_path.open("r", encoding="utf-8") as handle:
            json.load(handle)
        os.replace(tmp_path, path)
    except Exception:
        try:
            tmp_path.unlink()
        except FileNotFoundError:
            pass
        raise


def sanitize_name(raw: str) -> str:
    """Sanitize a string into a safe project/file name."""
    raw = Path(raw).stem if "/" in raw or "\\" in raw else raw
    raw = raw.rsplit(".", 1)[0] if "." in raw else raw
    raw = re.sub(r"[\s/:]+", "_", raw)
    raw = re.sub(r"[^a-zA-Z0-9_.\\-]", "", raw)
    return raw or "ghidra_project"


def flag_enabled(value: str | int | bool | None) -> bool:
    """Parse a boolean flag value (env-style: 1/0/true/false/yes/no/on/off)."""
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return bool(value)
    if value is None or value == "":
        return True
    v = str(value).lower()
    if v in {"1", "true", "yes", "on"}:
        return True
    if v in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"unsupported boolean flag value: {value!r}")


def json_from_kv(args: list[str]) -> dict[str, Any]:
    """Convert key=value argument list to a JSON-compatible dict.

    Supports:
      key=value   -> string
      key=true    -> bool
      key=false   -> bool
      key=42      -> int
      key=json:[] -> parsed JSON
      key         -> True (bare key)
    """
    payload: dict[str, Any] = {}
    for arg in args:
        if "=" in arg:
            key, value = arg.split("=", 1)
        else:
            key, value = arg, None
        if not key:
            continue
        if value is None:
            payload[key] = True
        elif value.startswith("json:"):
            payload[key] = json.loads(value[5:])
        elif value == "true":
            payload[key] = True
        elif value == "false":
            payload[key] = False
        elif value.lstrip("-").isdigit():
            payload[key] = int(value)
        else:
            payload[key] = value
    return payload


def extract_selectors_from_json(body: str | dict) -> tuple[str, str, str]:
    """Extract session/project/program selectors from a JSON body string or dict."""
    if isinstance(body, str):
        try:
            payload = json.loads(body)
        except Exception:
            payload = {}
    else:
        payload = body
    session = payload.get("session") or payload.get("session_id") or ""
    project = payload.get("project") or payload.get("project_name") or ""
    program = payload.get("program") or payload.get("program_name") or ""
    return str(session), str(project), str(program)
