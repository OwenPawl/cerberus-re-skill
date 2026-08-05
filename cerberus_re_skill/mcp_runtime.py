"""Execution, evidence-envelope, audit, and policy helpers for Cerberus MCP."""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
import threading
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SUCCESS = "success"
NO_HIT = "no_hit"
BLOCKED = "blocked"
FAILED = "failed"
UNVERIFIED = "unverified"
STATUSES = {SUCCESS, NO_HIT, BLOCKED, FAILED, UNVERIFIED}
STDOUT_CAP = 20_000


@dataclass(frozen=True)
class MCPSettings:
    """Environment-backed MCP configuration with no import-time file writes."""

    cli_command: tuple[str, ...]
    workspace: Path
    state_dir: Path
    jobs_dir: Path
    job_archive_dir: Path
    audit_log: Path
    elicit_timeout: float

    @classmethod
    def from_env(cls) -> MCPSettings:
        override = os.environ.get("CERBERUS_BIN")
        command = tuple(shlex.split(override)) if override else (
            sys.executable,
            "-m",
            "cerberus_re_skill",
        )
        workspace = Path(
            os.environ.get("GHIDRA_WORKSPACE", "~/ghidra-projects")
        ).expanduser()
        state_dir = Path(
            os.environ.get(
                "CERBERUS_MCP_STATE_DIR", str(workspace / ".cerberus-mcp")
            )
        ).expanduser()
        jobs_dir = state_dir / "jobs"
        return cls(
            cli_command=command,
            workspace=workspace,
            state_dir=state_dir,
            jobs_dir=jobs_dir,
            job_archive_dir=jobs_dir / "archive",
            audit_log=state_dir / "audit.jsonl",
            elicit_timeout=float(
                os.environ.get("CERBERUS_MCP_ELICIT_TIMEOUT", "120")
            ),
        )

    def ensure_state(self) -> None:
        for directory in (self.workspace, self.state_dir, self.jobs_dir, self.job_archive_dir):
            directory.mkdir(parents=True, exist_ok=True)


def envelope(
    status: str,
    *,
    command: Sequence[str] | None = None,
    exit_code: int | None = None,
    artifacts: list[str] | None = None,
    warnings: list[str] | None = None,
    stdout: str = "",
    stderr: str = "",
    data: Any = None,
    note: str = "",
) -> dict[str, Any]:
    if status not in STATUSES:
        raise ValueError(f"unsupported MCP status: {status}")
    return {
        "status": status,
        "note": note,
        "artifacts": sorted(set(artifacts or [])),
        "warnings": warnings or [],
        "command": list(command) if command else [],
        "exit_code": exit_code,
        "stdout": stdout[-STDOUT_CAP:],
        "stderr": stderr[-STDOUT_CAP:],
        "data": data,
    }


_ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def parse_json_output(output: str) -> Any:
    """Recover the first JSON value from CLI output that may include Rich prose."""
    clean = _ANSI_RE.sub("", output).strip()
    if not clean:
        return None
    try:
        return json.loads(clean)
    except json.JSONDecodeError:
        pass
    decoder = json.JSONDecoder()
    for index, char in enumerate(clean):
        if char not in "[{":
            continue
        try:
            value, _end = decoder.raw_decode(clean[index:])
        except json.JSONDecodeError:
            continue
        return value
    return None


def make_run_result(
    command: Sequence[str],
    *,
    returncode: int | None,
    stdout: str,
    stderr: str,
    spawn_ok: bool = True,
) -> dict[str, Any]:
    return {
        "_spawn_ok": spawn_ok,
        "cmd": list(command),
        "returncode": returncode,
        "stdout": stdout.strip(),
        "stderr": stderr.strip(),
        "parsed": parse_json_output(stdout),
    }


class CommandRunner:
    def __init__(self, settings: MCPSettings):
        self.settings = settings

    def run(self, args: list[str], timeout: int = 300) -> dict[str, Any]:
        command = [*self.settings.cli_command, *args]
        try:
            process = subprocess.run(
                command,
                cwd=self.settings.workspace,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=False,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            return make_run_result(
                command,
                returncode=None,
                stdout=_coerce_subprocess_text(exc.stdout),
                stderr=f"{_coerce_subprocess_text(exc.stderr)}\ntimeout after {timeout}s",
                spawn_ok=False,
            )
        except (FileNotFoundError, OSError) as exc:
            return make_run_result(
                command,
                returncode=None,
                stdout="",
                stderr=str(exc),
                spawn_ok=False,
            )
        return make_run_result(
            command,
            returncode=process.returncode,
            stdout=process.stdout,
            stderr=process.stderr,
        )

    def artifacts_for(self, project: str, program: str) -> list[str]:
        directory = self.settings.workspace / "exports" / project / program
        if not directory.exists():
            return []
        return sorted(str(path) for path in directory.rglob("*") if path.is_file())

    def wrap(
        self,
        run: dict[str, Any],
        *,
        kind: str = "generic",
        artifacts: list[str] | None = None,
    ) -> dict[str, Any]:
        parsed = run.get("parsed")
        found = list(artifacts or [])
        found.extend(artifact_paths_from_data(parsed))
        return envelope(
            classify(run, kind=kind),
            command=run.get("cmd"),
            exit_code=run.get("returncode"),
            artifacts=found,
            warnings=warning_list(parsed),
            stdout=run.get("stdout", ""),
            stderr=run.get("stderr", ""),
            data=parsed,
        )


def _coerce_subprocess_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


_BLOCK_TOKENS = (
    "attach-failed",
    "attach_failed",
    "spawn-gating",
    "trace_incomplete",
    "permission denied",
    '"status": "blocked"',
)
_NO_HIT_TOKENS = (
    "no-runtime-hits",
    "no_runtime_hits",
    "zero-hit",
    '"status": "no_hit"',
)


def classify(run: dict[str, Any], *, kind: str = "generic") -> str:
    if not run.get("_spawn_ok"):
        return FAILED
    parsed = run.get("parsed")
    stdout = run.get("stdout", "")
    stderr = run.get("stderr", "")
    blob = json.dumps(parsed).lower() if parsed is not None else f"{stdout}\n{stderr}".lower()
    runtime = kind in {"runtime", "frida", "lldb"}
    if run.get("returncode") not in (0, None):
        if runtime and any(token in blob for token in _BLOCK_TOKENS):
            return BLOCKED
        return FAILED
    if isinstance(parsed, dict):
        explicit = parsed.get("status")
        if explicit in STATUSES:
            return str(explicit)
        if parsed.get("ok") is False:
            if runtime and any(token in blob for token in _BLOCK_TOKENS):
                return BLOCKED
            return FAILED
        if runtime:
            if any(token in blob for token in _BLOCK_TOKENS):
                return BLOCKED
            hits = parsed.get("hit_count", parsed.get("runtime_hit_count"))
            if hits == 0 or any(token in blob for token in _NO_HIT_TOKENS):
                return NO_HIT
        warnings = parsed.get("warnings")
        if parsed.get("missing_input_count", 0):
            return UNVERIFIED
        if isinstance(warnings, list) and warnings:
            return UNVERIFIED
        if isinstance(warnings, dict) and any(warnings.values()):
            return UNVERIFIED
    return SUCCESS


def warning_list(parsed: Any) -> list[str]:
    if not isinstance(parsed, dict):
        return []
    warnings = parsed.get("warnings")
    if isinstance(warnings, list):
        return [str(item) for item in warnings]
    if isinstance(warnings, dict):
        return [f"{key}={value}" for key, value in warnings.items() if value]
    return []


_ARTIFACT_KEYS = {
    "artifact",
    "artifacts",
    "json_report",
    "log",
    "log_path",
    "markdown_report",
    "output",
    "output_dir",
    "project_file",
    "runtime_hits",
}


def artifact_paths_from_data(value: Any) -> list[str]:
    found: list[str] = []
    if not isinstance(value, dict):
        return found
    for key, item in value.items():
        if key not in _ARTIFACT_KEYS:
            continue
        if isinstance(item, str) and item:
            found.append(item)
        elif isinstance(item, list):
            found.extend(str(entry) for entry in item if isinstance(entry, str) and entry)
    return found


_AUDIT_LOCK = threading.Lock()


def append_audit(settings: MCPSettings, record: dict[str, Any]) -> None:
    settings.ensure_state()
    payload = {
        "timestamp": datetime.now(UTC).isoformat(),
        **record,
    }
    with _AUDIT_LOCK, settings.audit_log.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, sort_keys=True, default=str) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


BRIDGE_READ_ENDPOINTS = {
    "/health",
    "/session",
    "/context",
    "/analyze/target",
    "/functions/search",
    "/function",
    "/decompile",
    "/references",
    "/data/get",
    "/strings/search",
    "/symbols/get",
    "/symbols/xrefs",
    "/memory/range",
    "/variables",
    "/datatypes/search",
    "/objc/selector-trace",
    "/navigate",
}
BRIDGE_DESTRUCTIVE_PREFIXES = ("/patch/", "/listing/")
BRIDGE_DESTRUCTIVE_ENDPOINTS = {
    "/function/create",
    "/function/delete",
    "/function/fixup",
}


def normalize_endpoint(endpoint: str) -> str:
    return endpoint.strip().lower().split("?", 1)[0].rstrip("/") or "/"


def bridge_tier(endpoint: str) -> str:
    normalized = normalize_endpoint(endpoint)
    if normalized in BRIDGE_READ_ENDPOINTS:
        return "read"
    if normalized in BRIDGE_DESTRUCTIVE_ENDPOINTS or normalized.startswith(
        BRIDGE_DESTRUCTIVE_PREFIXES
    ):
        return "destructive"
    return "write"


_PASSTHROUGH_ALWAYS_BLOCKED = (
    ("bridge", "call"),
    ("bridge", "close"),
    ("validate", "lldb-trace"),
    ("frida", "recheck-attach"),
)
_PASSTHROUGH_OVERRIDEABLE = (
    ("notes",),
    ("publish",),
    ("bridge", "install"),
    ("bridge", "build"),
    ("import", "run-script"),
    ("install",),
)
_GATED_FLAGS = {"--allow-runtime", "--attach-pid", "--attach-name", "--destructive", "--write"}


def passthrough_policy(argv: list[str]) -> tuple[str, str]:
    lowered = [part.lower() for part in argv]
    if not argv:
        return "blocked", "empty argv"
    if any(flag in lowered for flag in _GATED_FLAGS):
        return "blocked", "runtime and bridge mutation flags require a dedicated gated MCP tool"
    if any(lowered[: len(prefix)] == list(prefix) for prefix in _PASSTHROUGH_ALWAYS_BLOCKED):
        return "blocked", "this command requires a dedicated gated MCP tool"
    if any(lowered[: len(prefix)] == list(prefix) for prefix in _PASSTHROUGH_OVERRIDEABLE):
        if os.environ.get("CERBERUS_MCP_ALLOW_UNSAFE_RUN") == "1":
            return "allowed_override", "explicit unsafe passthrough override"
        return "blocked", "network, installer, or arbitrary-script command is not enabled"
    return "allowed", "read-oriented local CLI passthrough"
