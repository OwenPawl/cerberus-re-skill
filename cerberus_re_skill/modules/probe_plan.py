"""Immutable probe plans, helper artifacts, and lifecycle evidence."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Any, Iterable, Mapping

from cerberus_re_skill.core.utils import utc_now, write_json_atomic


PROBE_PLAN_SCHEMA = "ghidra-re.probe-plan.v1"
EXECUTABLE_IDENTITY_SCHEMA = "ghidra-re.probe-executable-identity.v1"
TARGET_IDENTITY_SCHEMA = "ghidra-re.probe-target-identity.v1"
HELPER_IDENTITY_SCHEMA = "ghidra-re.probe-helper-identity.v1"
LIFECYCLE_SCHEMA = "ghidra-re.probe-lifecycle.v1"
LIFECYCLE_EVENT_SCHEMA = "ghidra-re.probe-lifecycle-event.v1"

TRANSPORTS = frozenset({"lldb", "frida"})
TRANSPORT_MODES = frozenset({"attach", "await", "launch"})
DETACH_POLICIES = frozenset({"always", "never", "on-success"})
KILL_POLICIES = frozenset({"never", "owned-only-always", "owned-only-on-timeout"})
LIFECYCLE_PHASES = frozenset(
    {"preflight", "attach", "launch", "hit", "detach", "liveness", "crash", "relaunch"}
)
LIFECYCLE_OUTCOMES = frozenset(
    {"started", "succeeded", "failed", "timed_out", "observed", "not_observed", "skipped"}
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_CONTENT_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_HELPER_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")


class ProbePlanError(ValueError):
    """Raised when a plan or lifecycle record is malformed."""


class ProbePlanIntegrityError(RuntimeError):
    """Raised when immutable content does not match its identity."""


def build_executable_identity(
    path: str | Path,
    *,
    sha256: str | None = None,
    size: int | None = None,
    architecture: str = "",
    object_uuid: str = "",
) -> dict[str, Any]:
    """Bind an executable locator to a stable content identity."""
    executable_path = _absolute_path(path, field="executable path")
    if sha256 is None:
        source = Path(executable_path)
        if not source.is_file():
            raise ProbePlanError(f"executable does not exist: {source}")
        sha256 = _sha256_file(source)
        size = source.stat().st_size
    else:
        sha256 = _validated_sha256(sha256, field="executable sha256")
        source = Path(executable_path)
        if source.is_file():
            actual_size = source.stat().st_size
            actual_sha256 = _sha256_file(source)
            if size is not None and size != actual_size:
                raise ProbePlanIntegrityError("executable size does not match the file")
            if sha256 != actual_sha256:
                raise ProbePlanIntegrityError("executable SHA-256 does not match the file")
            size = actual_size
        elif size is None:
            raise ProbePlanError("executable size is required when the file is unavailable")
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        raise ProbePlanError("executable size must be a non-negative integer")

    identity_material = {
        "architecture": str(architecture),
        "object_uuid": str(object_uuid).lower(),
        "sha256": sha256,
        "size": size,
    }
    return {
        "schema": EXECUTABLE_IDENTITY_SCHEMA,
        "executable_id": _content_id(identity_material),
        "path": executable_path,
        **identity_material,
    }


def build_target_identity(
    stable_key: str,
    executable: Mapping[str, Any],
    *,
    display_name: str = "",
    platform: str = "",
    architecture: str = "",
) -> dict[str, Any]:
    """Bind a caller-supplied stable target key to an executable identity."""
    stable_key = str(stable_key).strip()
    if not stable_key:
        raise ProbePlanError("target stable_key must not be empty")
    executable_record = _validated_executable_identity(executable)
    identity_material = {
        "architecture": str(architecture),
        "executable_id": executable_record["executable_id"],
        "platform": str(platform),
        "stable_key": stable_key,
    }
    return {
        "schema": TARGET_IDENTITY_SCHEMA,
        "target_id": _content_id(identity_material),
        "stable_key": stable_key,
        "display_name": str(display_name),
        "platform": str(platform),
        "architecture": str(architecture),
        "executable": executable_record,
    }


def materialize_helper(
    root: str | Path,
    name: str,
    content: str | bytes,
    *,
    executable: bool = False,
) -> dict[str, Any]:
    """Atomically publish helper content at an immutable SHA-256 path."""
    helper_name = _validated_helper_name(name)
    payload = content.encode("utf-8") if isinstance(content, str) else bytes(content)
    digest = hashlib.sha256(payload).hexdigest()
    root_path = Path(_absolute_path(root, field="helper root"))
    destination = root_path / "sha256" / digest[:2] / digest / helper_name
    destination.parent.mkdir(parents=True, exist_ok=True)
    immutable_mode = 0o555 if executable else 0o444

    if destination.exists() or destination.is_symlink():
        _verify_helper_content(destination, digest, len(payload), executable)
        return _helper_identity(destination, helper_name, digest, len(payload), executable)

    fd, tmp_name = tempfile.mkstemp(prefix=f".{helper_name}.", suffix=".tmp", dir=destination.parent)
    tmp_path = Path(tmp_name)
    published = False
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        tmp_path.chmod(immutable_mode)
        try:
            os.link(tmp_path, destination)
            published = True
        except FileExistsError:
            _verify_helper_content(destination, digest, len(payload), executable)
        _fsync_directory(destination.parent)
    finally:
        try:
            tmp_path.unlink()
        except FileNotFoundError:
            pass
        except PermissionError:
            # Windows refuses to unlink a read-only hard link. The temp is ours;
            # restore the published link's immutable mode after retrying cleanup.
            tmp_path.chmod(0o600)
            tmp_path.unlink()
            if published:
                destination.chmod(immutable_mode)

    _verify_helper_content(destination, digest, len(payload), executable)
    return _helper_identity(destination, helper_name, digest, len(payload), executable)


def build_probe_plan(
    target: Mapping[str, Any],
    *,
    transport: str,
    mode: str,
    timeout_seconds: int,
    detach_policy: str,
    kill_policy: str,
    expected_signals: Iterable[str] = (),
    helpers: Iterable[Mapping[str, Any]] = (),
    outputs: Mapping[str, str | Path],
) -> dict[str, Any]:
    """Build a normalized, deterministic probe plan."""
    target_record = _validated_target_identity(target)
    transport = str(transport).lower()
    mode = str(mode).lower()
    detach_policy = str(detach_policy).lower()
    kill_policy = str(kill_policy).lower()
    if transport not in TRANSPORTS:
        raise ProbePlanError(f"transport must be one of {sorted(TRANSPORTS)}")
    if mode not in TRANSPORT_MODES:
        raise ProbePlanError(f"transport mode must be one of {sorted(TRANSPORT_MODES)}")
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int) or timeout_seconds <= 0:
        raise ProbePlanError("timeout_seconds must be a positive integer")
    if detach_policy not in DETACH_POLICIES:
        raise ProbePlanError(f"detach_policy must be one of {sorted(DETACH_POLICIES)}")
    if kill_policy not in KILL_POLICIES:
        raise ProbePlanError(f"kill_policy must be one of {sorted(KILL_POLICIES)}")

    helper_records = [_validated_helper_identity(item) for item in helpers]
    helper_records.sort(key=lambda item: (item["name"], item["sha256"]))
    helper_names = [item["name"] for item in helper_records]
    if len(helper_names) != len(set(helper_names)):
        raise ProbePlanError("helper names must be unique within a plan")

    output_records: dict[str, str] = {}
    for name, path in sorted(outputs.items()):
        output_name = str(name).strip()
        if not output_name:
            raise ProbePlanError("output names must not be empty")
        output_records[output_name] = _absolute_path(path, field=f"output {output_name}")
    if not output_records:
        raise ProbePlanError("at least one output path is required")

    signals = sorted({str(signal).strip() for signal in expected_signals if str(signal).strip()})
    body = {
        "schema": PROBE_PLAN_SCHEMA,
        "target": target_record,
        "transport": {"engine": transport, "mode": mode},
        "timeout_seconds": timeout_seconds,
        "process_policy": {"detach": detach_policy, "kill": kill_policy},
        "expected_signals": signals,
        "helpers": helper_records,
        "outputs": output_records,
    }
    return {"plan_id": _content_id(body), **body}


def verify_probe_plan(plan: Mapping[str, Any]) -> dict[str, Any]:
    """Validate a plan and return its normalized representation."""
    expected_keys = {
        "plan_id",
        "schema",
        "target",
        "transport",
        "timeout_seconds",
        "process_policy",
        "expected_signals",
        "helpers",
        "outputs",
    }
    if set(plan) != expected_keys:
        raise ProbePlanError("probe plan fields do not match the v1 schema")
    if plan.get("schema") != PROBE_PLAN_SCHEMA:
        raise ProbePlanError(f"probe plan schema must be {PROBE_PLAN_SCHEMA!r}")
    transport = plan.get("transport")
    policy = plan.get("process_policy")
    if not isinstance(transport, Mapping) or not isinstance(policy, Mapping):
        raise ProbePlanError("transport and process_policy must be objects")
    normalized = build_probe_plan(
        _mapping(plan.get("target"), field="target"),
        transport=str(transport.get("engine") or ""),
        mode=str(transport.get("mode") or ""),
        timeout_seconds=plan.get("timeout_seconds"),
        detach_policy=str(policy.get("detach") or ""),
        kill_policy=str(policy.get("kill") or ""),
        expected_signals=_sequence(plan.get("expected_signals"), field="expected_signals"),
        helpers=_sequence(plan.get("helpers"), field="helpers"),
        outputs=_mapping(plan.get("outputs"), field="outputs"),
    )
    if plan.get("plan_id") != normalized["plan_id"]:
        raise ProbePlanIntegrityError("probe plan ID does not match its content")
    if _canonical_bytes(plan) != _canonical_bytes(normalized):
        raise ProbePlanError("probe plan is not normalized")
    return normalized


def write_probe_plan(path: str | Path, plan: Mapping[str, Any]) -> Path:
    """Validate and atomically write a probe plan."""
    destination = Path(_absolute_path(path, field="plan output"))
    write_json_atomic(destination, verify_probe_plan(plan))
    return destination


def write_probe_lifecycle(path: str | Path, lifecycle: Mapping[str, Any]) -> Path:
    """Validate and atomically write a probe lifecycle ledger."""
    _validate_lifecycle(lifecycle)
    destination = Path(_absolute_path(path, field="lifecycle output"))
    write_json_atomic(destination, lifecycle)
    return destination


def new_probe_lifecycle(plan_id: str) -> dict[str, Any]:
    """Create an empty lifecycle ledger for a probe plan."""
    _validated_content_id(plan_id, field="plan_id")
    return {"schema": LIFECYCLE_SCHEMA, "plan_id": plan_id, "events": []}


def record_lifecycle_event(
    lifecycle: dict[str, Any],
    phase: str,
    outcome: str,
    *,
    observed_at: str | None = None,
    details: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Append one independent lifecycle observation."""
    _validate_lifecycle(lifecycle)
    phase = str(phase).lower()
    outcome = str(outcome).lower()
    if phase not in LIFECYCLE_PHASES:
        raise ProbePlanError(f"lifecycle phase must be one of {sorted(LIFECYCLE_PHASES)}")
    if outcome not in LIFECYCLE_OUTCOMES:
        raise ProbePlanError(f"lifecycle outcome must be one of {sorted(LIFECYCLE_OUTCOMES)}")
    detail_record = _json_object(details or {}, field="details")
    sequence = len(lifecycle["events"]) + 1
    event_body = {
        "schema": LIFECYCLE_EVENT_SCHEMA,
        "sequence": sequence,
        "phase": phase,
        "outcome": outcome,
        "observed_at": str(observed_at or utc_now()),
        "details": detail_record,
    }
    event = {"event_id": _content_id({"plan_id": lifecycle["plan_id"], **event_body}), **event_body}
    lifecycle["events"].append(event)
    return event


def summarize_probe_lifecycle(lifecycle: Mapping[str, Any]) -> dict[str, Any]:
    """Summarize observations without treating timeout as a no-hit result."""
    _validate_lifecycle(lifecycle)
    events = lifecycle["events"]
    hit_observed = any(event["phase"] == "hit" and event["outcome"] == "observed" for event in events)
    no_hit_explicit = any(
        event["phase"] == "hit" and event["outcome"] == "not_observed" for event in events
    )
    timed_out = any(event["outcome"] == "timed_out" for event in events)
    crash_observed = any(
        event["phase"] == "crash" and event["outcome"] == "observed" for event in events
    )
    relaunched = any(
        event["phase"] == "relaunch" and event["outcome"] == "succeeded" for event in events
    )
    failed = any(event["outcome"] == "failed" for event in events)
    if hit_observed and crash_observed:
        status = "hit_then_crash"
    elif crash_observed:
        status = "crash"
    elif hit_observed:
        status = "hit"
    elif timed_out:
        status = "timeout"
    elif no_hit_explicit:
        status = "no_hit"
    elif failed:
        status = "failed"
    else:
        status = "incomplete"
    return {
        "schema": LIFECYCLE_SCHEMA,
        "plan_id": lifecycle["plan_id"],
        "status": status,
        "event_count": len(events),
        "hit_observed": hit_observed,
        "no_hit_explicit": no_hit_explicit,
        "timed_out": timed_out,
        "crash_observed": crash_observed,
        "relaunched": relaunched,
    }


def _validated_executable_identity(identity: Mapping[str, Any]) -> dict[str, Any]:
    record = _json_object(identity, field="executable identity")
    if record.get("schema") != EXECUTABLE_IDENTITY_SCHEMA:
        raise ProbePlanError("unexpected executable identity schema")
    normalized = build_executable_identity(
        record.get("path", ""),
        sha256=str(record.get("sha256") or ""),
        size=record.get("size"),
        architecture=str(record.get("architecture") or ""),
        object_uuid=str(record.get("object_uuid") or ""),
    )
    if record.get("executable_id") != normalized["executable_id"]:
        raise ProbePlanIntegrityError("executable identity ID does not match its content")
    if _canonical_bytes(record) != _canonical_bytes(normalized):
        raise ProbePlanError("executable identity is not normalized")
    return normalized


def _validated_target_identity(identity: Mapping[str, Any]) -> dict[str, Any]:
    record = _json_object(identity, field="target identity")
    if record.get("schema") != TARGET_IDENTITY_SCHEMA:
        raise ProbePlanError("unexpected target identity schema")
    normalized = build_target_identity(
        str(record.get("stable_key") or ""),
        _mapping(record.get("executable"), field="target executable"),
        display_name=str(record.get("display_name") or ""),
        platform=str(record.get("platform") or ""),
        architecture=str(record.get("architecture") or ""),
    )
    if record.get("target_id") != normalized["target_id"]:
        raise ProbePlanIntegrityError("target identity ID does not match its content")
    if _canonical_bytes(record) != _canonical_bytes(normalized):
        raise ProbePlanError("target identity is not normalized")
    return normalized


def _validated_helper_identity(identity: Mapping[str, Any]) -> dict[str, Any]:
    record = _json_object(identity, field="helper identity")
    if record.get("schema") != HELPER_IDENTITY_SCHEMA:
        raise ProbePlanError("unexpected helper identity schema")
    name = _validated_helper_name(str(record.get("name") or ""))
    digest = _validated_sha256(str(record.get("sha256") or ""), field="helper sha256")
    size = record.get("size")
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        raise ProbePlanError("helper size must be a non-negative integer")
    path = _absolute_path(record.get("path", ""), field="helper path")
    executable = record.get("executable")
    if not isinstance(executable, bool):
        raise ProbePlanError("helper executable must be boolean")
    normalized = _helper_identity(Path(path), name, digest, size, executable)
    if record.get("helper_id") != normalized["helper_id"]:
        raise ProbePlanIntegrityError("helper identity ID does not match its content")
    if _canonical_bytes(record) != _canonical_bytes(normalized):
        raise ProbePlanError("helper identity is not normalized")
    return normalized


def _helper_identity(
    path: Path,
    name: str,
    digest: str,
    size: int,
    executable: bool,
) -> dict[str, Any]:
    return {
        "schema": HELPER_IDENTITY_SCHEMA,
        "helper_id": f"sha256:{digest}",
        "name": name,
        "sha256": digest,
        "size": size,
        "executable": executable,
        "path": str(path),
    }


def _verify_helper_content(path: Path, digest: str, size: int, executable: bool) -> None:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError as exc:
        raise ProbePlanIntegrityError(f"helper disappeared during publication: {path}") from exc
    if not stat.S_ISREG(mode):
        raise ProbePlanIntegrityError(f"helper content path is not a regular file: {path}")
    if path.stat().st_size != size or _sha256_file(path) != digest:
        raise ProbePlanIntegrityError(f"helper content conflicts with its SHA-256 path: {path}")
    if mode & 0o222:
        raise ProbePlanIntegrityError(f"helper content path is writable: {path}")
    actual_executable = bool(mode & 0o111)
    if actual_executable != executable:
        raise ProbePlanIntegrityError(f"helper executable mode conflicts with its identity: {path}")


def _validate_lifecycle(lifecycle: Mapping[str, Any]) -> None:
    if lifecycle.get("schema") != LIFECYCLE_SCHEMA:
        raise ProbePlanError("unexpected lifecycle schema")
    _validated_content_id(str(lifecycle.get("plan_id") or ""), field="plan_id")
    events = lifecycle.get("events")
    if not isinstance(events, list):
        raise ProbePlanError("lifecycle events must be a list")
    for index, event in enumerate(events, start=1):
        if not isinstance(event, Mapping):
            raise ProbePlanError("lifecycle events must be objects")
        if set(event) != {
            "event_id",
            "schema",
            "sequence",
            "phase",
            "outcome",
            "observed_at",
            "details",
        }:
            raise ProbePlanError("lifecycle event fields do not match the v1 schema")
        if event.get("schema") != LIFECYCLE_EVENT_SCHEMA or event.get("sequence") != index:
            raise ProbePlanError("lifecycle event sequence or schema is invalid")
        if event.get("phase") not in LIFECYCLE_PHASES or event.get("outcome") not in LIFECYCLE_OUTCOMES:
            raise ProbePlanError("lifecycle event phase or outcome is invalid")
        if not isinstance(event.get("observed_at"), str) or not event.get("observed_at"):
            raise ProbePlanError("lifecycle event observed_at must be a non-empty string")
        _json_object(event.get("details"), field="lifecycle event details")
        event_body = {key: value for key, value in event.items() if key != "event_id"}
        expected_id = _content_id({"plan_id": lifecycle["plan_id"], **event_body})
        if event.get("event_id") != expected_id:
            raise ProbePlanIntegrityError("lifecycle event ID does not match its content")


def _validated_helper_name(name: str) -> str:
    name = str(name).strip()
    if name in {"", ".", ".."} or not _HELPER_NAME_RE.fullmatch(name):
        raise ProbePlanError("helper name must contain only letters, digits, dot, underscore, or dash")
    return name


def _absolute_path(path: str | Path, *, field: str) -> str:
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        raise ProbePlanError(f"{field} must be absolute")
    return os.path.normpath(str(candidate))


def _validated_sha256(value: str, *, field: str) -> str:
    value = str(value).lower()
    if not _SHA256_RE.fullmatch(value):
        raise ProbePlanError(f"{field} must be 64 lowercase hexadecimal characters")
    return value


def _validated_content_id(value: str, *, field: str) -> str:
    if not _CONTENT_ID_RE.fullmatch(value):
        raise ProbePlanError(f"{field} must be a sha256 content ID")
    return value


def _mapping(value: Any, *, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ProbePlanError(f"{field} must be an object")
    return value


def _sequence(value: Any, *, field: str) -> list[Any]:
    if not isinstance(value, list):
        raise ProbePlanError(f"{field} must be a list")
    return value


def _json_object(value: Mapping[str, Any], *, field: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProbePlanError(f"{field} must be an object")
    try:
        normalized = json.loads(json.dumps(dict(value), sort_keys=True, allow_nan=False))
    except (TypeError, ValueError) as exc:
        raise ProbePlanError(f"{field} must contain only JSON values") from exc
    if not isinstance(normalized, dict):
        raise ProbePlanError(f"{field} must be an object")
    return normalized


def _content_id(payload: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(_canonical_bytes(payload)).hexdigest()


def _canonical_bytes(payload: Any) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
