"""Transactional, content-addressed mission checkpoints and bounded resume packs."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping, Protocol, runtime_checkable


CHECKPOINT_SCHEMA = "cerberus.re.checkpoint.v1"
RESUME_PACK_SCHEMA = "cerberus.re.resume-pack.v1"
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SECRET_KEYS = {"authorization", "password", "secret", "token"}


class CheckpointError(RuntimeError):
    """Raised when checkpoint state is invalid, conflicting, or corrupt."""


@runtime_checkable
class CheckpointProvider(Protocol):
    """External state adapter used by :class:`CheckpointCoordinator`."""

    name: str

    def prepare(self, transaction_id: str) -> Mapping[str, Any]: ...

    def checkpoint(self, transaction_id: str) -> Mapping[str, Any]: ...

    def verify(
        self, transaction_id: str, payload: Mapping[str, Any]
    ) -> Mapping[str, Any]: ...

    def restore(
        self, transaction_id: str, payload: Mapping[str, Any]
    ) -> Mapping[str, Any]: ...


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as error:
        raise CheckpointError(f"invalid JSON at {path}: {error}") from error
    if not isinstance(value, dict):
        raise CheckpointError(f"expected JSON object at {path}")
    return value


def _validate_id(label: str, value: str) -> str:
    if not _SAFE_ID.fullmatch(value):
        raise CheckpointError(f"invalid {label}: {value!r}")
    return value


def _validate_sha256(label: str, value: str) -> str:
    normalized = value.lower()
    if not _SHA256.fullmatch(normalized):
        raise CheckpointError(f"{label} must be a lowercase SHA-256 digest")
    return normalized


def _validate_target(target: Mapping[str, Any]) -> dict[str, Any]:
    project_id = str(target.get("project_id") or "")
    project_path = str(target.get("project_path") or "")
    program_path = str(target.get("program_path") or "")
    executable_sha256 = str(target.get("executable_sha256") or "")
    if not project_id and not project_path:
        raise CheckpointError("target requires project_id or project_path")
    if not program_path:
        raise CheckpointError("target requires program_path")
    _validate_sha256("target.executable_sha256", executable_sha256)
    return dict(target)


def _validate_dependencies(dependencies: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in dependencies:
        dependency = dict(item)
        dependency_id = _validate_id("dependency id", str(dependency.get("id") or ""))
        if dependency_id in seen:
            raise CheckpointError(f"duplicate dependency id: {dependency_id}")
        seen.add(dependency_id)
        if not str(dependency.get("kind") or ""):
            raise CheckpointError(f"dependency {dependency_id} requires kind")
        _validate_sha256(
            f"dependency {dependency_id} content_sha256",
            str(dependency.get("content_sha256") or ""),
        )
        if not str(dependency.get("verification") or ""):
            raise CheckpointError(f"dependency {dependency_id} requires verification")
        output.append(dependency)
    return sorted(output, key=lambda item: str(item["id"]))


def _reject_secrets(value: Any, path: str = "payload") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if str(key).lower() in _SECRET_KEYS:
                raise CheckpointError(f"secret-bearing field is not checkpointable: {path}.{key}")
            _reject_secrets(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_secrets(child, f"{path}[{index}]")


@contextmanager
def _exclusive_lock(path: Path) -> Iterator[None]:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        if os.name == "nt":
            import msvcrt

            os.write(descriptor, b"\0") if os.fstat(descriptor).st_size == 0 else None
            os.lseek(descriptor, 0, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        if os.name == "nt":
            import msvcrt

            os.lseek(descriptor, 0, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _atomic_write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = _canonical_bytes(value)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def _write_immutable(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            if path.read_bytes() != payload:
                raise CheckpointError(f"conflicting immutable record: {path}")
    finally:
        Path(temporary).unlink(missing_ok=True)


class CheckpointStore:
    """Append-only mission transaction store with a mutable atomic head pointer."""

    def __init__(self, root: str | Path):
        self.root = Path(root).expanduser().resolve()

    def _transaction(self, transaction_id: str) -> Path:
        return self.root / _validate_id("transaction id", transaction_id)

    def _head(self, transaction: Path) -> dict[str, Any] | None:
        path = transaction / "HEAD.json"
        return _load_json(path) if path.exists() else None

    def _put_object(self, transaction: Path, kind: str, value: Any) -> dict[str, Any]:
        _reject_secrets(value)
        payload = _canonical_bytes(value)
        digest = _digest_bytes(payload)
        path = transaction / "objects" / kind / f"{digest}.json"
        if path.exists():
            if path.read_bytes() != payload:
                raise CheckpointError(f"corrupt content-addressed object: {path}")
        else:
            _write_immutable(path, payload)
        return {
            "kind": kind,
            "sha256": digest,
            "path": path.relative_to(transaction).as_posix(),
        }

    def _read_object(self, transaction: Path, reference: Mapping[str, Any]) -> dict[str, Any]:
        relative = str(reference.get("path") or "")
        path = (transaction / relative).resolve()
        if not path.is_relative_to(transaction.resolve()):
            raise CheckpointError(f"object path escapes transaction: {relative}")
        payload = path.read_bytes() if path.is_file() else b""
        expected = _validate_sha256("object sha256", str(reference.get("sha256") or ""))
        if _digest_bytes(payload) != expected:
            raise CheckpointError(f"object digest mismatch: {relative}")
        return _load_json(path)

    def _append_event(
        self,
        transaction: Path,
        event_kind: str,
        fields: Mapping[str, Any],
        expected_generation: int | None = None,
    ) -> dict[str, Any]:
        with _exclusive_lock(transaction / ".checkpoint.lock"):
            head = self._head(transaction)
            generation = int(head.get("generation", 0)) + 1 if head else 1
            if expected_generation is not None and generation - 1 != expected_generation:
                raise CheckpointError(
                    f"checkpoint generation changed: expected {expected_generation}, "
                    f"found {generation - 1}"
                )
            event = {
                "schema_version": CHECKPOINT_SCHEMA,
                "transaction_id": transaction.name,
                "generation": generation,
                "event": event_kind,
                "created_at": _utc_now(),
                "previous_event_sha256": str(head.get("event_sha256") or "") if head else "",
                **dict(fields),
            }
            payload = _canonical_bytes(event)
            event_digest = _digest_bytes(payload)
            event_path = transaction / "events" / f"{generation:08d}-{event_kind}-{event_digest}.json"
            if event_path.exists():
                raise CheckpointError(f"event already exists: {event_path}")
            _write_immutable(event_path, payload)
            _atomic_write(
                transaction / "HEAD.json",
                {
                    "schema_version": CHECKPOINT_SCHEMA,
                    "transaction_id": transaction.name,
                    "generation": generation,
                    "event": event_kind,
                    "event_sha256": event_digest,
                    "event_path": event_path.relative_to(transaction).as_posix(),
                },
            )
            return {**event, "event_sha256": event_digest}

    def prepare(
        self,
        transaction_id: str,
        *,
        mission_id: str,
        target: Mapping[str, Any],
        dependencies: list[Mapping[str, Any]],
        providers: Mapping[str, Mapping[str, Any]] | None = None,
    ) -> dict[str, Any]:
        transaction = self._transaction(transaction_id)
        transaction.mkdir(parents=True, exist_ok=True)
        if self._head(transaction) is not None:
            raise CheckpointError(f"transaction already prepared: {transaction_id}")
        identity = {
            "schema_version": CHECKPOINT_SCHEMA,
            "transaction_id": transaction_id,
            "mission_id": _validate_id("mission id", mission_id),
            "target": _validate_target(target),
            "dependencies": _validate_dependencies(dependencies),
            "providers": {
                _validate_id("provider name", name): dict(value)
                for name, value in sorted((providers or {}).items())
            },
        }
        identity_ref = self._put_object(transaction, "identity", identity)
        return self._append_event(transaction, "prepared", {"identity": identity_ref})

    def checkpoint(
        self,
        transaction_id: str,
        *,
        routing: Mapping[str, Any],
        provider_payloads: Mapping[str, Mapping[str, Any]],
        expected_generation: int | None = None,
    ) -> dict[str, Any]:
        transaction = self._transaction(transaction_id)
        head = self._head(transaction)
        if head is None:
            raise CheckpointError(f"transaction is not prepared: {transaction_id}")
        identity = self.restore(transaction_id)["identity"]
        expected_providers = set(identity.get("providers", {}))
        supplied_providers = set(provider_payloads)
        if expected_providers != supplied_providers:
            raise CheckpointError(
                f"provider set changed: expected {sorted(expected_providers)}, "
                f"received {sorted(supplied_providers)}"
            )
        routing_ref = self._put_object(transaction, "routing", dict(routing))
        provider_refs = {
            name: self._put_object(transaction, f"provider-{name}", dict(payload))
            for name, payload in sorted(provider_payloads.items())
        }
        return self._append_event(
            transaction,
            "checkpointed",
            {"routing": routing_ref, "provider_payloads": provider_refs},
            expected_generation,
        )

    def _events(self, transaction: Path) -> list[tuple[dict[str, Any], str]]:
        events: list[tuple[dict[str, Any], str]] = []
        for path in sorted((transaction / "events").glob("*.json")):
            payload = path.read_bytes()
            events.append((_load_json(path), _digest_bytes(payload)))
        return events

    def _committed_events(self, transaction: Path) -> list[tuple[dict[str, Any], str]]:
        head = self._head(transaction)
        if head is None:
            return []
        by_digest = {digest: (event, digest) for event, digest in self._events(transaction)}
        digest = str(head.get("event_sha256") or "")
        reversed_chain: list[tuple[dict[str, Any], str]] = []
        visited: set[str] = set()
        while digest:
            if digest in visited:
                raise CheckpointError("checkpoint event chain is cyclic")
            visited.add(digest)
            record = by_digest.get(digest)
            if record is None:
                raise CheckpointError("checkpoint HEAD references a missing or corrupt event")
            reversed_chain.append(record)
            digest = str(record[0].get("previous_event_sha256") or "")
        return list(reversed(reversed_chain))

    def verify(self, transaction_id: str) -> dict[str, Any]:
        transaction = self._transaction(transaction_id)
        head = self._head(transaction)
        if head is None:
            raise CheckpointError(f"transaction is not prepared: {transaction_id}")
        events = self._committed_events(transaction)
        previous = ""
        for index, (event, digest) in enumerate(events, start=1):
            if int(event.get("generation", 0)) != index:
                raise CheckpointError("checkpoint event generation is not contiguous")
            if str(event.get("previous_event_sha256") or "") != previous:
                raise CheckpointError("checkpoint event chain is broken")
            for key in ("identity", "routing"):
                if isinstance(event.get(key), dict):
                    self._read_object(transaction, event[key])
            for reference in event.get("provider_payloads", {}).values():
                self._read_object(transaction, reference)
            previous = digest
        if not events or previous != str(head.get("event_sha256") or ""):
            raise CheckpointError("checkpoint HEAD does not match the event chain")
        return {
            "ok": True,
            "schema_version": CHECKPOINT_SCHEMA,
            "transaction_id": transaction_id,
            "generation": int(head["generation"]),
            "event": head["event"],
            "event_sha256": head["event_sha256"],
        }

    def restore(self, transaction_id: str) -> dict[str, Any]:
        transaction = self._transaction(transaction_id)
        self.verify(transaction_id)
        events = self._committed_events(transaction)
        prepared = events[0][0]
        latest = events[-1][0]
        restored = {
            "schema_version": CHECKPOINT_SCHEMA,
            "transaction_id": transaction_id,
            "generation": latest["generation"],
            "identity": self._read_object(transaction, prepared["identity"]),
            "routing": {},
            "provider_payloads": {},
        }
        if latest["event"] == "checkpointed":
            restored["routing"] = self._read_object(transaction, latest["routing"])
            restored["provider_payloads"] = {
                name: self._read_object(transaction, reference)
                for name, reference in latest["provider_payloads"].items()
            }
        return restored

    def resume_pack(self, transaction_id: str, *, max_bytes: int = 65536) -> dict[str, Any]:
        restored = self.restore(transaction_id)
        pack = {
            "schema_version": RESUME_PACK_SCHEMA,
            "transaction_id": transaction_id,
            "generation": restored["generation"],
            "mission_id": restored["identity"]["mission_id"],
            "target": restored["identity"]["target"],
            "dependencies": restored["identity"]["dependencies"],
            "routing": restored["routing"],
            "provider_payloads": restored["provider_payloads"],
            "restore_policy": "re-observe live handles; never assume saved PIDs or ports remain live",
        }
        size = len(_canonical_bytes(pack))
        if max_bytes <= 0 or size > max_bytes:
            raise CheckpointError(
                f"resume pack requires {size} bytes, exceeding max_bytes={max_bytes}"
            )
        pack["size_bytes"] = size
        return pack


class CheckpointCoordinator:
    """Coordinate external providers around one transactional checkpoint store."""

    def __init__(self, store: CheckpointStore, providers: list[CheckpointProvider]):
        self.store = store
        self.providers = {provider.name: provider for provider in providers}
        if len(self.providers) != len(providers):
            raise CheckpointError("provider names must be unique")
        for name in self.providers:
            _validate_id("provider name", name)

    def prepare(
        self,
        transaction_id: str,
        *,
        mission_id: str,
        target: Mapping[str, Any],
        dependencies: list[Mapping[str, Any]],
    ) -> dict[str, Any]:
        prepared = {
            name: dict(provider.prepare(transaction_id))
            for name, provider in sorted(self.providers.items())
        }
        return self.store.prepare(
            transaction_id,
            mission_id=mission_id,
            target=target,
            dependencies=dependencies,
            providers=prepared,
        )

    def checkpoint(
        self,
        transaction_id: str,
        *,
        routing: Mapping[str, Any],
        expected_generation: int | None = None,
    ) -> dict[str, Any]:
        payloads = {
            name: dict(provider.checkpoint(transaction_id))
            for name, provider in sorted(self.providers.items())
        }
        return self.store.checkpoint(
            transaction_id,
            routing=routing,
            provider_payloads=payloads,
            expected_generation=expected_generation,
        )

    def verify(self, transaction_id: str) -> dict[str, Any]:
        integrity = self.store.verify(transaction_id)
        restored = self.store.restore(transaction_id)
        provider_results = {
            name: dict(provider.verify(transaction_id, restored["provider_payloads"][name]))
            for name, provider in sorted(self.providers.items())
        }
        if any(result.get("ok") is not True for result in provider_results.values()):
            raise CheckpointError("one or more checkpoint providers failed verification")
        return {**integrity, "providers": provider_results}

    def restore(self, transaction_id: str) -> dict[str, Any]:
        restored = self.store.restore(transaction_id)
        provider_results = {
            name: dict(provider.restore(transaction_id, restored["provider_payloads"][name]))
            for name, provider in sorted(self.providers.items())
        }
        return {**restored, "provider_restore": provider_results}
