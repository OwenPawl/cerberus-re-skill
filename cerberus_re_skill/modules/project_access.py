"""Route project reads around live Ghidra ownership without blind lock retries."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
from typing import Any, Iterator
import uuid

from cerberus_re_skill.core.config import cfg
from cerberus_re_skill.core.utils import utc_now
from cerberus_re_skill.modules.bridge_sessions import (
    find_matching_sessions,
    list_application_inventory,
)


SNAPSHOT_SCHEMA = "cerberus.project-snapshot.v1"
ROUTE_SCHEMA = "cerberus.project-read-route.v1"


@dataclass(frozen=True)
class ProjectReadRoute:
    """One resolved project read target and its durable routing evidence."""

    mode: str
    project_location: Path
    project_name: str
    source_project_name: str
    owners: tuple[dict[str, Any], ...] = ()
    snapshot_manifest: dict[str, Any] | None = None

    def evidence(self) -> dict[str, Any]:
        return {
            "schema": ROUTE_SCHEMA,
            "mode": self.mode,
            "project_location": str(self.project_location),
            "project_name": self.project_name,
            "source_project_name": self.source_project_name,
            "owners": list(self.owners),
            "snapshot": self.snapshot_manifest,
        }


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _excluded(path: Path) -> bool:
    return path.name == "tmp" or path.name.endswith(".lock") or path.name.endswith(".lock~")


def _content_manifest(root: Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if any(_excluded(part) for part in [root / component for component in relative.parts]):
            continue
        if path.is_symlink():
            raise RuntimeError(f"project snapshot refuses symlink: {path}")
        if not path.is_file():
            continue
        entries.append(
            {
                "path": relative.as_posix(),
                "size": path.stat().st_size,
                "sha256": _sha256_file(path),
            }
        )
    return entries


def _manifest_digest(entries: list[dict[str, Any]]) -> str:
    encoded = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _copy_ignore(_directory: str, names: list[str]) -> set[str]:
    return {
        name
        for name in names
        if name == "tmp" or name.endswith(".lock") or name.endswith(".lock~")
    }


def _program_matches(program: dict[str, Any], requested_program: str) -> bool:
    if not requested_program:
        return True
    name = str(program.get("program_name") or "")
    path = str(program.get("program_path") or "")
    return name == requested_program or path == requested_program or path.endswith(
        f"/{requested_program}"
    )


def _owner_record(path: Path, requested_program: str) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    programs = [
        item for item in payload.get("open_programs", []) if isinstance(item, dict)
    ]
    if not programs:
        programs = [
            {
                "program_name": payload.get("program_name", ""),
                "program_path": payload.get("program_path", ""),
                "program_id": payload.get("current_program_id", ""),
                "changed": payload.get("repository", {}).get("changed", False),
            }
        ]
    matching = [program for program in programs if _program_matches(program, requested_program)]
    return {
        "source": "bridge_session",
        "session_id": str(payload.get("session_id") or path.stem),
        "application_id": str(payload.get("application_id") or ""),
        "tool_id": str(payload.get("tool_id") or ""),
        "pid": payload.get("pid"),
        "last_heartbeat": str(payload.get("last_heartbeat") or ""),
        "matching_programs": [
            {
                "program_id": str(program.get("program_id") or ""),
                "program_name": str(program.get("program_name") or ""),
                "program_path": str(program.get("program_path") or ""),
                "program_version": program.get("program_version"),
                "changed": bool(program.get("changed", False)),
            }
            for program in matching
        ],
    }


def _inventory_owner_records(
    project_name: str,
    requested_program: str,
) -> tuple[dict[str, Any], ...]:
    """Return live GUI owners even when their per-tool bridge is disarmed."""
    records: list[dict[str, Any]] = []
    expected_marker = cfg.project_file(project_name).resolve(strict=False)
    for application in list_application_inventory():
        if application.get("status") != "live":
            continue
        recorded_name = str(application.get("project_name") or "")
        recorded_path = str(application.get("project_path") or "")
        path_matches = bool(recorded_path) and Path(recorded_path).resolve(
            strict=False
        ) == expected_marker
        if recorded_name != project_name and not path_matches:
            continue

        tools = [tool for tool in application.get("tools", []) if isinstance(tool, dict)]
        if not tools:
            tools = [{}]
        for tool in tools:
            programs = [
                program
                for program in tool.get("open_programs", [])
                if isinstance(program, dict)
            ]
            matching = [
                program
                for program in programs
                if _program_matches(program, requested_program)
            ]
            records.append(
                {
                    "source": "application_inventory",
                    "session_id": str(tool.get("bridge_session_id") or ""),
                    "application_id": str(application.get("application_id") or ""),
                    "tool_id": str(tool.get("tool_id") or ""),
                    "pid": application.get("pid"),
                    "last_heartbeat": str(application.get("last_heartbeat") or ""),
                    "bridge_armed": bool(tool.get("bridge_armed", False)),
                    "matching_programs": [
                        {
                            "program_id": str(program.get("program_id") or ""),
                            "program_name": str(program.get("program_name") or ""),
                            "program_path": str(program.get("program_path") or ""),
                            "program_version": program.get("program_version"),
                            "changed": bool(program.get("changed", False)),
                        }
                        for program in matching
                    ],
                }
            )
    return tuple(records)


def _live_project_owners(
    project_name: str,
    requested_program: str,
) -> tuple[dict[str, Any], ...]:
    inventory_owners = _inventory_owner_records(project_name, requested_program)
    if inventory_owners:
        return inventory_owners
    session_files = find_matching_sessions("", project_name, "")
    return tuple(_owner_record(path, requested_program) for path in session_files)


def _snapshot_project(
    source: Path,
    source_project_name: str,
    owners: tuple[dict[str, Any], ...],
) -> tuple[Path, str, dict[str, Any]]:
    if not source.is_dir():
        raise RuntimeError(f"project directory not found: {source}")
    snapshot_name = f"{source_project_name}-snapshot-{uuid.uuid4().hex[:12]}"
    snapshot_root = Path(tempfile.mkdtemp(prefix=f"cerberus-project-{source_project_name}."))
    snapshot_project = snapshot_root / snapshot_name
    try:
        before = _content_manifest(source)
        shutil.copytree(source, snapshot_project, ignore=_copy_ignore)
        after = _content_manifest(source)
        copied = _content_manifest(snapshot_project)
        if before != after:
            raise RuntimeError("source project changed while the read-only snapshot was copied")
        if before != copied:
            raise RuntimeError("read-only snapshot content does not match the source manifest")

        source_marker = snapshot_project / f"{source_project_name}.gpr"
        source_repository = snapshot_project / f"{source_project_name}.rep"
        if not source_marker.is_file() or not source_repository.is_dir():
            raise RuntimeError("project snapshot is missing its Ghidra marker or repository")
        source_marker.rename(snapshot_project / f"{snapshot_name}.gpr")
        source_repository.rename(snapshot_project / f"{snapshot_name}.rep")
        manifest = {
            "schema": SNAPSHOT_SCHEMA,
            "created_at": utc_now(),
            "source_project_name": source_project_name,
            "source_project_path": str(source),
            "snapshot_project_name": snapshot_name,
            "entry_count": len(before),
            "source_manifest_sha256": _manifest_digest(before),
            "copy_verified": True,
            "owners": list(owners),
        }
        return snapshot_root, snapshot_name, manifest
    except Exception:
        shutil.rmtree(snapshot_root, ignore_errors=True)
        raise


@contextmanager
def routed_project_read(project_name: str, program_name: str = "") -> Iterator[ProjectReadRoute]:
    """Route a read directly when unowned, otherwise through a verified snapshot."""
    project_location = cfg.project_location(project_name)
    owners = _live_project_owners(project_name, program_name)
    if not owners:
        yield ProjectReadRoute(
            mode="headless",
            project_location=project_location,
            project_name=project_name,
            source_project_name=project_name,
        )
        return

    dirty = [
        program
        for owner in owners
        for program in owner["matching_programs"]
        if program["changed"]
    ]
    if dirty:
        identities = ", ".join(
            program["program_id"] or program["program_path"] or program["program_name"]
            for program in dirty
        )
        raise RuntimeError(
            "live Ghidra owns a dirty target; use targeted bridge reads or explicitly save "
            f"before a snapshot export: {identities}"
        )

    snapshot_root, snapshot_name, manifest = _snapshot_project(
        project_location,
        project_name,
        owners,
    )
    try:
        yield ProjectReadRoute(
            mode="verified_snapshot",
            project_location=snapshot_root / snapshot_name,
            project_name=snapshot_name,
            source_project_name=project_name,
            owners=owners,
            snapshot_manifest=manifest,
        )
    finally:
        shutil.rmtree(snapshot_root, ignore_errors=True)
