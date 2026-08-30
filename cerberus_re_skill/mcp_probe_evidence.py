"""First-class MCP composition for probe plans and immutable evidence."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import stat
from typing import TYPE_CHECKING, Any, Callable, Mapping

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

from .mcp_runtime import BLOCKED, FAILED, SUCCESS, MCPSettings, append_audit, envelope
from .modules.evidence_graph import (
    CertificationError,
    EvidenceGraphError,
    EvidenceGraphStore,
    NODE_KINDS,
)
from .modules.probe_plan import (
    ProbePlanError,
    ProbePlanIntegrityError,
    build_executable_identity,
    build_probe_plan,
    build_target_identity,
    materialize_helper,
    new_probe_lifecycle,
    record_lifecycle_event,
    summarize_probe_lifecycle,
    verify_probe_plan,
    write_probe_lifecycle,
    write_probe_plan,
)


MAX_HELPERS = 32
MAX_HELPER_BYTES = 1_048_576
MAX_JSON_BYTES = 1_048_576
MAX_OUTPUTS = 32
MAX_DEPENDENCIES = 256
MAX_QUERY_RESULTS = 200
MAX_EXPECTED_SIGNALS = 64

TOOL_NAMES = (
    "probe_plan_create",
    "probe_plan_verify",
    "probe_plan_write",
    "probe_lifecycle_record",
    "probe_lifecycle_summarize",
    "evidence_append",
    "evidence_export",
    "evidence_query",
    "evidence_certification_gate",
    "evidence_certify",
)


class WorkspaceConfinementError(ValueError):
    """Raised when an MCP artifact path escapes the configured workspace."""


class ProbeEvidenceMCP:
    """Artifact-only handlers shared by FastMCP registration and unit tests."""

    def __init__(self, settings: MCPSettings):
        self.settings = settings
        self.workspace = settings.workspace.expanduser().resolve()
        self.settings.ensure_state()
        self.helper_root = self.workspace / ".cerberus-mcp" / "probe-helpers"

    def probe_plan_create(
        self,
        stable_target_key: str,
        executable_path: str,
        transport: str,
        mode: str,
        timeout_seconds: int,
        detach_policy: str,
        kill_policy: str,
        outputs: dict[str, str],
        helpers: list[dict[str, Any]] | None = None,
        expected_signals: list[str] | None = None,
        display_name: str = "",
        platform: str = "",
        architecture: str = "",
        object_uuid: str = "",
    ) -> dict[str, Any]:
        """Create a deterministic ProbePlan and materialize bounded helper content."""

        def operation() -> tuple[dict[str, Any], list[str]]:
            executable = self._path(executable_path, "executable_path", require_file=True)
            helper_specs = helpers or []
            if len(helper_specs) > MAX_HELPERS:
                raise ProbePlanError(f"helpers must contain at most {MAX_HELPERS} entries")
            helper_identities = [self._materialize_helper_spec(item) for item in helper_specs]
            normalized_outputs = self._output_paths(outputs)
            executable_identity = build_executable_identity(
                executable,
                architecture=architecture,
                object_uuid=object_uuid,
            )
            target = build_target_identity(
                stable_target_key,
                executable_identity,
                display_name=display_name,
                platform=platform,
                architecture=architecture,
            )
            plan = build_probe_plan(
                target,
                transport=transport,
                mode=mode,
                timeout_seconds=timeout_seconds,
                detach_policy=detach_policy,
                kill_policy=kill_policy,
                expected_signals=self._signals(expected_signals or []),
                helpers=helper_identities,
                outputs=normalized_outputs,
            )
            self._verify_plan_bindings(plan)
            return {"plan": plan}, [item["path"] for item in helper_identities]

        return self._execute("probe_plan_create", operation)

    def probe_plan_verify(
        self,
        plan: dict[str, Any] | None = None,
        plan_path: str = "",
    ) -> dict[str, Any]:
        """Strictly verify one inline or workspace-resident ProbePlan."""

        def operation() -> tuple[dict[str, Any], list[str]]:
            normalized, source = self._load_plan(plan, plan_path)
            self._verify_plan_bindings(normalized)
            artifacts = [str(source)] if source else []
            return {"plan": normalized}, artifacts

        return self._execute("probe_plan_verify", operation)

    def probe_plan_write(
        self,
        plan: dict[str, Any],
        output_path: str,
    ) -> dict[str, Any]:
        """Strictly verify and atomically write one ProbePlan inside the workspace."""

        def operation() -> tuple[dict[str, Any], list[str]]:
            normalized = verify_probe_plan(self._json_object(plan, "plan"))
            self._verify_plan_bindings(normalized)
            destination = self._writable_path(output_path, "output_path")
            write_probe_plan(destination, normalized)
            return {
                "plan_id": normalized["plan_id"],
                "path": str(destination),
            }, [str(destination)]

        return self._execute("probe_plan_write", operation)

    def probe_lifecycle_record(
        self,
        plan_path: str,
        lifecycle_path: str,
        phase: str,
        outcome: str,
        observed_at: str = "",
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Append and atomically persist one independent lifecycle event."""

        def operation() -> tuple[dict[str, Any], list[str]]:
            plan, plan_source = self._load_plan(None, plan_path)
            self._verify_plan_bindings(plan)
            destination = self._writable_path(lifecycle_path, "lifecycle_path")
            if destination.exists():
                lifecycle = self._read_object(destination, "lifecycle")
                summarize_probe_lifecycle(lifecycle)
            else:
                lifecycle = new_probe_lifecycle(plan["plan_id"])
            if lifecycle.get("plan_id") != plan["plan_id"]:
                raise ProbePlanIntegrityError("lifecycle plan_id does not match the verified plan")
            event = record_lifecycle_event(
                lifecycle,
                phase,
                outcome,
                observed_at=observed_at or None,
                details=self._json_object(details or {}, "details"),
            )
            write_probe_lifecycle(destination, lifecycle)
            summary = summarize_probe_lifecycle(lifecycle)
            return {
                "event": event,
                "summary": summary,
                "path": str(destination),
            }, [str(plan_source), str(destination)]

        return self._execute("probe_lifecycle_record", operation)

    def probe_lifecycle_summarize(
        self,
        plan_path: str,
        lifecycle_path: str,
    ) -> dict[str, Any]:
        """Verify a persisted lifecycle ledger and summarize its independent outcomes."""

        def operation() -> tuple[dict[str, Any], list[str]]:
            plan, plan_source = self._load_plan(None, plan_path)
            self._verify_plan_bindings(plan)
            source = self._path(lifecycle_path, "lifecycle_path", require_file=True)
            lifecycle = self._read_object(source, "lifecycle")
            summary = summarize_probe_lifecycle(lifecycle)
            if lifecycle.get("plan_id") != plan["plan_id"]:
                raise ProbePlanIntegrityError("lifecycle plan_id does not match the verified plan")
            return {
                "lifecycle": lifecycle,
                "summary": summary,
            }, [str(plan_source), str(source)]

        return self._execute("probe_lifecycle_summarize", operation)

    def evidence_append(
        self,
        graph_dir: str,
        kind: str,
        payload: dict[str, Any],
        dependencies: list[str] | None = None,
        content_identity: str = "",
        verification_path: str = "",
        finding_key: str = "",
        statement: str = "",
        status: str = "proposed",
        previous_finding_id: str = "",
        contradicts: list[str] | None = None,
        resolution_status: str = "disproved",
    ) -> dict[str, Any]:
        """Append one bounded immutable evidence node or contradictory observation."""

        def operation() -> tuple[dict[str, Any], list[str]]:
            store = self._store(graph_dir)
            normalized_payload = self._json_object(payload, "payload")
            dependency_ids = self._identities(dependencies or [], "dependencies")
            contradiction_ids = self._identities(contradicts or [], "contradicts")
            verification = self._verification_path(verification_path)
            normalized_kind = str(kind).strip().lower()
            if normalized_kind == "raw_artifact":
                if dependency_ids or contradiction_ids:
                    raise EvidenceGraphError("raw_artifact does not accept dependencies or contradicts")
                node = store.add_raw_artifact(
                    normalized_payload,
                    content_identity=content_identity,
                    verification_path=verification,
                )
            elif normalized_kind == "normalized_observation":
                if contradiction_ids:
                    raise EvidenceGraphError("use contradictory_observation when contradicts is provided")
                node = store.add_observation(
                    normalized_payload,
                    dependencies=dependency_ids,
                    content_identity=content_identity or None,
                    verification_path=verification,
                )
            elif normalized_kind == "hypothesis":
                if contradiction_ids:
                    raise EvidenceGraphError("hypothesis does not accept contradicts")
                node = store.add_hypothesis(
                    normalized_payload,
                    dependencies=dependency_ids,
                    content_identity=content_identity or None,
                    verification_path=verification,
                )
            elif normalized_kind == "finding":
                if status == "certified":
                    raise CertificationError("use evidence_certify for certified findings")
                if content_identity or contradiction_ids:
                    raise EvidenceGraphError("finding does not accept content_identity or contradicts")
                node = store.add_finding(
                    finding_key,
                    statement,
                    status,
                    dependencies=dependency_ids,
                    verification_path=verification,
                    previous_finding_id=previous_finding_id,
                    details=normalized_payload,
                )
            elif normalized_kind == "contradictory_observation":
                result = store.append_contradictory_observation(
                    normalized_payload,
                    contradicts=contradiction_ids,
                    dependencies=dependency_ids,
                    content_identity=content_identity or None,
                    verification_path=verification,
                    resolution_status=resolution_status,
                )
                return {"result": result}, []
            else:
                allowed = sorted(NODE_KINDS | {"contradictory_observation"})
                raise EvidenceGraphError(f"kind must be one of {allowed}")
            return {"node": node}, []

        return self._execute("evidence_append", operation)

    def evidence_export(
        self,
        graph_dir: str,
        output_path: str,
    ) -> dict[str, Any]:
        """Validate and atomically export an immutable evidence graph."""

        def operation() -> tuple[dict[str, Any], list[str]]:
            store = self._store(graph_dir)
            destination = self._writable_path(output_path, "output_path")
            if self._is_within(destination, store.records_dir):
                raise WorkspaceConfinementError("output_path overlaps immutable evidence records")
            graph = store.write_export(destination)
            return {
                "schema": graph["schema"],
                "node_count": len(graph["nodes"]),
                "edge_count": len(graph["edges"]),
                "path": str(destination),
            }, [str(destination)]

        return self._execute("evidence_export", operation)

    def evidence_query(
        self,
        graph_dir: str,
        node_id: str = "",
        kind: str = "",
        finding_key: str = "",
        include_dependency_closure: bool = False,
        limit: int = 50,
    ) -> dict[str, Any]:
        """Query one node or a bounded deterministic subset of the graph."""

        def operation() -> tuple[dict[str, Any], list[str]]:
            if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_QUERY_RESULTS:
                raise EvidenceGraphError(f"limit must be an integer from 1 to {MAX_QUERY_RESULTS}")
            store = self._store(graph_dir)
            if node_id:
                if kind or finding_key:
                    raise EvidenceGraphError("node_id cannot be combined with kind or finding_key")
                node = store.get_node(node_id)
                closure = sorted(store.transitive_dependencies(node_id)) if include_dependency_closure else []
                return {
                    "node": node,
                    "dependency_closure_ids": closure[:limit],
                    "dependency_closure_total": len(closure),
                    "dependency_closure_truncated": len(closure) > limit,
                }, []
            if include_dependency_closure:
                raise EvidenceGraphError("include_dependency_closure requires node_id")
            if kind and kind not in NODE_KINDS:
                raise EvidenceGraphError(f"unknown evidence node kind: {kind}")
            nodes = store.export_graph()["nodes"]
            if kind:
                nodes = [node for node in nodes if node["kind"] == kind]
            if finding_key:
                nodes = [
                    node
                    for node in nodes
                    if node["kind"] == "finding"
                    and node["payload"].get("finding_key") == finding_key
                ]
            total = len(nodes)
            return {
                "nodes": nodes[:limit],
                "total": total,
                "limit": limit,
                "truncated": total > limit,
            }, []

        return self._execute("evidence_query", operation)

    def evidence_certification_gate(
        self,
        graph_dir: str,
        dependency_ids: list[str],
    ) -> dict[str, Any]:
        """Read-only gate for a proposed certified finding dependency closure."""

        def operation() -> tuple[dict[str, Any], list[str]]:
            store = self._store(graph_dir)
            identities = self._identities(dependency_ids, "dependency_ids")
            return {"gate": self._certification_gate(store, identities)}, []

        return self._execute("evidence_certification_gate", operation)

    def evidence_certify(
        self,
        graph_dir: str,
        finding_key: str,
        statement: str,
        dependency_ids: list[str],
        verification_path: str = "",
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Gate and append one certified finding without weakening graph requirements."""

        def operation() -> tuple[dict[str, Any], list[str]]:
            store = self._store(graph_dir)
            identities = self._identities(dependency_ids, "dependency_ids")
            gate = self._certification_gate(store, identities)
            node = store.add_finding(
                finding_key,
                statement,
                "certified",
                dependencies=identities,
                verification_path=self._verification_path(verification_path),
                details=self._json_object(details or {}, "details"),
            )
            return {"gate": gate, "node": node}, []

        return self._execute("evidence_certify", operation)

    def _execute(
        self,
        action: str,
        operation: Callable[[], tuple[dict[str, Any], list[str]]],
    ) -> dict[str, Any]:
        try:
            data, artifacts = operation()
        except CertificationError as exc:
            self._audit(action, BLOCKED, str(exc))
            return envelope(BLOCKED, note=str(exc))
        except (EvidenceGraphError, ProbePlanIntegrityError, ValueError, OSError) as exc:
            self._audit(action, FAILED, str(exc))
            return envelope(FAILED, note=str(exc))
        self._audit(action, SUCCESS, "")
        return envelope(SUCCESS, data=data, artifacts=artifacts, note=f"{action} succeeded")

    def _audit(self, action: str, status: str, detail: str) -> None:
        append_audit(
            self.settings,
            {
                "tier": "probe_evidence",
                "action": action,
                "outcome": status,
                "detail": detail,
            },
        )

    def _path(
        self,
        value: str | Path,
        label: str,
        *,
        require_file: bool = False,
        allow_workspace: bool = False,
    ) -> Path:
        text = str(value).strip()
        if not text:
            raise WorkspaceConfinementError(f"{label} must not be empty")
        raw = Path(text).expanduser()
        candidate = raw if raw.is_absolute() else self.workspace / raw
        resolved = candidate.resolve(strict=False)
        try:
            resolved.relative_to(self.workspace)
        except ValueError as exc:
            raise WorkspaceConfinementError(f"{label} escapes the configured workspace") from exc
        if resolved == self.workspace and not allow_workspace:
            raise WorkspaceConfinementError(f"{label} must not be the workspace root")
        if require_file and not resolved.is_file():
            raise WorkspaceConfinementError(f"{label} is not a file inside the workspace")
        return resolved

    def _output_paths(self, outputs: Mapping[str, str]) -> dict[str, str]:
        if not isinstance(outputs, Mapping) or not outputs:
            raise ProbePlanError("outputs must be a non-empty object")
        if len(outputs) > MAX_OUTPUTS:
            raise ProbePlanError(f"outputs must contain at most {MAX_OUTPUTS} entries")
        normalized = {}
        for name, value in outputs.items():
            if not isinstance(name, str) or not name.strip() or not isinstance(value, str):
                raise ProbePlanError("output names and paths must be non-empty strings")
            output_name = name.strip()
            normalized[output_name] = str(self._writable_path(value, f"outputs.{output_name}"))
        return normalized

    def _signals(self, values: list[str]) -> list[str]:
        if not isinstance(values, list) or len(values) > MAX_EXPECTED_SIGNALS:
            raise ProbePlanError(
                f"expected_signals must be a list of at most {MAX_EXPECTED_SIGNALS} strings"
            )
        if not all(isinstance(value, str) and value.strip() for value in values):
            raise ProbePlanError("expected_signals entries must be non-empty strings")
        return values

    def _materialize_helper_spec(self, spec: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(spec, Mapping):
            raise ProbePlanError("helper entries must be objects")
        if not {"name", "content"} <= set(spec) or set(spec) - {"name", "content", "executable"}:
            raise ProbePlanError("helper fields must be name, content, and optional executable")
        content = spec["content"]
        if not isinstance(content, str):
            raise ProbePlanError("helper content must be a string")
        if len(content.encode("utf-8")) > MAX_HELPER_BYTES:
            raise ProbePlanError(f"helper content exceeds {MAX_HELPER_BYTES} bytes")
        executable = spec.get("executable", False)
        if not isinstance(executable, bool):
            raise ProbePlanError("helper executable must be boolean")
        return materialize_helper(
            self.helper_root,
            str(spec["name"]),
            content,
            executable=executable,
        )

    def _load_plan(
        self,
        plan: dict[str, Any] | None,
        plan_path: str,
    ) -> tuple[dict[str, Any], Path | None]:
        if (plan is None) == (not plan_path):
            raise ProbePlanError("provide exactly one plan or plan_path")
        if plan is not None:
            return verify_probe_plan(self._json_object(plan, "plan")), None
        source = self._path(plan_path, "plan_path", require_file=True)
        return verify_probe_plan(self._read_object(source, "plan")), source

    def _verify_plan_bindings(self, plan: Mapping[str, Any]) -> None:
        target = plan["target"]
        executable = target["executable"]
        executable_path = self._path(executable["path"], "plan executable", require_file=True)
        if str(executable_path) != executable["path"]:
            raise WorkspaceConfinementError("plan executable path is not canonical")
        if len(plan["helpers"]) > MAX_HELPERS:
            raise ProbePlanError(f"plan contains more than {MAX_HELPERS} helpers")
        if len(plan["outputs"]) > MAX_OUTPUTS:
            raise ProbePlanError(f"plan contains more than {MAX_OUTPUTS} outputs")
        self._signals(plan["expected_signals"])
        for helper in plan["helpers"]:
            path = self._path(helper["path"], f"helper {helper['name']}", require_file=True)
            if str(path) != helper["path"]:
                raise WorkspaceConfinementError(f"helper {helper['name']} path is not canonical")
            mode = path.lstat().st_mode
            if not stat.S_ISREG(mode) or mode & 0o222:
                raise ProbePlanIntegrityError(f"helper {helper['name']} is not immutable")
            if bool(mode & 0o111) != helper["executable"]:
                raise ProbePlanIntegrityError(f"helper {helper['name']} executable mode changed")
            if self._sha256_file(path) != helper["sha256"]:
                raise ProbePlanIntegrityError(f"helper {helper['name']} SHA-256 changed")
        for name, value in plan["outputs"].items():
            path = self._writable_path(value, f"plan output {name}")
            if str(path) != value:
                raise WorkspaceConfinementError(f"plan output {name} is not canonical")

    def _store(self, graph_dir: str) -> EvidenceGraphStore:
        root = self._path(graph_dir, "graph_dir")
        if self._is_within(root, self.helper_root):
            raise WorkspaceConfinementError("graph_dir overlaps the immutable helper store")
        return EvidenceGraphStore(root)

    def _verification_path(self, value: str) -> str:
        return str(self._path(value, "verification_path")) if str(value).strip() else ""

    def _identities(self, values: list[str], label: str) -> list[str]:
        if not isinstance(values, list):
            raise EvidenceGraphError(f"{label} must be a list")
        if len(values) > MAX_DEPENDENCIES:
            raise EvidenceGraphError(f"{label} must contain at most {MAX_DEPENDENCIES} identities")
        normalized = []
        for value in values:
            if not isinstance(value, str):
                raise EvidenceGraphError(f"{label} entries must be strings")
            identity = value
            if not identity.startswith("sha256:") or len(identity) != 71:
                raise EvidenceGraphError(f"{label} entries must be sha256 content identities")
            try:
                int(identity[7:], 16)
            except ValueError as exc:
                raise EvidenceGraphError(f"{label} contains a non-hex identity") from exc
            normalized.append(identity)
        return sorted(set(normalized))

    def _certification_gate(
        self,
        store: EvidenceGraphStore,
        dependency_ids: list[str],
    ) -> dict[str, Any]:
        gate = store.certification_gate(dependency_ids)
        verification_paths = []
        for node_id in gate["closure_ids"]:
            node = store.get_node(node_id)
            path = self._path(
                node["verification_path"],
                f"verification_path for {node_id}",
                require_file=True,
            )
            verification_paths.append(str(path))
        return {**gate, "verification_paths": sorted(verification_paths)}

    def _writable_path(self, value: str | Path, label: str) -> Path:
        path = self._path(value, label)
        if self._is_within(path, self.helper_root):
            raise WorkspaceConfinementError(f"{label} overlaps the immutable helper store")
        return path

    @staticmethod
    def _is_within(path: Path, root: Path) -> bool:
        try:
            path.relative_to(root)
            return True
        except ValueError:
            return False

    def _json_object(self, value: Any, label: str) -> dict[str, Any]:
        if not isinstance(value, Mapping):
            raise ValueError(f"{label} must be an object")
        try:
            encoded = json.dumps(
                dict(value),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{label} must contain canonical JSON values") from exc
        if len(encoded) > MAX_JSON_BYTES:
            raise ValueError(f"{label} exceeds {MAX_JSON_BYTES} bytes")
        decoded = json.loads(encoded)
        if not isinstance(decoded, dict):
            raise ValueError(f"{label} must be an object")
        return decoded

    def _read_object(self, path: Path, label: str) -> dict[str, Any]:
        try:
            size = path.stat().st_size
            if size > MAX_JSON_BYTES:
                raise ValueError(f"{label} exceeds {MAX_JSON_BYTES} bytes")
            return self._json_object(json.loads(path.read_text(encoding="utf-8")), label)
        except UnicodeDecodeError as exc:
            raise ValueError(f"{label} is not UTF-8 JSON") from exc

    @staticmethod
    def _sha256_file(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()


def register_probe_evidence_tools(server: FastMCP, settings: MCPSettings) -> list[str]:
    """Register the artifact-only probe/evidence surface on one FastMCP server."""
    handlers = ProbeEvidenceMCP(settings)
    for name in TOOL_NAMES:
        server.tool(name=name)(getattr(handlers, name))
    return list(TOOL_NAMES)
