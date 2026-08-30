"""Content-addressed immutable evidence nodes and dependency edges."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Iterable


NODE_SCHEMA = "ghidra-re.evidence-node.v1"
EDGE_SCHEMA = "ghidra-re.evidence-edge.v1"
RECORD_SCHEMA = "ghidra-re.evidence-record.v1"
GRAPH_SCHEMA = "ghidra-re.evidence-graph.v1"

NODE_KINDS = {
    "raw_artifact",
    "normalized_observation",
    "hypothesis",
    "finding",
}
EDGE_RELATIONS = {"depends_on", "contradicts", "supersedes"}
FINDING_STATUSES = {"proposed", "certified", "disproved", "superseded"}


class EvidenceGraphError(RuntimeError):
    """Base error for invalid or unsafe evidence-graph operations."""


class CorruptEvidenceGraph(EvidenceGraphError):
    """Raised when persisted content does not match its immutable identity."""


class CertificationError(EvidenceGraphError):
    """Raised when a finding does not have a fully verifiable dependency closure."""


def _canonical_bytes(payload: Any) -> bytes:
    try:
        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise EvidenceGraphError(f"evidence payload is not canonical JSON: {exc}") from exc
    return encoded.encode("utf-8")


def _normalized_json(payload: Any) -> Any:
    return json.loads(_canonical_bytes(payload).decode("utf-8"))


def _sha256_id(payload: Any) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(_canonical_bytes(payload)).hexdigest()


def _pretty_bytes(payload: Any) -> bytes:
    try:
        text = json.dumps(
            payload,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise EvidenceGraphError(f"evidence payload is not JSON serializable: {exc}") from exc
    return (text + "\n").encode("utf-8")


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


def _read_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CorruptEvidenceGraph(f"cannot read {label} {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise CorruptEvidenceGraph(f"{label} must be a JSON object: {path}")
    return payload


def _verify_existing(path: Path, payload: dict[str, Any]) -> None:
    existing = _read_json_object(path, "immutable evidence record")
    if existing != payload:
        raise CorruptEvidenceGraph(f"conflicting immutable evidence record: {path}")


def _write_immutable(path: Path, payload: dict[str, Any]) -> None:
    """Publish one immutable record atomically without replacing an existing path."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        _verify_existing(path, payload)
        return
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(_pretty_bytes(payload))
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            _verify_existing(path, payload)
        except OSError as exc:
            raise EvidenceGraphError(f"cannot atomically publish immutable record {path}: {exc}") from exc
        else:
            _fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def _write_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(_pretty_bytes(payload))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def _validate_identity(value: Any, label: str) -> str:
    identity = str(value or "")
    if not identity.startswith("sha256:") or len(identity) != 71:
        raise CorruptEvidenceGraph(f"{label} must be a sha256 content identity")
    try:
        int(identity[7:], 16)
    except ValueError as exc:
        raise CorruptEvidenceGraph(f"{label} has a non-hex sha256 digest") from exc
    return identity


def _edge_for(node_id: str, dependency: dict[str, str]) -> dict[str, Any]:
    body = {
        "schema": EDGE_SCHEMA,
        "dependent_id": node_id,
        "dependency_id": dependency["node_id"],
        "relation": dependency["relation"],
    }
    return {"id": _sha256_id(body), **body}


def _record_for(body: dict[str, Any]) -> dict[str, Any]:
    node_id = _sha256_id(body)
    node = {"id": node_id, **body}
    edges = [_edge_for(node_id, item) for item in body["dependencies"]]
    return {
        "schema": RECORD_SCHEMA,
        "node": node,
        "edges": sorted(edges, key=lambda item: item["id"]),
    }


def _validate_record(record: dict[str, Any], path: Path | None = None) -> dict[str, Any]:
    label = str(path) if path else "evidence record"
    if record.get("schema") != RECORD_SCHEMA:
        raise CorruptEvidenceGraph(f"unexpected evidence record schema: {label}")
    node = record.get("node")
    edges = record.get("edges")
    if not isinstance(node, dict) or not isinstance(edges, list):
        raise CorruptEvidenceGraph(f"record node/edges shape is invalid: {label}")
    node_id = _validate_identity(node.get("id"), "node id")
    body = {key: value for key, value in node.items() if key != "id"}
    if node.get("schema") != NODE_SCHEMA or node.get("kind") not in NODE_KINDS:
        raise CorruptEvidenceGraph(f"node schema or kind is invalid: {label}")
    if _sha256_id(body) != node_id:
        raise CorruptEvidenceGraph(f"node content does not match its id: {label}")
    if not isinstance(node.get("payload"), dict):
        raise CorruptEvidenceGraph(f"node payload must be an object: {label}")
    if not isinstance(node.get("content_identity"), str):
        raise CorruptEvidenceGraph(f"node content_identity must be a string: {label}")
    if node["content_identity"]:
        _validate_identity(node["content_identity"], "node content_identity")
    if not isinstance(node.get("verification_path"), str):
        raise CorruptEvidenceGraph(f"node verification_path must be a string: {label}")
    dependencies = node.get("dependencies")
    if not isinstance(dependencies, list):
        raise CorruptEvidenceGraph(f"node dependencies must be a list: {label}")
    normalized_dependencies: list[dict[str, str]] = []
    for dependency in dependencies:
        if not isinstance(dependency, dict):
            raise CorruptEvidenceGraph(f"node dependency must be an object: {label}")
        dependency_id = _validate_identity(dependency.get("node_id"), "dependency node id")
        relation = str(dependency.get("relation") or "")
        if relation not in EDGE_RELATIONS:
            raise CorruptEvidenceGraph(f"unknown dependency relation {relation!r}: {label}")
        normalized_dependencies.append({"node_id": dependency_id, "relation": relation})
    dependency_keys = {
        (item["node_id"], item["relation"])
        for item in normalized_dependencies
    }
    if len(dependency_keys) != len(normalized_dependencies):
        raise CorruptEvidenceGraph(f"node dependencies contain duplicates: {label}")
    if dependencies != sorted(normalized_dependencies, key=lambda item: (item["node_id"], item["relation"])):
        raise CorruptEvidenceGraph(f"node dependencies are not canonical: {label}")
    expected_edges = sorted(
        [_edge_for(node_id, item) for item in normalized_dependencies],
        key=lambda item: item["id"],
    )
    if edges != expected_edges:
        raise CorruptEvidenceGraph(f"record edges do not match node dependencies: {label}")
    if path and path.name != f"{node_id[7:]}.json":
        raise CorruptEvidenceGraph(f"record filename does not match node id: {path}")
    return record


def _validate_graph(graph: dict[str, Any]) -> dict[str, Any]:
    if graph.get("schema") != GRAPH_SCHEMA:
        raise CorruptEvidenceGraph("unexpected evidence graph schema")
    nodes = graph.get("nodes")
    edges = graph.get("edges")
    if not isinstance(nodes, list) or not isinstance(edges, list):
        raise CorruptEvidenceGraph("evidence graph nodes/edges must be lists")
    by_id: dict[str, dict[str, Any]] = {}
    for node in nodes:
        if not isinstance(node, dict):
            raise CorruptEvidenceGraph("evidence graph node must be an object")
        dependencies = node.get("dependencies")
        if not isinstance(dependencies, list):
            raise CorruptEvidenceGraph("evidence graph node dependencies must be a list")
        try:
            node_edges = sorted(
                [_edge_for(str(node.get("id") or ""), item) for item in dependencies],
                key=lambda item: item["id"],
            )
        except (KeyError, TypeError) as exc:
            raise CorruptEvidenceGraph("evidence graph node dependency is invalid") from exc
        record = _validate_record(
            {"schema": RECORD_SCHEMA, "node": node, "edges": node_edges}
        )
        node_id = record["node"]["id"]
        if node_id in by_id:
            raise CorruptEvidenceGraph(f"duplicate evidence node id: {node_id}")
        by_id[node_id] = node
    expected_edges: list[dict[str, Any]] = []
    for node in by_id.values():
        expected_edges.extend(_edge_for(node["id"], item) for item in node["dependencies"])
    expected_edges.sort(key=lambda item: item["id"])
    if edges != expected_edges:
        raise CorruptEvidenceGraph("evidence graph edges are not canonical")
    for edge in edges:
        if edge["dependent_id"] not in by_id or edge["dependency_id"] not in by_id:
            raise CorruptEvidenceGraph(f"evidence edge references a missing node: {edge['id']}")
    return {
        "schema": GRAPH_SCHEMA,
        "nodes": sorted(by_id.values(), key=lambda item: item["id"]),
        "edges": expected_edges,
    }


def read_graph_export(path: str | Path) -> dict[str, Any]:
    """Read and strictly validate a deterministic graph export."""
    return _validate_graph(_read_json_object(Path(path), "evidence graph export"))


class EvidenceGraphStore:
    """Append-only store of atomic node-plus-edge records."""

    def __init__(self, root: str | Path):
        self.root = Path(root).expanduser().resolve()
        self.records_dir = self.root / "records"

    def _record_path(self, node_id: str) -> Path:
        identity = _validate_identity(node_id, "node id")
        return self.records_dir / f"{identity[7:]}.json"

    def _records(self) -> list[dict[str, Any]]:
        if not self.records_dir.exists():
            return []
        records = []
        for path in sorted(self.records_dir.glob("*.json")):
            records.append(_validate_record(_read_json_object(path, "evidence record"), path))
        node_ids = {record["node"]["id"] for record in records}
        for record in records:
            for dependency in record["node"]["dependencies"]:
                if dependency["node_id"] not in node_ids:
                    raise CorruptEvidenceGraph(
                        f"node {record['node']['id']} references missing dependency {dependency['node_id']}"
                    )
        return records

    def export_graph(self) -> dict[str, Any]:
        records = self._records()
        nodes = sorted((record["node"] for record in records), key=lambda item: item["id"])
        edges = sorted(
            (edge for record in records for edge in record["edges"]),
            key=lambda item: item["id"],
        )
        return _validate_graph({"schema": GRAPH_SCHEMA, "nodes": nodes, "edges": edges})

    def write_export(self, path: str | Path) -> dict[str, Any]:
        graph = self.export_graph()
        _write_atomic(Path(path), graph)
        return graph

    def get_node(self, node_id: str) -> dict[str, Any]:
        path = self._record_path(node_id)
        if not path.is_file():
            raise EvidenceGraphError(f"unknown evidence node: {node_id}")
        return _validate_record(_read_json_object(path, "evidence record"), path)["node"]

    def _normalize_dependencies(
        self,
        dependencies: Iterable[tuple[str, str]],
    ) -> list[dict[str, str]]:
        normalized: dict[tuple[str, str], dict[str, str]] = {}
        for node_id, relation in dependencies:
            self.get_node(node_id)
            if relation not in EDGE_RELATIONS:
                raise EvidenceGraphError(f"unknown evidence edge relation: {relation}")
            normalized[(node_id, relation)] = {"node_id": node_id, "relation": relation}
        return sorted(normalized.values(), key=lambda item: (item["node_id"], item["relation"]))

    def _append_node(
        self,
        kind: str,
        payload: dict[str, Any],
        *,
        dependencies: Iterable[tuple[str, str]] = (),
        content_identity: str | None = None,
        verification_path: str = "",
    ) -> dict[str, Any]:
        if kind not in NODE_KINDS:
            raise EvidenceGraphError(f"unknown evidence node kind: {kind}")
        normalized_payload = _normalized_json(payload)
        if not isinstance(normalized_payload, dict):
            raise EvidenceGraphError("evidence node payload must be an object")
        identity = (
            _sha256_id({"kind": kind, "payload": normalized_payload})
            if content_identity is None
            else str(content_identity).strip()
        )
        if identity:
            try:
                _validate_identity(identity, "node content_identity")
            except CorruptEvidenceGraph as exc:
                raise EvidenceGraphError(str(exc)) from exc
        body = {
            "schema": NODE_SCHEMA,
            "kind": kind,
            "content_identity": identity,
            "verification_path": str(verification_path).strip(),
            "payload": normalized_payload,
            "dependencies": self._normalize_dependencies(dependencies),
        }
        record = _record_for(body)
        _write_immutable(self._record_path(record["node"]["id"]), record)
        return record["node"]

    def add_raw_artifact(
        self,
        payload: dict[str, Any],
        *,
        content_identity: str,
        verification_path: str = "",
    ) -> dict[str, Any]:
        if not str(content_identity).strip():
            raise EvidenceGraphError("raw artifacts require an explicit content identity")
        return self._append_node(
            "raw_artifact",
            payload,
            content_identity=content_identity,
            verification_path=verification_path,
        )

    def add_observation(
        self,
        payload: dict[str, Any],
        *,
        dependencies: Iterable[str] = (),
        content_identity: str | None = None,
        verification_path: str = "",
    ) -> dict[str, Any]:
        return self._append_node(
            "normalized_observation",
            payload,
            dependencies=((node_id, "depends_on") for node_id in dependencies),
            content_identity=content_identity,
            verification_path=verification_path,
        )

    def add_hypothesis(
        self,
        payload: dict[str, Any],
        *,
        dependencies: Iterable[str] = (),
        content_identity: str | None = None,
        verification_path: str = "",
    ) -> dict[str, Any]:
        return self._append_node(
            "hypothesis",
            payload,
            dependencies=((node_id, "depends_on") for node_id in dependencies),
            content_identity=content_identity,
            verification_path=verification_path,
        )

    def transitive_dependencies(self, node_id: str) -> set[str]:
        pending = [node_id]
        visited: set[str] = set()
        while pending:
            current = pending.pop()
            node = self.get_node(current)
            for dependency in node["dependencies"]:
                if dependency["relation"] != "depends_on":
                    continue
                dependency_id = dependency["node_id"]
                if dependency_id not in visited:
                    visited.add(dependency_id)
                    pending.append(dependency_id)
        visited.discard(node_id)
        return visited

    def certification_gate(self, dependencies: Iterable[str]) -> dict[str, Any]:
        """Validate and describe the dependency closure required for certification."""
        dependency_ids = sorted(set(dependencies))
        if not dependency_ids:
            raise CertificationError("certified findings require at least one dependency")
        closure: set[str] = set()
        for node_id in dependency_ids:
            closure.add(node_id)
            closure.update(self.transitive_dependencies(node_id))
        failures = []
        for node_id in sorted(closure):
            node = self.get_node(node_id)
            missing = []
            if not node.get("content_identity"):
                missing.append("content_identity")
            if not node.get("verification_path"):
                missing.append("verification_path")
            if missing:
                failures.append(f"{node_id} lacks {', '.join(missing)}")
        if failures:
            raise CertificationError("finding dependency closure is not certifiable: " + "; ".join(failures))
        return {
            "certifiable": True,
            "dependency_ids": dependency_ids,
            "closure_ids": sorted(closure),
        }

    def _require_certifiable(self, dependencies: list[str]) -> None:
        self.certification_gate(dependencies)

    def add_finding(
        self,
        finding_key: str,
        statement: str,
        status: str,
        *,
        dependencies: Iterable[str] = (),
        verification_path: str = "",
        previous_finding_id: str = "",
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if status not in FINDING_STATUSES:
            raise EvidenceGraphError(f"unknown finding status: {status}")
        dependency_ids = sorted(set(dependencies))
        relation_specs = [(node_id, "depends_on") for node_id in dependency_ids]
        if status == "certified":
            self._require_certifiable(dependency_ids)
        if status in {"disproved", "superseded"} and not previous_finding_id:
            raise EvidenceGraphError(f"{status} findings require previous_finding_id")
        if previous_finding_id:
            previous = self.get_node(previous_finding_id)
            if previous["kind"] != "finding":
                raise EvidenceGraphError("previous_finding_id must reference a finding")
            if previous["payload"].get("finding_key") != finding_key:
                raise EvidenceGraphError("finding revisions must preserve finding_key")
            relation_specs.append((previous_finding_id, "supersedes"))
        payload = {
            "finding_key": str(finding_key),
            "statement": str(statement),
            "status": status,
            "details": details or {},
        }
        return self._append_node(
            "finding",
            payload,
            dependencies=relation_specs,
            verification_path=verification_path,
        )

    def _active_certified_findings(self) -> list[dict[str, Any]]:
        graph = self.export_graph()
        superseded = {
            edge["dependency_id"]
            for edge in graph["edges"]
            if edge["relation"] == "supersedes"
        }
        return [
            node
            for node in graph["nodes"]
            if node["kind"] == "finding"
            and node["payload"].get("status") == "certified"
            and node["id"] not in superseded
        ]

    def append_contradictory_observation(
        self,
        payload: dict[str, Any],
        *,
        contradicts: Iterable[str],
        dependencies: Iterable[str] = (),
        content_identity: str | None = None,
        verification_path: str,
        resolution_status: str = "disproved",
    ) -> dict[str, Any]:
        if resolution_status not in {"disproved", "superseded"}:
            raise EvidenceGraphError("contradiction resolution must be disproved or superseded")
        if not verification_path.strip():
            raise EvidenceGraphError("contradictory observations require a verification path")
        contradicted_ids = sorted(set(contradicts))
        if not contradicted_ids:
            raise EvidenceGraphError("contradictory observations require at least one prior observation")
        for node_id in contradicted_ids:
            if self.get_node(node_id)["kind"] != "normalized_observation":
                raise EvidenceGraphError("contradicts must reference normalized observations")
        relation_specs = [(node_id, "depends_on") for node_id in sorted(set(dependencies))]
        relation_specs.extend((node_id, "contradicts") for node_id in contradicted_ids)
        observation = self._append_node(
            "normalized_observation",
            payload,
            dependencies=relation_specs,
            content_identity=content_identity,
            verification_path=verification_path,
        )
        affected = []
        contradicted = set(contradicted_ids)
        for finding in self._active_certified_findings():
            if not (contradicted & self.transitive_dependencies(finding["id"])):
                continue
            revision = self.add_finding(
                finding["payload"]["finding_key"],
                finding["payload"]["statement"],
                resolution_status,
                dependencies=[observation["id"]],
                previous_finding_id=finding["id"],
                details={
                    "reason": "contradictory_observation",
                    "contradicted_observation_ids": contradicted_ids,
                },
            )
            affected.append(
                {
                    "previous_finding_id": finding["id"],
                    "revision_finding_id": revision["id"],
                    "status": resolution_status,
                }
            )
        return {"observation_id": observation["id"], "finding_revisions": affected}
