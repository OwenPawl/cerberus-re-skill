import hashlib
import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from cerberus_re_skill.modules.evidence_graph import (
    CertificationError,
    CorruptEvidenceGraph,
    EvidenceGraphError,
    EvidenceGraphStore,
    read_graph_export,
)


def content_id(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


class EvidenceGraphTests(unittest.TestCase):
    def make_store(self, root: Path) -> EvidenceGraphStore:
        return EvidenceGraphStore(root / "evidence")

    def add_certified_chain(
        self,
        store: EvidenceGraphStore,
        *,
        suffix: str = "",
    ) -> tuple[dict, dict, dict, dict]:
        raw = store.add_raw_artifact(
            {"path": f"binary{suffix}", "size": 4},
            content_identity=content_id(f"raw{suffix}".encode()),
            verification_path=f"artifacts/raw{suffix}.sha256",
        )
        observation = store.add_observation(
            {"address": "0x1000", "value": f"observed{suffix}"},
            dependencies=[raw["id"]],
            verification_path=f"traces/observation{suffix}.json",
        )
        hypothesis = store.add_hypothesis(
            {"statement": f"candidate meaning{suffix}"},
            dependencies=[observation["id"]],
            verification_path=f"analysis/hypothesis{suffix}.md",
        )
        finding = store.add_finding(
            f"finding{suffix}",
            f"supported behavior{suffix}",
            "certified",
            dependencies=[hypothesis["id"]],
            verification_path=f"findings/finding{suffix}.json",
        )
        return raw, observation, hypothesis, finding

    def test_content_addressing_is_idempotent_and_concurrent_safe(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = self.make_store(Path(tmp))

            def append() -> str:
                node = store.add_raw_artifact(
                    {"path": "sample.bin", "size": 7},
                    content_identity=content_id(b"sample"),
                    verification_path="sample.bin.sha256",
                )
                return node["id"]

            with ThreadPoolExecutor(max_workers=8) as pool:
                node_ids = list(pool.map(lambda _: append(), range(24)))

            self.assertEqual(len(set(node_ids)), 1)
            self.assertEqual(len(list(store.records_dir.glob("*.json"))), 1)
            self.assertFalse(list(store.records_dir.glob(".*.tmp")))

            distinct = store.add_raw_artifact(
                {"path": "sample.bin", "size": 8},
                content_identity=content_id(b"sample-2"),
                verification_path="sample-2.bin.sha256",
            )
            self.assertNotEqual(distinct["id"], node_ids[0])

    def test_four_node_graph_has_deterministic_edges_and_export(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = self.make_store(root)
            raw, observation, hypothesis, finding = self.add_certified_chain(store)
            export_path = root / "graph.json"

            graph = store.write_export(export_path)
            first_bytes = export_path.read_bytes()
            store.write_export(export_path)

            self.assertEqual(export_path.read_bytes(), first_bytes)
            self.assertEqual(read_graph_export(export_path), graph)
            self.assertEqual(
                {node["kind"] for node in graph["nodes"]},
                {"raw_artifact", "normalized_observation", "hypothesis", "finding"},
            )
            self.assertEqual([node["id"] for node in graph["nodes"]], sorted(
                [raw["id"], observation["id"], hypothesis["id"], finding["id"]]
            ))
            self.assertEqual(len(graph["edges"]), 3)
            self.assertTrue(all(edge["relation"] == "depends_on" for edge in graph["edges"]))
            self.assertEqual(
                store.transitive_dependencies(finding["id"]),
                {raw["id"], observation["id"], hypothesis["id"]},
            )

    def test_graph_identity_is_independent_of_insertion_and_dependency_order(self) -> None:
        with tempfile.TemporaryDirectory() as first_tmp, tempfile.TemporaryDirectory() as second_tmp:
            first = self.make_store(Path(first_tmp))
            second = self.make_store(Path(second_tmp))

            first_a = first.add_raw_artifact(
                {"name": "a"},
                content_identity=content_id(b"a"),
                verification_path="a.sha256",
            )
            first_b = first.add_raw_artifact(
                {"name": "b"},
                content_identity=content_id(b"b"),
                verification_path="b.sha256",
            )
            first_observation = first.add_observation(
                {"value": 1},
                dependencies=[first_b["id"], first_a["id"]],
                verification_path="observation.json",
            )

            second_b = second.add_raw_artifact(
                {"name": "b"},
                content_identity=content_id(b"b"),
                verification_path="b.sha256",
            )
            second_a = second.add_raw_artifact(
                {"name": "a"},
                content_identity=content_id(b"a"),
                verification_path="a.sha256",
            )
            second_observation = second.add_observation(
                {"value": 1},
                dependencies=[second_a["id"], second_b["id"]],
                verification_path="observation.json",
            )

            self.assertEqual(first_observation["id"], second_observation["id"])
            self.assertEqual(first.export_graph(), second.export_graph())

    def test_certification_requires_identity_and_verification_for_full_closure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = self.make_store(Path(tmp))
            raw = store.add_raw_artifact(
                {"path": "unverified.bin"},
                content_identity=content_id(b"raw"),
            )
            observation = store.add_observation(
                {"value": "seen"},
                dependencies=[raw["id"]],
                content_identity="",
                verification_path="observation.json",
            )
            hypothesis = store.add_hypothesis(
                {"statement": "possible"},
                dependencies=[observation["id"]],
                verification_path="hypothesis.md",
            )

            with self.assertRaisesRegex(CertificationError, "content_identity"):
                store.add_finding(
                    "unverified",
                    "not yet certifiable",
                    "certified",
                    dependencies=[hypothesis["id"]],
                )
            with self.assertRaisesRegex(CertificationError, "verification_path"):
                store.add_finding(
                    "raw-unverified",
                    "not yet certifiable",
                    "certified",
                    dependencies=[raw["id"]],
                )
            with self.assertRaisesRegex(CertificationError, "at least one dependency"):
                store.add_finding("empty", "unsupported", "certified")

    def test_finding_statuses_and_revision_contract_are_strict(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = self.make_store(Path(tmp))
            proposed = store.add_finding("key", "candidate", "proposed")

            with self.assertRaisesRegex(EvidenceGraphError, "unknown finding status"):
                store.add_finding("key", "candidate", "accepted")
            with self.assertRaisesRegex(EvidenceGraphError, "require previous_finding_id"):
                store.add_finding("key", "candidate", "disproved")
            with self.assertRaisesRegex(EvidenceGraphError, "preserve finding_key"):
                store.add_finding(
                    "other-key",
                    "candidate",
                    "superseded",
                    previous_finding_id=proposed["id"],
                )

    def test_contradiction_appends_disproof_without_rewriting_history(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = self.make_store(Path(tmp))
            _, observation, _, finding = self.add_certified_chain(store)
            unaffected_chain = self.add_certified_chain(store, suffix="-unaffected")
            old_record = store._record_path(finding["id"])
            old_bytes = old_record.read_bytes()
            new_raw = store.add_raw_artifact(
                {"path": "counterexample.bin"},
                content_identity=content_id(b"counterexample"),
                verification_path="counterexample.sha256",
            )

            result = store.append_contradictory_observation(
                {"address": "0x1000", "value": "counterexample"},
                contradicts=[observation["id"]],
                dependencies=[new_raw["id"]],
                verification_path="traces/counterexample.json",
            )

            self.assertEqual(old_record.read_bytes(), old_bytes)
            self.assertEqual(len(result["finding_revisions"]), 1)
            revision_id = result["finding_revisions"][0]["revision_finding_id"]
            revision = store.get_node(revision_id)
            self.assertEqual(revision["payload"]["status"], "disproved")
            self.assertIn(finding["id"], {
                item["node_id"]
                for item in revision["dependencies"]
                if item["relation"] == "supersedes"
            })
            graph = store.export_graph()
            self.assertIn(finding["id"], {node["id"] for node in graph["nodes"]})
            self.assertIn(revision_id, {node["id"] for node in graph["nodes"]})
            self.assertIn(unaffected_chain[3]["id"], {
                node["id"]
                for node in store._active_certified_findings()
            })
            repeated = store.append_contradictory_observation(
                {"address": "0x1000", "value": "counterexample"},
                contradicts=[observation["id"]],
                dependencies=[new_raw["id"]],
                verification_path="traces/counterexample.json",
            )
            self.assertEqual(repeated["observation_id"], result["observation_id"])
            self.assertEqual(repeated["finding_revisions"], [])

    def test_contradiction_can_append_superseded_revision(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = self.make_store(Path(tmp))
            _, observation, _, finding = self.add_certified_chain(store)

            result = store.append_contradictory_observation(
                {"value": "replacement evidence"},
                contradicts=[observation["id"]],
                verification_path="replacement.json",
                resolution_status="superseded",
            )

            revision = store.get_node(result["finding_revisions"][0]["revision_finding_id"])
            self.assertEqual(revision["payload"]["status"], "superseded")
            self.assertEqual(result["finding_revisions"][0]["previous_finding_id"], finding["id"])

    def test_corrupt_and_conflicting_records_are_rejected_not_replaced(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = self.make_store(Path(tmp))
            kwargs = {
                "payload": {"path": "sample.bin"},
                "content_identity": content_id(b"sample"),
                "verification_path": "sample.sha256",
            }
            node = store.add_raw_artifact(**kwargs)
            path = store._record_path(node["id"])
            path.write_text("not-json\n", encoding="utf-8")

            with self.assertRaises(CorruptEvidenceGraph):
                store.add_raw_artifact(**kwargs)
            self.assertEqual(path.read_text(encoding="utf-8"), "not-json\n")

        with tempfile.TemporaryDirectory() as tmp:
            store = self.make_store(Path(tmp))
            node = store.add_raw_artifact(**kwargs)
            path = store._record_path(node["id"])
            conflicting = {"schema": "conflict"}
            path.write_text(json.dumps(conflicting), encoding="utf-8")

            with self.assertRaisesRegex(CorruptEvidenceGraph, "conflicting"):
                store.add_raw_artifact(**kwargs)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), conflicting)

    def test_corrupt_export_and_missing_dependency_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = self.make_store(root)
            self.add_certified_chain(store)
            export_path = root / "graph.json"
            graph = store.write_export(export_path)
            graph["edges"].pop()
            export_path.write_text(json.dumps(graph), encoding="utf-8")

            with self.assertRaisesRegex(CorruptEvidenceGraph, "edges are not canonical"):
                read_graph_export(export_path)

            record_path = next(
                path
                for path in store.records_dir.glob("*.json")
                if json.loads(path.read_text(encoding="utf-8"))["node"]["kind"] == "raw_artifact"
            )
            record_path.unlink()
            with self.assertRaisesRegex(CorruptEvidenceGraph, "missing dependency"):
                store.export_graph()


if __name__ == "__main__":
    unittest.main()
