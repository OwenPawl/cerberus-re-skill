import json
import tempfile
import unittest
from pathlib import Path

from cerberus_re_skill.modules.mission_checkpoint import (
    CheckpointCoordinator,
    CheckpointError,
    CheckpointStore,
)


SHA_A = "a" * 64
SHA_B = "b" * 64


class _Provider:
    name = "runtime"

    def __init__(self) -> None:
        self.restored = False

    def prepare(self, transaction_id: str) -> dict:
        return {"prepared": transaction_id}

    def checkpoint(self, transaction_id: str) -> dict:
        return {"cursor": 7, "transaction_id": transaction_id}

    def verify(self, transaction_id: str, payload: dict) -> dict:
        return {"ok": payload.get("cursor") == 7, "transaction_id": transaction_id}

    def restore(self, transaction_id: str, payload: dict) -> dict:
        self.restored = True
        return {"ok": True, "cursor": payload["cursor"], "transaction_id": transaction_id}


def _target() -> dict:
    return {
        "application_id": "ephemeral-app",
        "tool_id": "ephemeral-tool",
        "program_id": "ephemeral-program",
        "project_id": "stable-project",
        "project_path": "/tmp/demo.gpr",
        "program_path": "/Demo",
        "executable_sha256": SHA_A,
    }


def _dependencies() -> list[dict]:
    return [
        {
            "id": "static-export",
            "kind": "artifact",
            "content_sha256": SHA_B,
            "verification": "sha256sum static-export.json",
        }
    ]


class MissionCheckpointTests(unittest.TestCase):
    def test_provider_transaction_round_trip_and_bounded_resume_pack(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            provider = _Provider()
            store = CheckpointStore(Path(tmp) / "checkpoints")
            coordinator = CheckpointCoordinator(store, [provider])
            prepared = coordinator.prepare(
                "tx-one",
                mission_id="mission-one",
                target=_target(),
                dependencies=_dependencies(),
            )
            checkpointed = coordinator.checkpoint(
                "tx-one",
                routing={"program_id": "ephemeral-program", "bridge_url": "redacted"},
                expected_generation=prepared["generation"],
            )
            verified = coordinator.verify("tx-one")
            restored = coordinator.restore("tx-one")
            pack = store.resume_pack("tx-one", max_bytes=4096)

        self.assertEqual(checkpointed["generation"], 2)
        self.assertTrue(verified["providers"]["runtime"]["ok"])
        self.assertTrue(provider.restored)
        self.assertEqual(restored["provider_payloads"]["runtime"]["cursor"], 7)
        self.assertEqual(pack["target"]["executable_sha256"], SHA_A)
        self.assertIn("re-observe", pack["restore_policy"])
        self.assertLessEqual(pack["size_bytes"], 4096)

    def test_resume_pack_fails_instead_of_truncating(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = CheckpointStore(tmp)
            store.prepare(
                "tx-size",
                mission_id="mission-size",
                target=_target(),
                dependencies=_dependencies(),
                providers={},
            )
            store.checkpoint(
                "tx-size",
                routing={"large": "x" * 2048},
                provider_payloads={},
            )
            with self.assertRaisesRegex(CheckpointError, "exceeding max_bytes"):
                store.resume_pack("tx-size", max_bytes=128)

    def test_generation_compare_and_swap_rejects_stale_writer(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = CheckpointStore(tmp)
            store.prepare(
                "tx-cas",
                mission_id="mission-cas",
                target=_target(),
                dependencies=_dependencies(),
                providers={},
            )
            store.checkpoint(
                "tx-cas",
                routing={},
                provider_payloads={},
                expected_generation=1,
            )
            with self.assertRaisesRegex(CheckpointError, "generation changed"):
                store.checkpoint(
                    "tx-cas",
                    routing={},
                    provider_payloads={},
                    expected_generation=1,
                )

    def test_corrupt_content_addressed_object_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = CheckpointStore(tmp)
            store.prepare(
                "tx-corrupt",
                mission_id="mission-corrupt",
                target=_target(),
                dependencies=_dependencies(),
                providers={},
            )
            store.checkpoint(
                "tx-corrupt",
                routing={"program_id": "one"},
                provider_payloads={},
            )
            routing = next((Path(tmp) / "tx-corrupt" / "objects" / "routing").glob("*.json"))
            routing.write_text(json.dumps({"program_id": "tampered"}), encoding="utf-8")
            with self.assertRaisesRegex(CheckpointError, "object digest mismatch"):
                store.verify("tx-corrupt")

    def test_broken_event_chain_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = CheckpointStore(tmp)
            store.prepare(
                "tx-chain",
                mission_id="mission-chain",
                target=_target(),
                dependencies=_dependencies(),
                providers={},
            )
            store.checkpoint("tx-chain", routing={}, provider_payloads={})
            event = sorted((Path(tmp) / "tx-chain" / "events").glob("*.json"))[1]
            payload = json.loads(event.read_text(encoding="utf-8"))
            payload["previous_event_sha256"] = "0" * 64
            event.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(CheckpointError, "missing or corrupt event"):
                store.verify("tx-chain")

    def test_secret_bearing_payload_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = CheckpointStore(tmp)
            store.prepare(
                "tx-secret",
                mission_id="mission-secret",
                target=_target(),
                dependencies=_dependencies(),
                providers={},
            )
            with self.assertRaisesRegex(CheckpointError, "secret-bearing field"):
                store.checkpoint(
                    "tx-secret",
                    routing={"bridge": {"token": "must-not-persist"}},
                    provider_payloads={},
                )

    def test_uncommitted_orphan_event_does_not_corrupt_head(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = CheckpointStore(tmp)
            store.prepare(
                "tx-orphan",
                mission_id="mission-orphan",
                target=_target(),
                dependencies=_dependencies(),
                providers={},
            )
            events = Path(tmp) / "tx-orphan" / "events"
            (events / f"00000002-checkpointed-{'f' * 64}.json").write_text(
                json.dumps(
                    {
                        "schema_version": "cerberus.re.checkpoint.v1",
                        "transaction_id": "tx-orphan",
                        "generation": 2,
                        "event": "checkpointed",
                        "previous_event_sha256": "f" * 64,
                    }
                ),
                encoding="utf-8",
            )

            verified = store.verify("tx-orphan")

        self.assertEqual(verified["generation"], 1)

    def test_dependencies_require_identity_and_verification(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = CheckpointStore(tmp)
            with self.assertRaisesRegex(CheckpointError, "requires verification"):
                store.prepare(
                    "tx-invalid",
                    mission_id="mission-invalid",
                    target=_target(),
                    dependencies=[
                        {
                            "id": "unverified",
                            "kind": "artifact",
                            "content_sha256": SHA_B,
                        }
                    ],
                    providers={},
                )


if __name__ == "__main__":
    unittest.main()
