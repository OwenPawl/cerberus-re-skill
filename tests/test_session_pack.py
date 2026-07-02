import json
import tempfile
import unittest
from pathlib import Path

from cerberus_re_skill.modules.session_pack import (
    SESSION_PACK_REPORT_SCHEMA,
    SESSION_PACK_SCHEMA,
    default_session_pack_manifest,
    render_session_pack_report,
    validate_session_pack,
    write_default_session_pack_manifest,
)


class SessionPackTests(unittest.TestCase):
    def test_default_session_pack_manifest_shape(self) -> None:
        manifest = default_session_pack_manifest()

        self.assertEqual(manifest["schema"], SESSION_PACK_SCHEMA)
        self.assertGreaterEqual(len(manifest["targets"]), 3)
        self.assertIn("runtime_evidence", manifest["report_sections"])
        self.assertTrue(any(target["id"] == "owned-host" for target in manifest["targets"]))
        self.assertIn("selector:<selected selector>", manifest["seeds"])

    def test_write_default_session_pack_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "session-pack.json"
            result = write_default_session_pack_manifest(path)
            payload = json.loads(path.read_text(encoding="utf-8"))

        self.assertTrue(result["ok"])
        self.assertEqual(result["schema"], SESSION_PACK_SCHEMA)
        self.assertEqual(payload["schema"], SESSION_PACK_SCHEMA)
        self.assertEqual(result["targets"], len(payload["targets"]))

    def test_validate_session_pack_artifacts(self) -> None:
        manifest = default_session_pack_manifest()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runtime = root / "runtime_hits_enriched.json"
            runtime.write_text(
                json.dumps(
                    {
                        "schema": "ghidra-re.runtime-hits.v1",
                        "enriched": True,
                        "hit_count": 1,
                        "tools": ["frida"],
                        "enrichment": {"matched_function_count": 1, "slide_confidence": "medium"},
                        "hits": [
                            {
                                "symbol": "-[ExampleManager privilegedStateWithError:]",
                                "tool": "frida",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            xpc_graph = root / "example-xpc-graph.json"
            xpc_graph.write_text(
                json.dumps({"schema": "ghidra-re.xpc-graph.v1", "summary": {"edge_count": 2}, "edges": [1, 2]}),
                encoding="utf-8",
            )

            result = validate_session_pack(
                manifest,
                artifact_specs=[
                    f"runtime:primary:{runtime}",
                    f"xpc-graph:related-service:{xpc_graph}",
                ],
            )

        self.assertTrue(result["ok"])
        self.assertEqual(result["errors"], [])
        self.assertEqual(len(result["artifacts"]), 2)

    def test_render_session_pack_report_writes_json_and_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest_path = root / "session-pack.json"
            write_default_session_pack_manifest(manifest_path)
            runtime = root / "runtime_hits.json"
            runtime.write_text(
                json.dumps(
                    {
                        "schema": "ghidra-re.runtime-hits.v1",
                        "hit_count": 1,
                        "hits": [{"symbol": "-[ExampleManager privilegedStateWithError:]"}],
                    }
                ),
                encoding="utf-8",
            )

            result = render_session_pack_report(
                manifest_path,
                artifacts=[f"runtime:primary:{runtime}"],
                output_dir=root / "out",
            )
            payload = json.loads(Path(result["report_json"]).read_text(encoding="utf-8"))
            markdown = Path(result["report_markdown"]).read_text(encoding="utf-8")

        self.assertTrue(result["ok"])
        self.assertEqual(result["schema"], SESSION_PACK_REPORT_SCHEMA)
        self.assertEqual(payload["schema"], SESSION_PACK_REPORT_SCHEMA)
        self.assertIn("runtime_evidence", payload["sections"])
        self.assertIn("Runtime Evidence", markdown)


if __name__ == "__main__":
    unittest.main()
