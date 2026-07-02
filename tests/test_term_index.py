import json
import tempfile
import unittest
from pathlib import Path

from typer.testing import CliRunner

from cerberus_re_skill.cli import app
from cerberus_re_skill.modules.term_index import build_term_index


class TermIndexTests(unittest.TestCase):
    def test_build_term_index_scans_common_export_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = root / "BundleA"
            bundle.mkdir()
            (bundle / "symbols.json").write_text(
                json.dumps(
                    {
                        "symbols": [
                            {
                                "name": "-[ExampleConfiguredAction(LNValue)_asLNValue]",
                                "address": "1000",
                                "artifact_type": "objc_method",
                            },
                            {"name": "unrelated", "address": "2000"},
                        ]
                    }
                ),
                encoding="utf-8",
            )
            (bundle / "strings.json").write_text(
                json.dumps(
                    {
                        "strings": [
                            {
                                "value": "remoteObjectProxy",
                                "address": "3000",
                                "artifact_type": "string",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            (bundle / "program_summary.json").write_text(
                json.dumps(
                    {
                        "source_image": "/System/Library/PrivateFrameworks/ExampleKit.framework/ExampleKit",
                        "purpose_note": "root metadata can mention remoteObjectProxy",
                        "memory_blocks": [{"name": "__TEXT", "start": "0x1000"}],
                    }
                ),
                encoding="utf-8",
            )

            out = root / "term-index.json"
            result = build_term_index(
                [f"workflow={bundle}"],
                ["ExampleConfiguredAction", "remoteObjectProxy"],
                output=str(out),
            )

            self.assertTrue(result["ok"])
            self.assertEqual(result["term_totals"]["ExampleConfiguredAction"], 1)
            self.assertEqual(result["term_totals"]["remoteObjectProxy"], 2)
            self.assertEqual(result["inputs"][0]["label"], "workflow")
            self.assertTrue(out.exists())
            self.assertTrue(out.with_suffix(".md").exists())
            saved = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(saved["output"], str(out))

    def test_build_term_index_records_missing_input_without_failing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "missing"
            result = build_term_index([str(missing)], ["needle"], output=str(Path(tmp) / "out.json"))

            self.assertTrue(result["ok"])
            self.assertFalse(result["inputs"][0]["exists"])
            self.assertEqual(result["term_totals"]["needle"], 0)
            self.assertEqual(result["warning_count"], 1)

    def test_build_term_index_warns_on_empty_existing_input(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            empty = Path(tmp) / "empty-export"
            empty.mkdir()
            output = Path(tmp) / "out.json"

            result = build_term_index([f"empty={empty}"], ["needle"], output=str(output))

            self.assertTrue(result["ok"])
            self.assertTrue(result["inputs"][0]["exists"])
            self.assertEqual(result["inputs"][0]["file_count"], 0)
            self.assertEqual(result["inputs"][0]["warning"], "input path contains no indexed JSON files")
            self.assertEqual(result["warning_count"], 1)
            self.assertIn("Warning", output.with_suffix(".md").read_text(encoding="utf-8"))

    def test_build_term_index_surfaces_swift_descriptor_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = root / "AppIntentsServices"
            bundle.mkdir()
            (bundle / "swift_metadata.json").write_text(
                json.dumps(
                    {
                        "field_descriptors": [
                            {
                                "address": "0x230c35cd0",
                                "kind": "struct",
                                "field_count": 4,
                                "mangled_type_name": {
                                    "display_value": "_symbolic_AppIntentsServices_FetchFileChunk_Request"
                                },
                                "fields": [{"field_name": {"value": "fileURL"}}],
                            }
                        ],
                        "capture_descriptors": [
                            {
                                "address": "0x230c3f000",
                                "capture_type_count": 1,
                                "capture_types": [
                                    {"mangled_type_name": {"display_value": "_symbolic_RemoteFileDispatching"}}
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            result = build_term_index(
                [str(bundle)],
                ["FetchFileChunk", "RemoteFileDispatching"],
                output=str(root / "term-index.json"),
                json_files=("swift_metadata.json",),
            )

            samples = result["inputs"][0]["samples"]
            self.assertEqual(result["term_totals"]["FetchFileChunk"], 1)
            self.assertEqual(result["term_totals"]["RemoteFileDispatching"], 1)
            self.assertFalse(any(item["path"] == "$" for item in samples))
            self.assertTrue(any(item["path"] == "field_descriptors[0]" for item in samples))
            self.assertTrue(any(item["path"] == "capture_descriptors[0]" for item in samples))
            descriptor = next(item for item in samples if item["path"] == "field_descriptors[0]")
            self.assertEqual(descriptor["record_summary"]["field_count"], 4)

    def test_cli_smoke(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = root / "BundleB"
            bundle.mkdir()
            (bundle / "function_inventory.json").write_text(
                json.dumps({"functions": [{"name": "fetchOptionsForAction", "entry": "4000"}]}),
                encoding="utf-8",
            )
            output = root / "cli-index.json"
            runner = CliRunner()
            result = runner.invoke(
                app,
                [
                    "export",
                    "term-index",
                    f"bundle={bundle}",
                    "--term",
                    "fetchOptionsForAction",
                    "--output",
                    str(output),
                ],
            )

            self.assertEqual(result.exit_code, 0, result.output)
            data = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(data["term_totals"]["fetchOptionsForAction"], 1)

    def test_cli_json_file_restricts_term_index_input(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = root / "BundleC"
            bundle.mkdir()
            (bundle / "symbols.json").write_text(
                json.dumps({"symbols": [{"name": "FetchFileChunk"}]}), encoding="utf-8"
            )
            (bundle / "swift_metadata.json").write_text(
                json.dumps({"field_descriptors": [{"address": "1000", "kind": "struct", "field_count": 1, "name": "FetchFileChunk"}]}),
                encoding="utf-8",
            )
            output = root / "cli-descriptor-index.json"
            runner = CliRunner()
            result = runner.invoke(
                app,
                [
                    "export",
                    "term-index",
                    str(bundle),
                    "--term",
                    "FetchFileChunk",
                    "--json-file",
                    "swift_metadata.json",
                    "--output",
                    str(output),
                ],
            )

            self.assertEqual(result.exit_code, 0, result.output)
            data = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(data["term_totals"]["FetchFileChunk"], 1)
            self.assertEqual(data["inputs"][0]["files"][0]["file"], "swift_metadata.json")


if __name__ == "__main__":
    unittest.main()
