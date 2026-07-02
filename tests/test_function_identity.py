import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cerberus_re_skill.modules.function_identity import (
    build_function_identity_report,
    normalize_function_identity,
)
from cerberus_re_skill.modules.lldb_enrich import _apply_runtime_finding, _decompile_function


class FunctionIdentityTests(unittest.TestCase):
    def test_normalizes_headless_and_bridge_function_shapes(self) -> None:
        headless = normalize_function_identity(
            {
                "name": "runWithInput:",
                "namespace": "CodexProbe",
                "entry": "100000928",
                "signature": "id runWithInput:(id)input",
                "body_size": 140,
            },
            source="headless",
            project="codex_objc_probe",
            program="CodexObjCProbe",
        )
        bridge = normalize_function_identity(
            {
                "function_ref": {
                    "program_path": "/tmp/CodexObjCProbe",
                    "entry": "100000928",
                },
                "name": "runWithInput:",
                "entry": "100000928",
                "body": {"ranges": [{"start": "100000928", "end": "1000009b3"}]},
            },
            source="bridge",
        )

        self.assertEqual(headless["entry"], "0x100000928")
        self.assertEqual(headless["symbol"], "-[CodexProbe runWithInput:]")
        self.assertEqual(bridge["entry"], "0x100000928")
        self.assertEqual(bridge["body_size"], 140)
        self.assertIn("/tmp/CodexObjCProbe", bridge["identity_key"])

    def test_builds_headless_live_identity_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            headless = root / "function_inventory.json"
            live = root / "live_functions.json"
            output = root / "report.json"

            headless.write_text(
                json.dumps(
                    {
                        "program_name": "CodexObjCProbe",
                        "functions": [
                            {"name": "runWithInput:", "namespace": "CodexProbe", "entry": "100000928"},
                            {"name": "onlyHeadless", "entry": "100000a00"},
                        ],
                    }
                ),
                encoding="utf-8",
            )
            live.write_text(
                json.dumps(
                    {
                        "ok": True,
                        "result": {
                            "matches": [
                                {
                                    "name": "runWithInput:",
                                    "function_ref": {"entry": "100000928"},
                                    "body": [{"start": "100000928", "end": "1000009b3"}],
                                },
                                {"name": "onlyLive", "function_ref": {"entry": "100000b00"}},
                            ]
                        },
                    }
                ),
                encoding="utf-8",
            )

            report = build_function_identity_report(
                project="codex_objc_probe",
                program="CodexObjCProbe",
                headless_path=headless,
                live_path=live,
                output=output,
            )
            self.assertTrue(output.exists())

        self.assertEqual(report["matched_count"], 1)
        self.assertEqual(len(report["missing_in_live"]), 1)
        self.assertEqual(len(report["extra_in_live"]), 1)

    def test_decompile_cache_writes_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            export_dir = Path(tmp)

            def fake_run_script(**kwargs):
                output_arg = next(arg for arg in kwargs["script_args"] if arg.startswith("output="))
                Path(output_arg.removeprefix("output=")).write_text("void f(void) {}\n", encoding="utf-8")
                return {"ok": True}

            with patch("cerberus_re_skill.modules.importer.run_script", side_effect=fake_run_script):
                result = _decompile_function(
                    project="codex_objc_probe",
                    program="CodexObjCProbe",
                    func={"name": "runWithInput:", "namespace": "CodexProbe", "entry": "100000928"},
                    export_dir=export_dir,
                    timeout=30,
                )

            provenance = json.loads(Path(result["provenance_path"]).read_text(encoding="utf-8"))

        self.assertEqual(provenance["schema"], "ghidra-re.decompile-cache-provenance.v1")
        self.assertEqual(provenance["function_identity"]["symbol"], "-[CodexProbe runWithInput:]")
        self.assertIn("DecompileFunction.java", provenance["source_command"])

    def test_auto_apply_skips_existing_runtime_finding_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            export_dir = Path(tmp)
            findings = export_dir / "findings"
            findings.mkdir()
            existing = findings / "runtime-observed-100000928.json"
            existing.write_text('{"ok":true}\n', encoding="utf-8")

            result = _apply_runtime_finding(
                project="codex_objc_probe",
                program="CodexObjCProbe",
                entry="100000928",
                function_name="runWithInput:",
                comment="Observed at runtime",
                export_dir=export_dir,
            )

        self.assertTrue(result["ok"])
        self.assertTrue(result["skipped"])
        self.assertEqual(result["output"], str(existing))


if __name__ == "__main__":
    unittest.main()
