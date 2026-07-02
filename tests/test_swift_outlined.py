import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cerberus_re_skill.core.config import cfg
from cerberus_re_skill.modules.swift_outlined import resolve_swift_outlined


class SwiftOutlinedTests(unittest.TestCase):
    def test_resolve_swift_outlined_runs_script_and_reads_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp)
            seen: dict[str, object] = {}

            def fake_run_script(script: str, project: str, program: str, script_args: list[str]) -> dict:
                seen.update(
                    {
                        "script": script,
                        "project": project,
                        "program": program,
                        "script_args": script_args,
                    }
                )
                (out_dir / "swift_outlined_resolved.json").write_text(
                    json.dumps(
                        {
                            "dry_run": True,
                            "total_outlined_functions": 12,
                            "renamed": 0,
                            "inlined": 0,
                            "skipped_stubs": 3,
                            "pactail_updated_pass2": 0,
                            "pactail_slot_resolved_pass3": 2,
                            "categories": {"authstub": 9, "helper": 3},
                        }
                    ),
                    encoding="utf-8",
                )
                return {"ok": True, "script_name": script}

            with patch("cerberus_re_skill.modules.importer.run_script", side_effect=fake_run_script):
                result = resolve_swift_outlined(
                    "proj",
                    "Program",
                    output_dir=out_dir,
                    dry_run=True,
                    inline=False,
                    skip_stubs=True,
                    scan_fun_stubs=False,
                    second_pass=False,
                    authstub_map=out_dir / "authstub_map.json",
                )

        self.assertTrue(result["ok"])
        self.assertEqual(seen["script"], "ResolveSwiftOutlined.java")
        self.assertIn("dry_run=true", seen["script_args"])
        self.assertIn("inline=false", seen["script_args"])
        self.assertIn("skip_stubs=true", seen["script_args"])
        self.assertIn("scan_fun_stubs=false", seen["script_args"])
        self.assertIn("second_pass=false", seen["script_args"])
        self.assertEqual(result["summary"]["total_outlined_functions"], 12)
        self.assertEqual(result["summary"]["pactail_slot_resolved_pass3"], 2)
        self.assertTrue(result["artifact_status"]["exists"])

    def test_resolve_swift_outlined_defaults_to_export_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            exports = Path(tmp) / "exports"

            def fake_run_script(script: str, project: str, program: str, script_args: list[str]) -> dict:
                out_arg = next(arg for arg in script_args if arg.startswith("output_dir="))
                out_dir = Path(out_arg.split("=", 1)[1])
                out_dir.mkdir(parents=True, exist_ok=True)
                (out_dir / "swift_outlined_resolved.json").write_text("{}", encoding="utf-8")
                return {"ok": True, "script_name": script}

            with (
                patch.object(cfg, "exports_dir", exports),
                patch("cerberus_re_skill.modules.importer.run_script", side_effect=fake_run_script),
            ):
                result = resolve_swift_outlined("proj", "Program")

        self.assertEqual(result["output_dir"], str(exports / "proj" / "Program"))
        self.assertEqual(result["report"], str(exports / "proj" / "Program" / "swift_outlined_resolved.json"))


if __name__ == "__main__":
    unittest.main()
