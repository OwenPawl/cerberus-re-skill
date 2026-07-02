import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cerberus_re_skill.core.config import cfg
from cerberus_re_skill.modules.triage import export_triage_bundle, export_function_dossier


class TriageExportTests(unittest.TestCase):
    def test_export_triage_bundle_runs_expected_scripts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = root / "patterns.json"
            manifest.write_text("{}", encoding="utf-8")
            output = root / "triage"
            calls: list[tuple[str, str, str, list[str]]] = []

            def fake_run_script(script: str, project: str, program: str, script_args: list[str]) -> dict:
                calls.append((script, project, program, script_args))
                out_arg = next((arg for arg in script_args if arg.startswith("output=")), "")
                if out_arg:
                    path = Path(out_arg.split("=", 1)[1])
                    key = {
                        "ExportEntrypoints.java": "entrypoint_count",
                        "ExportSinks.java": "sink_count",
                        "TriagePaths.java": "candidate_count",
                    }[script]
                    path.write_text(json.dumps({key: 7}), encoding="utf-8")
                summary_arg = next((arg for arg in script_args if arg.startswith("summary=")), "")
                if summary_arg:
                    Path(summary_arg.split("=", 1)[1]).write_text("# Summary\n", encoding="utf-8")
                return {"ok": True, "script_name": script}

            with patch("cerberus_re_skill.modules.importer.run_script", side_effect=fake_run_script):
                result = export_triage_bundle(
                    "proj",
                    "Program",
                    output_dir=output,
                    manifest=manifest,
                    sample_limit=3,
                    max_depth=2,
                    max_visited_functions=50,
                    top_candidates=5,
                    xref_limit=6,
                    entrypoint_limit=8,
                )

        self.assertTrue(result["ok"])
        self.assertEqual([call[0] for call in calls], [
            "ExportEntrypoints.java",
            "ExportSinks.java",
            "TriagePaths.java",
        ])
        self.assertEqual(result["counts"]["entrypoint_count"], 7)
        self.assertEqual(result["counts"]["sink_count"], 7)
        self.assertEqual(result["counts"]["candidate_count"], 7)
        self.assertEqual(result["counts"]["entrypoint_match_count"], 7)
        self.assertEqual(result["counts"]["sink_match_count"], 7)
        self.assertTrue(result["artifact_status"]["candidate_paths.json"]["exists"])
        self.assertIn("max_depth=2", calls[2][3])
        self.assertIn("entrypoint_limit=8", calls[2][3])

    def test_export_function_dossier_runs_by_address(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = root / "patterns.json"
            manifest.write_text("{}", encoding="utf-8")
            output = root / "dossier"
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
                output_arg = next(arg for arg in script_args if arg.startswith("output_dir="))
                dossier_dir = Path(output_arg.split("=", 1)[1])
                dossier_dir.mkdir(parents=True, exist_ok=True)
                (dossier_dir / "context.json").write_text("{}", encoding="utf-8")
                (dossier_dir / "decompile.c").write_text("void target(void) {}\n", encoding="utf-8")
                (dossier_dir / "linear_instructions.txt").write_text("body 0x1000: ret\n", encoding="utf-8")
                (dossier_dir / "summary.md").write_text("# Summary\n", encoding="utf-8")
                return {"ok": True, "script_name": script}

            with patch("cerberus_re_skill.modules.importer.run_script", side_effect=fake_run_script):
                result = export_function_dossier(
                    "proj",
                    "Program",
                    address="0x1000",
                    output_dir=output,
                    manifest=manifest,
                    sample_limit=4,
                    linear_instruction_limit=33,
                    timeout=11,
                )

        self.assertTrue(result["ok"])
        self.assertEqual(seen["script"], "ExportFunctionDossier.java")
        self.assertIn("address=0x1000", seen["script_args"])
        self.assertIn("timeout=11", seen["script_args"])
        self.assertIn("linear_instruction_limit=33", seen["script_args"])
        self.assertEqual(result["outputs"]["summary"], str(output / "summary.md"))
        self.assertEqual(result["outputs"]["linear_instructions"], str(output / "linear_instructions.txt"))
        self.assertIn("decompile.c", result["artifact_status"])
        self.assertIn("linear_instructions.txt", result["artifact_status"])

    def test_export_function_dossier_classifies_missing_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = root / "patterns.json"
            manifest.write_text("{}", encoding="utf-8")

            def fake_run_script(script: str, project: str, program: str, script_args: list[str]) -> dict:
                return {"ok": True, "script_name": script}

            with patch("cerberus_re_skill.modules.importer.run_script", side_effect=fake_run_script):
                result = export_function_dossier(
                    "proj",
                    "Program",
                    address="0x1000",
                    output_dir=root / "missing-dossier",
                    manifest=manifest,
                )

        self.assertFalse(result["ok"])
        self.assertEqual(
            result["missing_artifacts"],
            ["context.json", "decompile.c", "linear_instructions.txt", "summary.md"],
        )
        self.assertIn("did not produce required artifacts", result["failure_reason"])

    def test_export_function_dossier_requires_target(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "either function or address"):
            export_function_dossier("proj", "Program")

    def test_function_dossier_script_accepts_objc_class_and_instance_lookup_forms(self) -> None:
        support = Path("scripts/ghidra_scripts/TriageSupport.java").read_text(encoding="utf-8")

        self.assertIn('candidates.add("-[" + owner + " " + facts.name + "]");', support)
        self.assertIn('candidates.add("+[" + owner + " " + facts.name + "]");', support)

    def test_function_dossier_records_external_thunk_imports(self) -> None:
        support = Path("scripts/ghidra_scripts/TriageSupport.java").read_text(encoding="utf-8")

        self.assertIn("externalThunkTargetName(callee)", support)
        self.assertIn("function.getThunkedFunction(true)", support)
        self.assertIn("facts.importedApis.add(externalThunkName)", support)

    def test_function_dossier_reports_named_block_invoke_references(self) -> None:
        script = Path("scripts/ghidra_scripts/ExportFunctionDossier.java").read_text(encoding="utf-8")

        self.assertIn('"referenced_block_invoke_functions"', script)
        self.assertIn('candidate.name.contains("block_invoke")', script)
        self.assertIn('candidate.name.replaceAll("[^A-Za-z0-9_]", "_")', script)

    def test_function_dossier_preserves_linear_instructions_for_truncation_review(self) -> None:
        script = Path("scripts/ghidra_scripts/ExportFunctionDossier.java").read_text(encoding="utf-8")

        self.assertIn('"linear_instruction_window"', script)
        self.assertIn('"analysis_warnings"', script)
        self.assertIn('"linear_instructions.txt"', script)
        self.assertIn("possible_authstub_truncation", script)
        self.assertIn("hasNoReturnAuthStubCallee", script)

    def test_default_paths_use_export_dir_and_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = root / "patterns.json"
            manifest.write_text("{}", encoding="utf-8")
            exports = root / "exports"

            def fake_run_script(script: str, project: str, program: str, script_args: list[str]) -> dict:
                out_arg = next(arg for arg in script_args if arg.startswith("output="))
                Path(out_arg.split("=", 1)[1]).write_text('{"entrypoint_count": 1}', encoding="utf-8")
                return {"ok": True, "script_name": script}

            with (
                patch.object(cfg, "exports_dir", exports),
                patch.object(cfg, "triage_manifest", manifest),
                patch("cerberus_re_skill.modules.importer.run_script", side_effect=fake_run_script),
            ):
                result = export_triage_bundle("proj", "Program")

        self.assertEqual(result["manifest"], str(manifest))
        self.assertEqual(result["output_dir"], str(exports / "proj" / "Program" / "triage"))


if __name__ == "__main__":
    unittest.main()
