import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cerberus_re_skill.core.config import cfg
from cerberus_re_skill.modules.importer import _stage_macho_arch, import_analyze, run_script


class ImportAnalyzeTests(unittest.TestCase):
    def _capture_import_command(
        self,
        skip_macho_reexports: bool,
        *,
        macho_arch: str = "",
        disable_analysis_options: list[str] | None = None,
    ) -> tuple[list[str], dict]:
        commands: list[list[str]] = []

        def runner(command, **_kwargs):
            commands.append(list(command))

        @contextmanager
        def unlocked(*_args, **_kwargs):
            yield Path("/tmp/import-lock")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "Demo"
            binary.write_bytes(b"demo")
            staged = root / "sources" / "macho-slices" / "abc" / "Demo.arm64e"
            with (
                patch.object(cfg, "projects_dir", root / "projects"),
                patch.object(cfg, "logs_dir", root / "logs"),
                patch.object(cfg, "import_demangle", "0"),
                patch.object(cfg, "sources_cache_dir", root / "sources"),
                patch(
                    "cerberus_re_skill.modules.importer._stage_macho_arch",
                    return_value=(
                        staged,
                        {
                            "requested_arch": "arm64e",
                            "available_archs": ["x86_64", "arm64e"],
                            "staged": True,
                            "original_binary": str(binary),
                            "staged_binary": str(staged),
                        },
                    ),
                ) as stage_macho_arch,
                patch("cerberus_re_skill.modules.importer._headless", return_value=Path("/bin/analyzeHeadless")),
                patch("cerberus_re_skill.modules.importer.run", side_effect=runner),
                patch("cerberus_re_skill.modules.importer.project_headless_lock", side_effect=unlocked),
                patch("cerberus_re_skill.modules.bridge.require_tools"),
                patch("cerberus_re_skill.modules.bridge.export_env", return_value={}),
                patch("cerberus_re_skill.modules.bridge.ensure_workspace"),
            ):
                result = import_analyze(
                    binary,
                    "demo",
                    skip_macho_reexports=skip_macho_reexports,
                    macho_arch=macho_arch,
                    disable_analysis_options=disable_analysis_options,
                )

        if macho_arch:
            stage_macho_arch.assert_called_once_with(binary, macho_arch)
        else:
            stage_macho_arch.assert_not_called()
        return commands[0], result

    def test_normal_import_does_not_force_macho_loader(self) -> None:
        command, result = self._capture_import_command(False)

        self.assertNotIn("-loader", command)
        self.assertFalse(result["skip_macho_reexports"])

    def test_skip_macho_reexports_adds_verified_loader_option(self) -> None:
        command, result = self._capture_import_command(True)

        option_index = command.index("-loader")
        self.assertEqual(
            command[option_index : option_index + 4],
            ["-loader", "MachoLoader", "-loader-reexport", "false"],
        )
        self.assertTrue(result["skip_macho_reexports"])

    def test_macho_arch_import_uses_staged_slice(self) -> None:
        command, result = self._capture_import_command(False, macho_arch="arm64e")

        import_index = command.index("-import")
        self.assertTrue(command[import_index + 1].endswith("Demo.arm64e"))
        self.assertEqual(result["binary"], command[import_index + 1])
        self.assertEqual(result["program_name"], "Demo.arm64e")
        self.assertEqual(result["macho_arch"]["requested_arch"], "arm64e")
        self.assertTrue(result["macho_arch"]["staged"])

    def test_disable_analysis_options_adds_pre_analysis_script(self) -> None:
        command, result = self._capture_import_command(
            False,
            disable_analysis_options=[
                "Objective-C Selector Trampoline Analysis",
                "Objective-C Selector Trampoline Analysis",
                "Stack",
            ],
        )

        script_index = command.index("-preScript")
        self.assertEqual(
            command[script_index : script_index + 5],
            [
                "-preScript",
                "SetAnalysisOptions.java",
                "Objective-C Selector Trampoline Analysis=false",
                "Stack=false",
                "-log",
            ],
        )
        self.assertEqual(
            result["disabled_analysis_options"],
            ["Objective-C Selector Trampoline Analysis", "Stack"],
        )

    def test_disable_analysis_option_rejects_empty_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "Demo"
            binary.write_bytes(b"demo")
            with self.assertRaisesRegex(RuntimeError, "cannot be empty"):
                import_analyze(binary, "demo", disable_analysis_options=[" "])

    def test_import_analyze_rejects_explicit_ghidra_import_failure_marker(self) -> None:
        def runner(command, **_kwargs):
            log_path = Path(command[command.index("-log") + 1])
            log_path.parent.mkdir(parents=True, exist_ok=True)
            log_path.write_text(
                "ERROR REPORT: Import failed for file: file:///tmp/Demo\n",
                encoding="utf-8",
            )

        @contextmanager
        def unlocked(*_args, **_kwargs):
            yield Path("/tmp/import-lock")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "Demo"
            binary.write_bytes(b"demo")
            with (
                patch.object(cfg, "projects_dir", root / "projects"),
                patch.object(cfg, "logs_dir", root / "logs"),
                patch.object(cfg, "import_demangle", "0"),
                patch("cerberus_re_skill.modules.importer._headless", return_value=Path("/bin/analyzeHeadless")),
                patch("cerberus_re_skill.modules.importer.run", side_effect=runner),
                patch("cerberus_re_skill.modules.importer.project_headless_lock", side_effect=unlocked),
                patch("cerberus_re_skill.modules.bridge.require_tools"),
                patch("cerberus_re_skill.modules.bridge.export_env", return_value={}),
                patch("cerberus_re_skill.modules.bridge.ensure_workspace"),
            ):
                with self.assertRaisesRegex(RuntimeError, "Ghidra import failed"):
                    import_analyze(binary, "demo")

    def test_stage_macho_arch_thins_universal_binary(self) -> None:
        commands: list[list[str]] = []

        def runner(command, **_kwargs):
            commands.append([str(part) for part in command])
            if "-archs" in command:
                return SimpleNamespace(returncode=0, stdout=b"x86_64 arm64e\n", stderr=b"")
            output = Path(command[-1])
            output.write_bytes(b"thin")
            return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "Demo"
            binary.write_bytes(b"fat")
            with (
                patch.object(cfg, "sources_cache_dir", root / "sources"),
                patch("cerberus_re_skill.modules.importer.find_tool", return_value="/usr/bin/lipo"),
                patch("cerberus_re_skill.modules.importer.run", side_effect=runner),
            ):
                staged, info = _stage_macho_arch(binary, "arm64e")
                staged_name = staged.name
                staged_bytes = staged.read_bytes()

        self.assertEqual(staged_name, "Demo.arm64e")
        self.assertEqual(staged_bytes, b"thin")
        self.assertTrue(info["staged"])
        self.assertIn(["/usr/bin/lipo", "-archs", str(binary)], commands)

    def test_stage_macho_arch_rejects_missing_slice(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "Demo"
            binary.write_bytes(b"fat")
            with (
                patch("cerberus_re_skill.modules.importer.find_tool", return_value="/usr/bin/lipo"),
                patch(
                    "cerberus_re_skill.modules.importer.run",
                    return_value=SimpleNamespace(returncode=0, stdout=b"x86_64\n", stderr=b""),
                ),
            ):
                with self.assertRaisesRegex(RuntimeError, "not found"):
                    _stage_macho_arch(binary, "arm64e")

    def test_run_script_rejects_zero_exit_script_error_marker(self) -> None:
        def runner(_command, **_kwargs):
            return SimpleNamespace(
                returncode=0,
                stdout=b"ERROR REPORT SCRIPT ERROR: ExportAppleBundle.java\nGhidraScriptLoadException",
                stderr=b"",
            )

        @contextmanager
        def unlocked(*_args, **_kwargs):
            yield Path("/tmp/run-script-lock")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "projects" / "demo"
            project.mkdir(parents=True)
            (project / "demo.gpr").write_text("", encoding="utf-8")
            with (
                patch.object(cfg, "projects_dir", root / "projects"),
                patch.object(cfg, "logs_dir", root / "logs"),
                patch("cerberus_re_skill.modules.importer._headless", return_value=Path("/bin/analyzeHeadless")),
                patch("cerberus_re_skill.modules.importer.run", side_effect=runner),
                patch("cerberus_re_skill.modules.importer.project_headless_lock", side_effect=unlocked),
                patch("cerberus_re_skill.modules.bridge.require_tools"),
                patch("cerberus_re_skill.modules.bridge.export_env", return_value={}),
            ):
                with self.assertRaisesRegex(RuntimeError, "Ghidra script ExportAppleBundle.java failed"):
                    run_script("ExportAppleBundle.java", "demo", "Demo")

    def test_run_script_reports_active_bridge_project_lock_before_headless(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "projects" / "demo"
            project.mkdir(parents=True)
            (project / "demo.gpr").write_text("", encoding="utf-8")
            session_file = root / "bridge-session.json"
            session_file.write_text(
                '{"session_id":"abc123","pid":4242,"project_name":"demo","program_name":"Demo"}\n',
                encoding="utf-8",
            )
            with (
                patch.object(cfg, "projects_dir", root / "projects"),
                patch(
                    "cerberus_re_skill.modules.bridge_sessions.find_matching_sessions",
                    return_value=[session_file],
                ),
                patch("cerberus_re_skill.modules.importer._headless") as headless,
            ):
                with self.assertRaisesRegex(RuntimeError, "active bridge session holds the Ghidra project lock"):
                    run_script("ExportAppleBundle.java", "demo", "Demo")

            headless.assert_not_called()

    def test_run_script_uses_captured_output_on_success(self) -> None:
        commands: list[list[str]] = []
        capture_flags: list[bool] = []

        def runner(command, **kwargs):
            commands.append([str(part) for part in command])
            capture_flags.append(bool(kwargs.get("capture_output")))
            return SimpleNamespace(returncode=0, stdout=b"script complete", stderr=b"")

        @contextmanager
        def unlocked(*_args, **_kwargs):
            yield Path("/tmp/run-script-lock")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "projects" / "demo"
            project.mkdir(parents=True)
            (project / "demo.gpr").write_text("", encoding="utf-8")
            with (
                patch.object(cfg, "projects_dir", root / "projects"),
                patch.object(cfg, "logs_dir", root / "logs"),
                patch("cerberus_re_skill.modules.importer._headless", return_value=Path("/bin/analyzeHeadless")),
                patch("cerberus_re_skill.modules.importer.run", side_effect=runner),
                patch("cerberus_re_skill.modules.importer.project_headless_lock", side_effect=unlocked),
                patch("cerberus_re_skill.modules.bridge.require_tools"),
                patch("cerberus_re_skill.modules.bridge.export_env", return_value={}),
            ):
                result = run_script("ExportAppleBundle.java", "demo", "Demo")

        self.assertTrue(result["ok"])
        self.assertTrue(capture_flags[0])
        self.assertIn("-postScript", commands[0])


if __name__ == "__main__":
    unittest.main()
