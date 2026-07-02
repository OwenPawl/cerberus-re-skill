import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cerberus_re_skill.modules.validation import (
    ValidationProcessResult,
    _git_diff_check_fallback,
    _git_diff_check_command,
    _validation_ok,
    validate_local,
)


class ValidationReportTests(unittest.TestCase):
    def test_validate_local_writes_reports(self) -> None:
        commands: list[list[str]] = []

        def runner(command, _cwd: Path, _timeout: float) -> ValidationProcessResult:
            commands.append([str(part) for part in command])
            return ValidationProcessResult(0, "OK\n", "")

        with tempfile.TemporaryDirectory() as tmp:
            report = validate_local(output_dir=tmp, runner=runner)
            self.assertTrue(report["ok"])
            self.assertTrue(Path(report["json_report"]).exists())
            self.assertTrue(Path(report["markdown_report"]).exists())
            self.assertGreaterEqual(report["step_count"], 4)
            self.assertTrue(any("doctor" in arg for command in commands for arg in command))
            self.assertIn("PASS", Path(report["markdown_report"]).read_text(encoding="utf-8"))

    def test_validate_local_adds_optional_gate_steps(self) -> None:
        def runner(_command, _cwd: Path, _timeout: float) -> ValidationProcessResult:
            return ValidationProcessResult(0, "OK\n", "")

        with tempfile.TemporaryDirectory() as tmp:
            report = validate_local(
                output_dir=tmp,
                headless_smoke=True,
                live_bridge_smoke=True,
                lldb_smoke=True,
                frida_smoke=True,
                runner=runner,
            )

        labels = [step["label"] for step in report["steps"]]
        self.assertIn("headless Apple bundle export", labels)
        self.assertIn("live bridge close", labels)
        self.assertIn("LLDB static symbol export", labels)
        self.assertIn("Frida trace JavaScript syntax", labels)

    def test_validate_local_extracts_failure_and_warning_seeds(self) -> None:
        def runner(command, _cwd: Path, _timeout: float) -> ValidationProcessResult:
            if "unittest" in [str(part) for part in command]:
                return ValidationProcessResult(1, "WARN failing tests\n", "")
            return ValidationProcessResult(0, "OK\n", "")

        with tempfile.TemporaryDirectory() as tmp:
            report = validate_local(output_dir=tmp, runner=runner)

        self.assertFalse(report["ok"])
        self.assertIn("Fix validation failure: unit tests", report["next_work_items"])
        self.assertIn("Review warning output from validation step: unit tests", report["next_work_items"])

    def test_validate_local_does_not_seed_resolved_amfi_workaround(self) -> None:
        def runner(command, _cwd: Path, _timeout: float) -> ValidationProcessResult:
            if "doctor" in [str(part) for part in command]:
                return ValidationProcessResult(
                    0,
                    "INFO macOS boot-args: amfi_get_out_of_my_way=1\nOK Frida helper policy: AMFI workaround active\n",
                    "",
                )
            return ValidationProcessResult(0, "OK\n", "")

        with tempfile.TemporaryDirectory() as tmp:
            report = validate_local(output_dir=tmp, runner=runner)

        self.assertNotIn("Recheck Frida helper/AMFI runtime attach policy", report["next_work_items"])

    def test_validation_ok_accepts_passing_fallback(self) -> None:
        steps = [
            {"label": "headless Apple bundle export", "ok": False, "returncode": 124},
            {
                "label": "direct headless Apple bundle export fallback",
                "ok": True,
                "returncode": 0,
                "fallback_for": "headless Apple bundle export",
            },
        ]

        self.assertTrue(_validation_ok(steps))

    def test_git_diff_check_command_disables_fsmonitor_and_ext_diff(self) -> None:
        command = _git_diff_check_command(resolve_changed_files=False)

        self.assertEqual(command[:5], ["git", "-c", "core.fsmonitor=false", "diff", "--check"])
        self.assertIn("--no-ext-diff", command)

    def test_git_diff_check_fallback_uses_bounded_pathspecs(self) -> None:
        command = _git_diff_check_fallback(["git", "diff", "--check"])

        self.assertIn("--", command)
        self.assertIn("cerberus_re_skill", command)
        self.assertIn("tests", command)

    def test_git_diff_check_command_accepts_path_override(self) -> None:
        with patch.dict("os.environ", {"GHIDRA_RE_DIFF_CHECK_PATHS": "foo.py 'docs/a b.md'"}):
            command = _git_diff_check_command(resolve_changed_files=True)

        self.assertEqual(command[-3:], ["--", "foo.py", "docs/a b.md"])


if __name__ == "__main__":
    unittest.main()
