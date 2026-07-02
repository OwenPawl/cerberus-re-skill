import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cerberus_re_skill.modules.polish import (
    build_command_surface_inventory,
    check_package_surface,
    polish_release,
)


class PolishTests(unittest.TestCase):
    def test_command_surface_inventory_finds_cli_and_scripts(self) -> None:
        inventory = build_command_surface_inventory()
        self.assertIn("validate local", inventory["actual_cli_commands"])
        self.assertIn("polish release", inventory["actual_cli_commands"])
        self.assertIn("ghidra_polish_release", inventory["actual_scripts"])
        self.assertEqual(inventory["missing_cli_references"], [])

    def test_package_surface_required_files_exist(self) -> None:
        package = check_package_surface()
        self.assertEqual(package["missing_required_files"], [])
        self.assertGreater(package["test_file_count"], 0)

    def test_polish_release_writes_reports_with_mocked_validation(self) -> None:
        fake_validation = {
            "ok": True,
            "json_report": "/tmp/validation.json",
            "markdown_report": "/tmp/validation.md",
            "failed_step_count": 0,
            "next_work_items": [],
        }
        with tempfile.TemporaryDirectory() as tmp:
            with patch("cerberus_re_skill.modules.polish.validate_local", return_value=fake_validation):
                report = polish_release(mode="quick", output_dir=tmp, strict_command_surface=True)

            self.assertTrue(report["ok"])
            self.assertTrue(Path(report["json_report"]).exists())
            self.assertTrue(Path(report["markdown_report"]).exists())
            self.assertEqual(report["mode"], "quick")
            self.assertTrue(report["strict_command_surface"])


if __name__ == "__main__":
    unittest.main()
