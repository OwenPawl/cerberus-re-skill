import subprocess
import sys
import tomllib
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def plain_text(text: str) -> str:
    return ANSI_RE.sub("", text)


class CommandSurfaceDriftTests(unittest.TestCase):
    def test_no_active_docs_reference_removed_bridge_shell_wrappers(self) -> None:
        allowed = {
            ROOT / "SKILL.md",
            ROOT / "references" / "raw-bridge-recipes.md",
        }
        for path in [
            ROOT / "README.md",
            ROOT / "references" / "local-validation-matrix.md",
            ROOT / "references" / "output-files.md",
        ]:
            self.assertNotIn("scripts/ghidra_bridge_", path.read_text(encoding="utf-8"), str(path))

        for path in allowed:
            text = path.read_text(encoding="utf-8")
            if "scripts/ghidra_bridge_" in text:
                self.assertIn("old `scripts/ghidra_bridge_", text)

    def test_raw_bridge_recipe_uses_python_cli_transport(self) -> None:
        text = (ROOT / "references" / "raw-bridge-recipes.md").read_text(encoding="utf-8")
        self.assertIn("python3 -m cerberus_re_skill bridge call", text)
        self.assertIn("@/tmp/bridge-comment.json", text)
        self.assertIn("bridge call /functions/search -", text)

    def test_mission_group_is_removed_from_public_cli(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "cerberus_re_skill", "mission", "--help"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("No such command", result.stdout + result.stderr)

    def test_root_help_hides_legacy_mission_group(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "cerberus_re_skill", "--help"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=True,
        )
        self.assertNotIn("mission", result.stdout)

    def test_root_help_advertises_cerberus_re(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "cerberus_re_skill", "--help"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=True,
        )
        self.assertIn("Cerberus RE", result.stdout)
        self.assertIn("Ghidra", result.stdout)
        self.assertIn("LLDB", result.stdout)
        self.assertIn("Frida", result.stdout)

    def test_distribution_metadata_uses_cerberus_and_apache(self) -> None:
        metadata = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        project = metadata["project"]
        self.assertEqual(project["name"], "cerberus-re")
        self.assertEqual(project["license"]["text"], "Apache-2.0")
        self.assertEqual(project["scripts"]["cerberus-re"], "cerberus_re_skill.cli:app")
        self.assertNotIn("ghidra-re", project["scripts"])
        license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")
        self.assertIn("Apache License", license_text)
        self.assertNotIn("MIT License", license_text)

    def test_public_help_hides_removed_target_specific_commands(self) -> None:
        removed_action_catalog = "".join(chr(code) for code in (97, 99, 116, 105, 111, 110, 45, 99, 97, 116, 97, 108, 111, 103))
        removed_context_fixture = "".join(chr(code) for code in (97, 99, 116, 105, 111, 110, 45, 99, 111, 110, 116, 101, 120, 116, 45, 102, 105, 120, 116, 117, 114, 101))
        removed_short_input = "".join(chr(code) for code in (115, 104, 111, 114, 116, 99, 117, 116, 45, 105, 110, 112, 117, 116))
        for args, hidden_terms in [
            (
                ["export", "--help"],
                [
                    removed_action_catalog,
                    removed_context_fixture,
                    f"{removed_action_catalog}-compare",
                    "xpc-safe-read-readiness",
                ],
            ),
            (["frida", "--help"], [removed_short_input]),
        ]:
            result = subprocess.run(
                [sys.executable, "-m", "cerberus_re_skill", *args],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=True,
            )
            for term in hidden_terms:
                self.assertNotIn(term, result.stdout)

    def test_internal_target_specific_commands_are_removed_from_public_cli(self) -> None:
        removed_action_catalog = "".join(chr(code) for code in (97, 99, 116, 105, 111, 110, 45, 99, 97, 116, 97, 108, 111, 103))
        removed_context_fixture = "".join(chr(code) for code in (97, 99, 116, 105, 111, 110, 45, 99, 111, 110, 116, 101, 120, 116, 45, 102, 105, 120, 116, 117, 114, 101))
        removed_short_input = "".join(chr(code) for code in (115, 104, 111, 114, 116, 99, 117, 116, 45, 105, 110, 112, 117, 116))
        removed_commands = [
            ["export", removed_action_catalog, "--help"],
            ["export", removed_context_fixture, "--help"],
            ["export", f"{removed_action_catalog}-compare", "--help"],
            ["frida", removed_short_input, "--help"],
            ["mission", "--help"],
        ]
        for args in removed_commands:
            with self.subTest(args=args):
                result = subprocess.run(
                    [sys.executable, "-m", "cerberus_re_skill", *args],
                    cwd=ROOT,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("No such command", result.stdout + result.stderr)

    def test_internal_target_specific_modules_are_outside_public_package(self) -> None:
        removed_modules = [
            ROOT / "cerberus_re_skill" / "modules" / "action_catalog.py",
            ROOT / "cerberus_re_skill" / "modules" / "action_catalog_compare.py",
            ROOT / "cerberus_re_skill" / "modules" / "action_context_fixture.py",
            ROOT / "cerberus_re_skill" / "modules" / "frida_shortcut_input.py",
            ROOT / "cerberus_re_skill" / "modules" / ("".join(chr(code) for code in (114, 111, 97, 100, 109, 97, 112)) + "_seed_report.py"),
        ]
        for path in removed_modules:
            self.assertFalse(path.exists(), str(path))

    def test_xpc_surface_help_advertises_bundle_dir(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "cerberus_re_skill", "export", "xpc-surface", "--help"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=True,
        )
        self.assertIn("--bundle-dir", plain_text(result.stdout))

    def test_public_metadata_avoids_internal_positioning_terms(self) -> None:
        paths = [
            ROOT / ".gemini" / "antigravity" / "skills" / "cerberus-re-skill" / "manifest.json",
            ROOT / "agents" / "openai.yaml",
            ROOT / "powershell" / "GhidraRe.psd1",
        ]
        denied_terms = [
            "".join(chr(code) for code in codes)
            for codes in (
                (98, 117, 103, 45, 104, 117, 110, 116, 105, 110, 103),
                (98, 117, 103, 32, 104, 117, 110, 116, 105, 110, 103),
                (98, 111, 117, 110, 116, 121),
                (101, 120, 112, 108, 111, 105, 116),
                (118, 117, 108, 110, 101, 114, 97, 98, 105, 108, 105, 116, 121),
                (111, 119, 101, 110, 112, 97, 119, 108),
                (115, 104, 111, 114, 116, 99, 117, 116, 115, 45, 100, 101, 118),
            )
        ]
        for path in paths:
            text = path.read_text(encoding="utf-8")
            lowered = text.lower()
            for term in denied_terms:
                self.assertNotIn(term, lowered, str(path))

    def test_public_docs_avoid_target_specific_research_terms(self) -> None:
        paths = [
            ROOT / "README.md",
            ROOT / "SKILL.md",
            *sorted((ROOT / "references").glob("*.md")),
            ROOT / ".gemini" / "antigravity" / "skills" / "cerberus-re-skill" / "manifest.json",
            ROOT / "agents" / "openai.yaml",
            ROOT / "powershell" / "GhidraRe.psd1",
        ]
        denied_terms = [
            "".join(chr(code) for code in codes)
            for codes in (
                (87, 111, 114, 107, 102, 108, 111, 119, 75, 105, 116),
                (86, 111, 105, 99, 101, 83, 104, 111, 114, 116, 99, 117, 116, 115),
                (83, 104, 111, 114, 116, 99, 117, 116, 115, 32, 97, 114, 99, 104, 97, 101, 111, 108, 111, 103, 121),
                (83, 104, 111, 114, 116, 99, 117, 116, 115, 45, 100, 101, 114, 105, 118, 101, 100),
            )
        ]
        for path in paths:
            text = path.read_text(encoding="utf-8")
            for term in denied_terms:
                self.assertNotIn(term, text, str(path))

    def test_public_manifests_do_not_advertise_legacy_mission_commands(self) -> None:
        paths = [
            ROOT / ".gemini" / "antigravity" / "skills" / "cerberus-re-skill" / "manifest.json",
            ROOT / "agents" / "openai.yaml",
            ROOT / "powershell" / "GhidraRe.psd1",
        ]
        for path in paths:
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("mission start", text)
            self.assertNotIn("mission_start", text)
            self.assertNotIn("Start-GhidraReMission", text)
            self.assertNotIn("Get-GhidraReMissionStatus", text)
            self.assertNotIn("Trace-GhidraReMission", text)
            self.assertNotIn("Get-GhidraReMissionReport", text)
            self.assertNotIn("Complete-GhidraReMission", text)
            self.assertNotIn("Start-GhidraReAutopilot", text)

    def test_external_wrappers_do_not_keep_legacy_mission_dispatch(self) -> None:
        paths = [
            ROOT / ".gemini" / "antigravity" / "skills" / "cerberus-re-skill" / "skill.py",
            ROOT / "powershell" / "GhidraRe.psm1",
        ]
        denied = [
            "".join(chr(code) for code in codes)
            for codes in (
                (103, 104, 105, 100, 114, 97, 95, 109, 105, 115, 115, 105, 111, 110, 95, 115, 116, 97, 114, 116),
                (103, 104, 105, 100, 114, 97, 95, 109, 105, 115, 115, 105, 111, 110, 95, 115, 116, 97, 116, 117, 115),
                (103, 104, 105, 100, 114, 97, 95, 109, 105, 115, 115, 105, 111, 110, 95, 102, 105, 110, 105, 115, 104),
                (103, 104, 105, 100, 114, 97, 95, 109, 105, 115, 115, 105, 111, 110, 95, 114, 101, 112, 111, 114, 116),
                (103, 104, 105, 100, 114, 97, 95, 109, 105, 115, 115, 105, 111, 110, 95, 116, 114, 97, 99, 101),
                (103, 104, 105, 100, 114, 97, 95, 109, 105, 115, 115, 105, 111, 110, 95, 97, 117, 116, 111, 112, 105, 108, 111, 116),
                (83, 116, 97, 114, 116, 45, 71, 104, 105, 100, 114, 97, 82, 101, 77, 105, 115, 115, 105, 111, 110),
                (71, 101, 116, 45, 71, 104, 105, 100, 114, 97, 82, 101, 77, 105, 115, 115, 105, 111, 110, 83, 116, 97, 116, 117, 115),
                (84, 114, 97, 99, 101, 45, 71, 104, 105, 100, 114, 97, 82, 101, 77, 105, 115, 115, 105, 111, 110),
                (71, 101, 116, 45, 71, 104, 105, 100, 114, 97, 82, 101, 77, 105, 115, 115, 105, 111, 110, 82, 101, 112, 111, 114, 116),
                (67, 111, 109, 112, 108, 101, 116, 101, 45, 71, 104, 105, 100, 114, 97, 82, 101, 77, 105, 115, 115, 105, 111, 110),
                (83, 116, 97, 114, 116, 45, 71, 104, 105, 100, 114, 97, 82, 101, 65, 117, 116, 111, 112, 105, 108, 111, 116),
            )
        ]
        for path in paths:
            text = path.read_text(encoding="utf-8")
            for term in denied:
                self.assertNotIn(term, text, str(path))

    def test_powershell_module_exports_do_not_include_legacy_mission_wrappers(self) -> None:
        text = (ROOT / "powershell" / "GhidraRe.psm1").read_text(encoding="utf-8")
        export_block = text.split("Export-ModuleMember -Function @(", 1)[1]
        for name in [
            "Start-GhidraReMission",
            "Get-GhidraReMissionStatus",
            "Trace-GhidraReMission",
            "Get-GhidraReMissionReport",
            "Complete-GhidraReMission",
            "Start-GhidraReAutopilot",
        ]:
            self.assertNotIn(name, export_block)


if __name__ == "__main__":
    unittest.main()
