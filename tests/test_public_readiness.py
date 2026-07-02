import contextlib
import importlib.util
import io
import json
import argparse
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


def load_installer_module():
    script = ROOT / "scripts" / "install_dependencies.py"
    spec = importlib.util.spec_from_file_location("install_dependencies", script)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class PublicReadinessTests(unittest.TestCase):
    def test_dependency_installer_dry_run_json(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                "scripts/install_dependencies.py",
                "--json",
                "--skip-system",
                "--no-node",
                "--venv",
                "/tmp/cerberus-re-test-venv",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=True,
        )
        payload = json.loads(result.stdout)
        self.assertTrue(payload["ok"])
        self.assertFalse(payload["execute"])
        step_ids = {step["id"] for step in payload["steps"]}
        self.assertIn("python_create_venv", step_ids)
        self.assertIn("python_install_project", step_ids)
        self.assertIn("python_install_frida", step_ids)
        activation_command = payload["next_commands"][0]
        if os.name == "nt":
            self.assertTrue(activation_command.endswith("\\Scripts\\Activate.ps1"))
        else:
            self.assertEqual(activation_command, "source /tmp/cerberus-re-test-venv/bin/activate")
        self.assertIn("cerberus-re bootstrap", payload["next_commands"])

    def test_dependency_installer_execute_json_stays_parseable(self) -> None:
        module = load_installer_module()
        steps = [
            module.Step(
                id="noisy_step",
                description="Emit stdout that must not pollute JSON.",
                command=[sys.executable, "-c", "print('noise')"],
                status="pending",
                reason="test",
            )
        ]
        self.assertEqual(module.execute_plan(steps, quiet=True), 0)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            module.print_plan(steps, as_json=True, execute=True, venv=Path("/tmp/cerberus-re-json-smoke-venv"))
        payload = json.loads(output.getvalue())
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["execute"])
        self.assertTrue(output.getvalue().lstrip().startswith("{"))

    def test_dependency_installer_linux_plan_has_reviewable_package_hint(self) -> None:
        module = load_installer_module()
        args = argparse.Namespace(skip_system=False, include_node=True, include_frida=False, venv="/tmp/cerberus-linux")

        with (
            patch.object(module.platform, "system", return_value="Linux"),
            patch.object(module, "_which", side_effect=lambda name: "/usr/bin/apt-get" if name == "apt-get" else None),
            patch.object(module, "_detect_jdk21", return_value=False),
        ):
            steps = module.build_plan(args)

        by_id = {step.id: step for step in steps}
        self.assertEqual(by_id["linux_apt_get_dependencies"].status, "manual")
        self.assertFalse(by_id["linux_apt_get_dependencies"].execute_ok)
        self.assertIn("openjdk-21-jdk", by_id["linux_apt_get_dependencies"].command)
        self.assertIn("lldb", by_id["linux_apt_get_dependencies"].command)
        self.assertEqual(by_id["linux_ghidra_manual"].status, "manual")

    def test_dependency_installer_windows_plan_has_reviewable_package_hint(self) -> None:
        module = load_installer_module()
        args = argparse.Namespace(skip_system=False, include_node=False, include_frida=False, venv="C:/tmp/cerberus")

        with (
            patch.object(module.platform, "system", return_value="Windows"),
            patch.object(module, "_which", side_effect=lambda name: "C:/Windows/System32/winget.exe" if name == "winget" else None),
            patch.object(module, "_detect_jdk21", return_value=False),
        ):
            steps = module.build_plan(args)

        by_id = {step.id: step for step in steps}
        self.assertEqual(by_id["windows_winget_dependencies"].status, "manual")
        self.assertFalse(by_id["windows_winget_dependencies"].execute_ok)
        self.assertIn("Ghidra.Ghidra", by_id["windows_winget_dependencies"].command)
        self.assertIn("Microsoft.OpenJDK.21", by_id["windows_winget_dependencies"].command)
        self.assertNotIn("OpenJS.NodeJS", by_id["windows_winget_dependencies"].command)

    def test_benchmark_scaffold_documents_requested_matrix(self) -> None:
        text = (ROOT / "benchmarks" / "AGENT_BENCHMARK_PLAN.md").read_text(encoding="utf-8")
        for term in [
            "Claude Code",
            "Codex",
            "No skills",
            "long-run-agent only",
            "cerberus-re only",
            "cerberus-re + long-run-agent",
            "Status: scaffolded",
            "python3 scripts/agent_benchmark.py prompt",
            "benchmarks/tasks/",
        ]:
            self.assertIn(term, text)
        self.assertIn("does not run agents, assign scores, or report benchmark results yet", text)

    def test_benchmark_definition_and_scaffold_validate(self) -> None:
        definition = json.loads((ROOT / "benchmarks" / "agent_benchmark.v1.json").read_text(encoding="utf-8"))
        self.assertEqual(definition["schema_version"], "agent_benchmark.v1")
        self.assertEqual(
            {item["id"] for item in definition["runners"]},
            {"claude-code", "codex"},
        )
        self.assertEqual(
            {item["id"] for item in definition["configurations"]},
            {"no-skills", "long-run-agent", "cerberus-re", "cerberus-re-long-run-agent"},
        )
        self.assertEqual(len(definition["tasks"]), 5)
        for task in definition["tasks"]:
            self.assertIn("prompt_path", task)
            self.assertTrue((ROOT / task["prompt_path"]).is_file(), task["prompt_path"])

        with self.subTest("list command emits definition JSON"):
            listed = subprocess.run(
                [sys.executable, "scripts/agent_benchmark.py", "list", "--json"],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=True,
            )
            self.assertEqual(json.loads(listed.stdout)["schema_version"], "agent_benchmark.v1")

        with self.subTest("prompt command renders all task cards"):
            prompted = subprocess.run(
                [
                    sys.executable,
                    "scripts/agent_benchmark.py",
                    "prompt",
                    "--runner",
                    "codex",
                    "--configuration",
                    "cerberus-re-long-run-agent",
                    "--bundle",
                    "benchmarks/results/example/codex/cerberus-re-long-run-agent",
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=True,
            )
            self.assertIn("# Agent Benchmark Prompt", prompted.stdout)
            self.assertIn("Enabled skills: cerberus-re, long-run-agent", prompted.stdout)
            for task in definition["tasks"]:
                task_title = (ROOT / task["prompt_path"]).read_text(encoding="utf-8").splitlines()[0]
                self.assertIn(task_title, prompted.stdout)

        with self.subTest("scaffold creates and validates empty result bundle"):
            import tempfile

            with tempfile.TemporaryDirectory() as tmp:
                bundle = Path(tmp) / "bundle"
                subprocess.run(
                    [
                        sys.executable,
                        "scripts/agent_benchmark.py",
                        "scaffold",
                        "--runner",
                        "codex",
                        "--configuration",
                        "cerberus-re-long-run-agent",
                        "--output",
                        str(bundle),
                    ],
                    cwd=ROOT,
                    text=True,
                    capture_output=True,
                    check=True,
                )
                validated = subprocess.run(
                    [sys.executable, "scripts/agent_benchmark.py", "validate", "--bundle", str(bundle)],
                    cwd=ROOT,
                    text=True,
                    capture_output=True,
                    check=True,
                )
                payload = json.loads(validated.stdout)
                self.assertTrue(payload["ok"])
                self.assertEqual(payload["runner"], "codex")
                self.assertEqual(payload["configuration"], "cerberus-re-long-run-agent")
                metrics = json.loads((bundle / "metrics.json").read_text(encoding="utf-8"))
                self.assertEqual({item["status"] for item in metrics["task_statuses"]}, {"not_run"})

    def test_readme_points_fresh_users_to_dependency_installer(self) -> None:
        text = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("python3 scripts/install_dependencies.py", text)
        self.assertIn("python3 scripts/install_dependencies.py --execute", text)
        self.assertIn("python3 scripts/agent_benchmark.py list", text)
        self.assertIn("benchmarks/", text)

    def test_share_packages_exclude_development_archive(self) -> None:
        source = (ROOT / "cerberus_re_skill" / "modules" / "publisher.py").read_text(encoding="utf-8")
        self.assertIn('"development"', source)
        self.assertIn("_EXCLUDE_NAMES", source)

    def test_public_tree_avoids_target_specific_leftovers(self) -> None:
        denied = [
            "".join(chr(code) for code in codes)
            for codes in (
                (87, 111, 114, 107, 102, 108, 111, 119, 75, 105, 116),
                (86, 111, 105, 99, 101, 83, 104, 111, 114, 116, 99, 117, 116),
                (83, 104, 111, 114, 116, 99, 117, 116),
                (86, 67, 65, 99, 99, 101, 115, 115, 83, 112, 101, 99, 105, 102, 105, 101, 114),
                (97, 99, 116, 105, 111, 110, 45, 99, 97, 116, 97, 108, 111, 103),
                (67, 79, 78, 84, 82, 79, 76, 46, 109, 100),
                (114, 111, 97, 100, 109, 97, 112),
                (98, 117, 103, 32, 104, 117, 110, 116, 105, 110, 103),
                (98, 117, 103, 45, 104, 117, 110, 116, 105, 110, 103),
                (98, 111, 117, 110, 116, 121),
                (101, 120, 112, 108, 111, 105, 116, 97, 98, 105, 108, 105, 116, 121),
                (79, 119, 101, 110),
            )
        ]
        roots = [
            ROOT / "cerberus_re_skill",
            ROOT / "scripts",
            ROOT / "tests",
            ROOT / "references",
            ROOT / "README.md",
            ROOT / "SKILL.md",
            ROOT / "benchmarks",
            ROOT / "agents",
            ROOT / "powershell",
        ]
        files = []
        for root in roots:
            if root.is_file():
                files.append(root)
            else:
                files.extend(path for path in root.rglob("*") if path.is_file())
        for path in files:
            if any(part in {"__pycache__", "development"} for part in path.parts):
                continue
            if path.suffix in {".pyc", ".zip"}:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            for term in denied:
                self.assertNotIn(term, text, str(path))


if __name__ == "__main__":
    unittest.main()
