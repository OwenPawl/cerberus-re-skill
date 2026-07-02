import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cerberus_re_skill.modules.simulator_framework_host import (
    SIMULATOR_FRAMEWORK_HOST_SCHEMA,
    generate_simulator_framework_host,
)


class SimulatorFrameworkHostTests(unittest.TestCase):
    def test_generates_load_only_host_for_repeatable_frameworks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "host.m"
            result = generate_simulator_framework_host(
                frameworks=[
                    "/System/Library/PrivateFrameworks/ExampleKit.framework/ExampleKit",
                    "/System/Library/PrivateFrameworks/ExampleClient.framework/ExampleClient",
                ],
                output=output,
                hold_seconds=45,
            )
            source = output.read_text(encoding="utf-8")

        self.assertTrue(result["ok"])
        self.assertEqual(result["schema"], SIMULATOR_FRAMEWORK_HOST_SCHEMA)
        self.assertEqual(result["safety_default"], "load_only_wait_for_external_probe")
        self.assertEqual(result["runtime_invocation"], "not_performed")
        self.assertIn("dlopen", source)
        self.assertIn("ExampleKit.framework/ExampleKit", source)
        self.assertIn("ExampleClient.framework/ExampleClient", source)
        self.assertIn("sleep(45)", source)
        self.assertNotIn("objc_msgSend", source)

    def test_compiles_and_signs_simulator_host_when_requested(self) -> None:
        commands: list[list[str]] = []

        def runner(command):
            commands.append(list(command))
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "host.m"
            with patch(
                "cerberus_re_skill.modules.simulator_framework_host.shutil.which",
                side_effect=lambda tool: f"/usr/bin/{tool}",
            ):
                result = generate_simulator_framework_host(
                    frameworks=["/System/Library/PrivateFrameworks/ExampleKit.framework/ExampleKit"],
                    output=output,
                    compile_harness=True,
                    deployment_target="26.4",
                    runner=runner,
                )

        self.assertTrue(result["compile"]["ok"])
        self.assertEqual(commands[0][:4], ["/usr/bin/xcrun", "--sdk", "iphonesimulator", "clang"])
        self.assertIn("arm64-apple-ios26.4-simulator", commands[0])
        self.assertEqual(commands[1][:3], ["/usr/bin/codesign", "-s", "-"])

    def test_rejects_relative_or_missing_framework_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "host.m"
            with self.assertRaisesRegex(RuntimeError, "at least one"):
                generate_simulator_framework_host(frameworks=[], output=output)
            with self.assertRaisesRegex(RuntimeError, "absolute"):
                generate_simulator_framework_host(frameworks=["ExampleKit"], output=output)


if __name__ == "__main__":
    unittest.main()
