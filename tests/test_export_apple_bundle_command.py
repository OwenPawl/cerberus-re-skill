import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from cerberus_re_skill.modules.static_reliability import (
    APPLE_BUNDLE_FILES,
    validate_apple_bundle,
)


ROOT = Path(__file__).resolve().parents[1]


class ExportAppleBundleCommandTests(unittest.TestCase):
    def test_export_apple_bundle_help_exists(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "cerberus_re_skill", "export", "apple-bundle", "--help"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Export the standard Apple-focused JSON bundle", result.stdout)

    def test_export_command_stages_then_publishes_complete_bundle(self) -> None:
        from cerberus_re_skill.commands.export_static import export_apple_bundle_cmd

        observed_output_dirs = []

        def fake_run_script(_script, _project, _program, *, script_args):
            staging = Path(script_args[0].removeprefix("outdir="))
            observed_output_dirs.append(staging)
            for name in APPLE_BUNDLE_FILES:
                (staging / name).write_text('{"ok":true}\n', encoding="utf-8")
            return {"ok": True}

        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "bundle"
            with (
                patch(
                    "cerberus_re_skill.modules.importer.run_script",
                    side_effect=fake_run_script,
                ),
                patch("cerberus_re_skill.commands.export_static._print_json"),
                patch("cerberus_re_skill.commands.export_static.console.print"),
            ):
                export_apple_bundle_cmd("demo", "Demo", str(destination))
            manifest = validate_apple_bundle(destination)
            staging_path = observed_output_dirs[0]

        self.assertEqual(manifest["status"], "complete")
        self.assertNotEqual(staging_path, destination)
        self.assertFalse(staging_path.exists())

    def test_swift_demangle_cached_miss_returns_non_null_sentinel(self) -> None:
        ghidra_install = Path(os.environ.get("GHIDRA_INSTALL_DIR", "/Applications/Ghidra"))
        javac = shutil.which("javac")
        java = shutil.which("java")
        jars = sorted(ghidra_install.glob("Ghidra/**/*.jar"))
        if not javac or not java or not jars:
            self.skipTest("Ghidra Java build dependencies are unavailable")

        harness = """
public final class AppleBundleSwiftNameSupportRegression extends AppleBundleSwiftNameSupport {
    @Override
    protected void run() {
    }

    private String resolveCachedMiss() {
        swiftDemangleToolResolved = true;
        return resolveSwiftDemangleTool();
    }

    public static void main(String[] args) {
        String tool = new AppleBundleSwiftNameSupportRegression().resolveCachedMiss();
        if (tool == null) {
            throw new AssertionError("cached Swift demangler miss returned null");
        }
        if (!tool.isEmpty()) {
            throw new AssertionError("cached Swift demangler miss did not return the empty sentinel");
        }
    }
}
"""
        script_dir = ROOT / "scripts" / "ghidra_scripts"
        classpath = os.pathsep.join(str(path) for path in jars)
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            harness_path = tmp_path / "AppleBundleSwiftNameSupportRegression.java"
            classes = tmp_path / "classes"
            harness_path.write_text(harness, encoding="utf-8")
            classes.mkdir()
            compile_result = subprocess.run(
                [
                    javac,
                    "-cp",
                    classpath,
                    "-d",
                    str(classes),
                    str(script_dir / "AppleBundleCoreSupport.java"),
                    str(script_dir / "AppleBundleObjcSupport.java"),
                    str(script_dir / "AppleBundleSwiftNameSupport.java"),
                    str(harness_path),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            run_result = subprocess.run(
                [
                    java,
                    "-cp",
                    os.pathsep.join((str(classes), classpath)),
                    "AppleBundleSwiftNameSupportRegression",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(run_result.returncode, 0, run_result.stderr)


if __name__ == "__main__":
    unittest.main()
