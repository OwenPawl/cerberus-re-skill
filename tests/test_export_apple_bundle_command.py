import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


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
