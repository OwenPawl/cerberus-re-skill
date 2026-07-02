import subprocess
import sys
import unittest


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


if __name__ == "__main__":
    unittest.main()
