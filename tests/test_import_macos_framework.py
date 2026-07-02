import tempfile
import unittest
from pathlib import Path

from cerberus_re_skill.modules.importer import _resolve_framework_executable


class ImportMacOSFrameworkTests(unittest.TestCase):
    def test_resolves_direct_framework_executable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            framework = Path(tmp) / "Demo.framework"
            framework.mkdir()
            binary = framework / "Demo"
            binary.write_text("not a real mach-o", encoding="utf-8")

            self.assertEqual(_resolve_framework_executable(framework), binary)

    def test_resolves_versioned_framework_executable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            framework = Path(tmp) / "Demo.framework"
            binary = framework / "Versions" / "A" / "Demo"
            binary.parent.mkdir(parents=True)
            binary.write_text("not a real mach-o", encoding="utf-8")

            self.assertEqual(_resolve_framework_executable(framework), binary)

    def test_returns_none_for_dyld_cache_only_framework_layout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            framework = Path(tmp) / "Demo.framework"
            (framework / "Versions" / "A").mkdir(parents=True)

            self.assertIsNone(_resolve_framework_executable(framework))


if __name__ == "__main__":
    unittest.main()
