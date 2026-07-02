import unittest
from unittest.mock import patch

from cerberus_re_skill.core import ghidra_locator


class GhidraLocatorTests(unittest.TestCase):
    def test_macos_usr_java_shim_is_not_valid_jdk_home(self) -> None:
        with patch.object(ghidra_locator, "is_macos", return_value=True):
            self.assertFalse(ghidra_locator.is_valid_jdk_dir("/usr"))


if __name__ == "__main__":
    unittest.main()
