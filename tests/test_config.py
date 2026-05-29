from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ghidra_re_skill.core.config import Config


class ConfigTests(unittest.TestCase):
    def test_ghidra_install_dir_defaults_to_detected_install(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            detected = Path(tmp) / "ghidra" / "libexec"
            detected.mkdir(parents=True)

            env = {k: v for k, v in os.environ.items() if k != "GHIDRA_INSTALL_DIR"}
            with (
                patch.dict(os.environ, env, clear=True),
                patch("ghidra_re_skill.core.ghidra_locator.detect_ghidra_dir", return_value=detected),
            ):
                self.assertEqual(Config().ghidra_install_dir, detected)

    def test_ghidra_install_dir_env_overrides_detected_install(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            detected = Path(tmp) / "detected" / "libexec"
            configured = Path(tmp) / "configured"
            detected.mkdir(parents=True)
            configured.mkdir()

            with (
                patch.dict(os.environ, {"GHIDRA_INSTALL_DIR": str(configured)}),
                patch("ghidra_re_skill.core.ghidra_locator.detect_ghidra_dir", return_value=detected),
            ):
                self.assertEqual(Config().ghidra_install_dir, configured)


if __name__ == "__main__":
    unittest.main()
