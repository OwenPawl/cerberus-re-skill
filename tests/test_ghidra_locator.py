from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ghidra_re_skill.core import ghidra_locator


def make_fake_ghidra(root: Path) -> None:
    (root / "support").mkdir(parents=True)
    (root / "support" / "analyzeHeadless").write_text("#!/bin/sh\n", encoding="utf-8")
    (root / "ghidraRun").write_text("#!/bin/sh\n", encoding="utf-8")


class GhidraLocatorTests(unittest.TestCase):
    def test_resolve_ghidra_dir_accepts_direct_install_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "ghidra_12.1_PUBLIC"
            make_fake_ghidra(root)

            self.assertEqual(ghidra_locator.resolve_ghidra_dir(root), root)

    def test_resolve_ghidra_dir_finds_libexec_child(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            package_root = Path(tmp) / "ghidra"
            install_root = package_root / "libexec"
            make_fake_ghidra(install_root)

            self.assertEqual(ghidra_locator.resolve_ghidra_dir(package_root), install_root)

    def test_resolve_ghidra_dir_finds_versioned_child_libexec(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cask_root = Path(tmp) / "Caskroom" / "ghidra"
            install_root = cask_root / "12.1" / "libexec"
            make_fake_ghidra(install_root)

            self.assertEqual(ghidra_locator.resolve_ghidra_dir(cask_root), install_root)

    def test_detect_ghidra_dir_follows_path_ghidra_run_to_libexec(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            package_root = Path(tmp) / "ghidra" / "12.1"
            bin_dir = package_root / "bin"
            install_root = package_root / "libexec"
            bin_dir.mkdir(parents=True)
            (bin_dir / "ghidraRun").write_text("#!/bin/sh\n", encoding="utf-8")
            make_fake_ghidra(install_root)

            def fake_find_tool(name: str) -> str | None:
                if name == "ghidraRun":
                    return str(bin_dir / "ghidraRun")
                return None

            with (
                patch.object(ghidra_locator, "find_tool", side_effect=fake_find_tool),
                patch.object(ghidra_locator, "get_platform", return_value="linux"),
            ):
                self.assertEqual(ghidra_locator.detect_ghidra_dir(), install_root.resolve())

    def test_detect_ghidra_dir_prefers_homebrew_opt_over_cellar(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            prefix = Path(tmp) / "homebrew"
            cellar_root = prefix / "Cellar" / "ghidra" / "12.1"
            bin_dir = cellar_root / "bin"
            opt_root = prefix / "opt" / "ghidra" / "libexec"
            bin_dir.mkdir(parents=True)
            (bin_dir / "ghidraRun").write_text("#!/bin/sh\n", encoding="utf-8")
            make_fake_ghidra(cellar_root / "libexec")
            make_fake_ghidra(opt_root)

            def fake_find_tool(name: str) -> str | None:
                if name == "ghidraRun":
                    return str(bin_dir / "ghidraRun")
                return None

            with (
                patch.object(ghidra_locator, "find_tool", side_effect=fake_find_tool),
                patch.object(ghidra_locator, "get_platform", return_value="linux"),
            ):
                self.assertEqual(ghidra_locator.detect_ghidra_dir(), opt_root.resolve())


if __name__ == "__main__":
    unittest.main()
