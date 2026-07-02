import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from cerberus_re_skill.core.config import cfg
from cerberus_re_skill.modules.headless_lock import (
    acquire_project_headless_lock,
    lock_path,
    project_headless_lock,
    release_project_headless_lock,
)


class HeadlessLockTests(unittest.TestCase):
    def test_context_manager_creates_and_releases_lock(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(cfg, "config_home", Path(tmp)):
                with project_headless_lock("demo", "/tmp/demo", operation="test") as path:
                    self.assertTrue(path.is_dir())
                    self.assertTrue((path / "owner.json").exists())
                self.assertFalse(path.exists())

    def test_acquire_times_out_when_lock_is_fresh(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(cfg, "config_home", Path(tmp)):
                path = lock_path("demo", "/tmp/demo")
                path.parent.mkdir(parents=True)
                path.mkdir()
                with self.assertRaisesRegex(RuntimeError, "timed out waiting"):
                    acquire_project_headless_lock(
                        "demo",
                        "/tmp/demo",
                        timeout_seconds=0,
                        stale_seconds=999,
                    )

    def test_stale_lock_is_removed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(cfg, "config_home", Path(tmp)):
                path = lock_path("demo", "/tmp/demo")
                path.parent.mkdir(parents=True)
                path.mkdir()
                old = time.time() - 3600
                os.utime(path, (old, old))

                acquired = acquire_project_headless_lock(
                    "demo",
                    "/tmp/demo",
                    timeout_seconds=1,
                    stale_seconds=1,
                )
                self.assertEqual(acquired, path)
                release_project_headless_lock(acquired)


if __name__ == "__main__":
    unittest.main()
