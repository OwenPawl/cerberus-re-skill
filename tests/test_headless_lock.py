import json
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
                    owner = json.loads((path / "owner.json").read_text(encoding="utf-8"))
                    self.assertEqual(owner["version"], 2)
                    self.assertEqual(owner["pid"], os.getpid())
                    self.assertTrue(owner["lease_id"])
                    self.assertTrue(owner["heartbeat_at"])
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

    def test_old_lock_with_live_matching_owner_is_not_reclaimed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(cfg, "config_home", Path(tmp)):
                path = lock_path("demo", "/tmp/demo")
                path.mkdir(parents=True)
                (path / "owner.json").write_text(
                    json.dumps(
                        {
                            "pid": 4321,
                            "process_start": "same-start",
                            "heartbeat_at": "2000-01-01T00:00:00Z",
                            "operation": "long-analysis",
                        }
                    ),
                    encoding="utf-8",
                )
                with (
                    patch("cerberus_re_skill.modules.headless_lock.check_pid_alive", return_value=True),
                    patch(
                        "cerberus_re_skill.modules.headless_lock._process_start_identity",
                        return_value="same-start",
                    ),
                    self.assertRaisesRegex(RuntimeError, "pid=4321 alive=true operation=long-analysis"),
                ):
                    acquire_project_headless_lock(
                        "demo",
                        "/tmp/demo",
                        timeout_seconds=0,
                        stale_seconds=1,
                    )

    def test_reused_pid_lock_is_reclaimed_after_grace_period(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(cfg, "config_home", Path(tmp)):
                path = lock_path("demo", "/tmp/demo")
                path.mkdir(parents=True)
                (path / "owner.json").write_text(
                    json.dumps(
                        {
                            "pid": 4321,
                            "process_start": "old-start",
                            "heartbeat_at": "2000-01-01T00:00:00Z",
                        }
                    ),
                    encoding="utf-8",
                )
                with (
                    patch("cerberus_re_skill.modules.headless_lock.check_pid_alive", return_value=True),
                    patch(
                        "cerberus_re_skill.modules.headless_lock._process_start_identity",
                        return_value="new-start",
                    ),
                ):
                    acquired = acquire_project_headless_lock(
                        "demo",
                        "/tmp/demo",
                        timeout_seconds=1,
                        stale_seconds=1,
                    )
                self.assertEqual(acquired, path)
                release_project_headless_lock(acquired)

    def test_release_refuses_a_different_owner(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(cfg, "config_home", Path(tmp)):
                acquired = acquire_project_headless_lock("demo", "/tmp/demo")
                self.assertFalse(release_project_headless_lock(acquired, owner_pid=os.getpid() + 1))
                self.assertTrue(acquired.exists())
                self.assertTrue(release_project_headless_lock(acquired))


if __name__ == "__main__":
    unittest.main()
