import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cerberus_re_skill.core.config import cfg
from cerberus_re_skill.modules.project_access import routed_project_read


class ProjectAccessTests(unittest.TestCase):
    def _project(self, root: Path) -> Path:
        project = root / "projects" / "demo"
        project.mkdir(parents=True)
        (project / "demo.gpr").write_text("project marker", encoding="utf-8")
        repository = project / "demo.rep"
        repository.mkdir()
        (repository / "data.bin").write_bytes(b"immutable saved bytes")
        (project / "demo.lock").write_text("live lock", encoding="utf-8")
        return project

    def _session(self, root: Path, *, changed: bool = False) -> Path:
        session = root / "session.json"
        session.write_text(
            json.dumps(
                {
                    "session_id": "session-live",
                    "application_id": "application-live",
                    "tool_id": "tool-live",
                    "pid": 4242,
                    "last_heartbeat": "2026-08-30T00:00:00Z",
                    "program_name": "Current",
                    "open_programs": [
                        {
                            "program_id": "program-target",
                            "program_name": "Target",
                            "program_path": "/Target",
                            "program_version": 7,
                            "changed": changed,
                        }
                    ],
                }
            )
            + "\n",
            encoding="utf-8",
        )
        return session

    def test_unowned_project_routes_directly_to_headless(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = self._project(root)
            with (
                patch.object(cfg, "projects_dir", root / "projects"),
                patch(
                    "cerberus_re_skill.modules.project_access.list_application_inventory",
                    return_value=[],
                ),
                patch("cerberus_re_skill.modules.project_access.find_matching_sessions", return_value=[]),
            ):
                with routed_project_read("demo", "Target") as route:
                    self.assertEqual(route.mode, "headless")
                    self.assertEqual(route.project_location, project)
                    self.assertIsNone(route.snapshot_manifest)

    def test_live_clean_project_routes_through_content_verified_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = self._project(root)
            session = self._session(root)
            with (
                patch.object(cfg, "projects_dir", root / "projects"),
                patch(
                    "cerberus_re_skill.modules.project_access.list_application_inventory",
                    return_value=[],
                ),
                patch(
                    "cerberus_re_skill.modules.project_access.find_matching_sessions",
                    return_value=[session],
                ),
            ):
                with routed_project_read("demo", "Target") as route:
                    snapshot = route.project_location
                    self.assertEqual(route.mode, "verified_snapshot")
                    self.assertTrue(route.snapshot_manifest["copy_verified"])
                    self.assertEqual(route.snapshot_manifest["entry_count"], 2)
                    self.assertTrue((snapshot / f"{route.project_name}.gpr").is_file())
                    self.assertTrue((snapshot / f"{route.project_name}.rep" / "data.bin").is_file())
                    self.assertFalse(any(snapshot.glob("*.lock")))
                    self.assertEqual(route.owners[0]["matching_programs"][0]["program_id"], "program-target")
                self.assertFalse(snapshot.exists())
                self.assertTrue(source.exists())

    def test_dirty_live_program_refuses_stale_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._project(root)
            session = self._session(root, changed=True)
            with (
                patch.object(cfg, "projects_dir", root / "projects"),
                patch(
                    "cerberus_re_skill.modules.project_access.list_application_inventory",
                    return_value=[],
                ),
                patch(
                    "cerberus_re_skill.modules.project_access.find_matching_sessions",
                    return_value=[session],
                ),
            ):
                with self.assertRaisesRegex(RuntimeError, "dirty target"):
                    with routed_project_read("demo", "Target"):
                        self.fail("dirty project must not yield a route")

    def test_disarmed_live_application_still_routes_through_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._project(root)
            inventory = {
                "status": "live",
                "application_id": "application-live",
                "pid": 4242,
                "last_heartbeat": "2026-08-30T00:00:00Z",
                "project_name": "demo",
                "project_path": str(root / "projects" / "demo" / "demo.gpr"),
                "tools": [
                    {
                        "tool_id": "tool-live",
                        "bridge_session_id": "session-disarmed",
                        "bridge_armed": False,
                        "open_programs": [
                            {
                                "program_id": "program-target",
                                "program_name": "Target",
                                "program_path": "/Target",
                                "program_version": 9,
                                "changed": False,
                            }
                        ],
                    }
                ],
            }
            with (
                patch.object(cfg, "projects_dir", root / "projects"),
                patch(
                    "cerberus_re_skill.modules.project_access.list_application_inventory",
                    return_value=[inventory],
                ),
                patch(
                    "cerberus_re_skill.modules.project_access.find_matching_sessions",
                    return_value=[],
                ) as session_lookup,
            ):
                with routed_project_read("demo", "Target") as route:
                    self.assertEqual(route.mode, "verified_snapshot")
                    self.assertEqual(route.owners[0]["source"], "application_inventory")
                    self.assertFalse(route.owners[0]["bridge_armed"])
                    self.assertTrue(route.snapshot_manifest["copy_verified"])
                session_lookup.assert_not_called()


if __name__ == "__main__":
    unittest.main()
