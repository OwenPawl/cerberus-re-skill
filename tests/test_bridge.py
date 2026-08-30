import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from cerberus_re_skill.core.config import cfg
from cerberus_re_skill.modules.bridge import (
    arm,
    audit_bridge_state,
    bridge_inventory,
    call_bridge,
    close_bridge,
    open_program_in_tool,
    resolve_session_file,
    write_request_file,
)
from cerberus_re_skill.modules import bridge_install
from cerberus_re_skill.core.utils import utc_now


class _FakeResponse:
    def __init__(self, status_code: int, text: str, payload: dict | None = None) -> None:
        self.status_code = status_code
        self.text = text
        self._payload = payload
        self.ok = 200 <= status_code < 300

    def json(self) -> dict:
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


class BridgeCallErrorTests(unittest.TestCase):
    def test_failed_bridge_call_preserves_json_error_detail(self) -> None:
        response = _FakeResponse(
            404,
            '{"ok":false,"error":"no function matches for query: Missing"}',
            {"ok": False, "error": "no function matches for query: Missing"},
        )

        with (
            patch("cerberus_re_skill.modules.bridge_runtime.resolve_session_file", return_value=Path("/tmp/session.json")),
            patch("cerberus_re_skill.modules.bridge_runtime.session_healthy", return_value=True),
            patch("cerberus_re_skill.modules.bridge_runtime._read_session_value") as read_value,
            patch("cerberus_re_skill.modules.bridge_runtime.requests.post", return_value=response),
        ):
            read_value.side_effect = lambda _path, key: {
                "bridge_url": "http://127.0.0.1:12345",
                "token": "secret",
            }[key]

            with self.assertRaisesRegex(
                RuntimeError,
                r"bridge HTTP 404 for /analyze/target: no function matches for query: Missing",
            ):
                call_bridge("/analyze/target", {"query": "Missing"})

    def test_failed_bridge_call_truncates_long_text_bodies(self) -> None:
        response = _FakeResponse(500, "x" * 1200)

        with (
            patch("cerberus_re_skill.modules.bridge_runtime.resolve_session_file", return_value=Path("/tmp/session.json")),
            patch("cerberus_re_skill.modules.bridge_runtime.session_healthy", return_value=True),
            patch("cerberus_re_skill.modules.bridge_runtime._read_session_value") as read_value,
            patch("cerberus_re_skill.modules.bridge_runtime.requests.post", return_value=response),
        ):
            read_value.side_effect = lambda _path, key: {
                "bridge_url": "http://127.0.0.1:12345",
                "token": "secret",
            }[key]

            with self.assertRaises(RuntimeError) as ctx:
                call_bridge("/health", {})

        message = str(ctx.exception)
        self.assertIn("bridge HTTP 500 for /health:", message)
        self.assertIn("...[truncated]", message)
        self.assertLess(len(message), 1100)

    def test_target_program_id_is_used_for_session_routing(self) -> None:
        response = _FakeResponse(200, '{"ok":true}', {"ok": True})
        with (
            patch(
                "cerberus_re_skill.modules.bridge_runtime.resolve_session_file",
                return_value=Path("/tmp/session.json"),
            ) as resolve,
            patch("cerberus_re_skill.modules.bridge_runtime.session_healthy", return_value=True),
            patch("cerberus_re_skill.modules.bridge_runtime._read_session_value") as read_value,
            patch("cerberus_re_skill.modules.bridge_runtime.requests.post", return_value=response),
        ):
            read_value.side_effect = lambda _path, key: {
                "bridge_url": "http://127.0.0.1:12345",
                "token": "secret",
            }[key]
            call_bridge("/function", {"target": {"program_id": "program-stable-id"}})

        resolve.assert_called_once_with("", "", "", "program-stable-id")


class BridgeLifecycleTests(unittest.TestCase):
    def _with_bridge_config(self, tmp: str):
        root = Path(tmp) / "bridge"
        sessions = root / "bridge-sessions"
        requests = root / "bridge-requests"
        return (
            patch.object(cfg, "bridge_config_dir", root),
            patch.object(cfg, "bridge_sessions_dir", sessions),
            patch.object(cfg, "bridge_requests_dir", requests),
            patch.object(cfg, "bridge_current_file", root / "bridge-current.json"),
            patch.object(cfg, "bridge_install_state_file", root / "bridge-install-state.json"),
        )

    def _write_session(
        self,
        sessions_dir: Path,
        session_id: str,
        *,
        pid: int = 1234,
        project: str = "demo",
        program: str = "Demo",
        program_id: str = "",
    ) -> Path:
        sessions_dir.mkdir(parents=True, exist_ok=True)
        session_file = sessions_dir / f"{session_id}.json"
        session_file.write_text(
            json.dumps(
                {
                    "version": 1,
                    "session_id": session_id,
                    "bridge_url": "http://127.0.0.1:12345",
                    "token": "secret",
                    "pid": pid,
                    "project_name": project,
                    "project_path": f"/tmp/{project}.gpr",
                    "program_name": program,
                    "program_path": f"/{program}",
                    "started_at": "2026-04-25T00:00:00Z",
                    "last_heartbeat": "2026-04-25T00:00:01Z",
                    "armed": True,
                    "current_program_id": program_id,
                    "open_programs": (
                        [{"program_id": program_id, "program_name": program}]
                        if program_id
                        else []
                    ),
                }
            )
            + "\n",
            encoding="utf-8",
        )
        return session_file

    def test_request_file_uses_v2_routing_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            patches = self._with_bridge_config(tmp)
            with patches[0], patches[1], patches[2], patches[3], patches[4]:
                request_file = write_request_file(
                    "arm",
                    project_name="demo",
                    program_name="Demo",
                    application_id="app-one",
                    tool_id="tool-one",
                )
                request = json.loads(request_file.read_text(encoding="utf-8"))

        self.assertEqual(request["version"], 2)
        self.assertEqual(request["schema_version"], "cerberus.bridge.request.v2")
        self.assertEqual(request["application_id"], "app-one")
        self.assertEqual(request["tool_id"], "tool-one")

    def test_program_id_selects_owning_session(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            patches = self._with_bridge_config(tmp)
            with patches[0], patches[1], patches[2], patches[3], patches[4]:
                self._write_session(cfg.bridge_sessions_dir, "one", program_id="program-one")
                expected = self._write_session(
                    cfg.bridge_sessions_dir,
                    "two",
                    program="Other",
                    program_id="program-two",
                )
                with patch(
                    "cerberus_re_skill.modules.bridge_sessions.session_healthy",
                    return_value=True,
                ):
                    selected = resolve_session_file(requested_program_id="program-two")
                self.assertEqual(selected, expected)

    def test_inventory_redacts_orphan_session_tokens(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "bridge"
            patches = self._with_bridge_config(tmp)
            with (
                patches[0],
                patches[1],
                patches[2],
                patches[3],
                patches[4],
                patch.object(cfg, "bridge_applications_dir", root / "bridge-applications"),
            ):
                session = self._write_session(
                    cfg.bridge_sessions_dir,
                    "orphan",
                    program_id="program-orphan",
                )
                payload = json.loads(session.read_text(encoding="utf-8"))
                payload["token"] = "must-not-leak"
                session.write_text(json.dumps(payload), encoding="utf-8")
                cfg.bridge_applications_dir.mkdir(parents=True)
                (cfg.bridge_applications_dir / "app.json").write_text(
                    json.dumps(
                        {
                            "application_id": "application-live",
                            "pid": 4321,
                            "last_heartbeat": utc_now(),
                            "tools": [],
                        }
                    ),
                    encoding="utf-8",
                )
                with (
                    patch(
                        "cerberus_re_skill.modules.bridge_sessions.check_pid_alive",
                        return_value=True,
                    ),
                    patch(
                        "cerberus_re_skill.modules.bridge_sessions.session_healthy",
                        return_value=True,
                    ),
                ):
                    inventory = bridge_inventory()

                self.assertEqual(inventory["applications"][0]["status"], "live")
                self.assertEqual(len(inventory["orphan_sessions"]), 1)
                self.assertNotIn("token", inventory["orphan_sessions"][0])

    def test_application_inventory_requires_fresh_heartbeat(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "bridge"
            patches = self._with_bridge_config(tmp)
            with (
                patches[0],
                patches[1],
                patches[2],
                patches[3],
                patches[4],
                patch.object(cfg, "bridge_applications_dir", root / "bridge-applications"),
            ):
                cfg.bridge_applications_dir.mkdir(parents=True)
                (cfg.bridge_applications_dir / "app.json").write_text(
                    json.dumps(
                        {
                            "application_id": "application-unresponsive",
                            "pid": 4321,
                            "last_heartbeat": "2026-01-01T00:00:00Z",
                            "tools": [],
                        }
                    ),
                    encoding="utf-8",
                )
                with patch(
                    "cerberus_re_skill.modules.bridge_sessions.check_pid_alive",
                    return_value=True,
                ):
                    inventory = bridge_inventory()

        self.assertEqual(inventory["applications"][0]["status"], "unresponsive")
        self.assertTrue(inventory["applications"][0]["pid_alive"])

    def test_open_program_routes_request_to_explicit_tool(self) -> None:
        session = {
            "session_id": "session-one",
            "application_id": "application-one",
            "tool_id": "tool-one",
            "open_programs": [
                {
                    "program_id": "program-two",
                    "program_name": "bridge_two",
                    "program_path": "/bridge_two",
                    "current": False,
                }
            ],
        }
        with (
            patch(
                "cerberus_re_skill.modules.bridge_runtime.write_request_file"
            ) as write_request,
            patch(
                "cerberus_re_skill.modules.bridge_runtime.list_sessions",
                return_value=[session],
            ),
        ):
            result = open_program_in_tool(
                "broker_acceptance",
                "bridge_two",
                "tool-one",
                application_id="application-one",
                timeout_seconds=0.1,
            )

        self.assertTrue(result["ok"])
        self.assertFalse(result["program"]["current"])
        write_request.assert_called_once_with(
            "arm",
            project_name="broker_acceptance",
            program_name="bridge_two",
            application_id="application-one",
            tool_id="tool-one",
        )
        write_request.return_value.unlink.assert_called_once_with(missing_ok=True)

    def test_open_program_timeout_removes_its_request(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            request_file = Path(tmp) / "request.json"
            request_file.write_text("{}", encoding="utf-8")
            with (
                patch(
                    "cerberus_re_skill.modules.bridge_runtime.write_request_file",
                    return_value=request_file,
                ),
                patch(
                    "cerberus_re_skill.modules.bridge_runtime.list_sessions",
                    return_value=[],
                ),
            ):
                with self.assertRaisesRegex(RuntimeError, "timed out opening"):
                    open_program_in_tool(
                        "broker_acceptance",
                        "missing",
                        "tool-one",
                        timeout_seconds=0,
                    )

        self.assertFalse(request_file.exists())

    def test_close_requires_explicit_selector(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "requires --session"):
            close_bridge()

    def test_close_refuses_shared_pid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            patches = self._with_bridge_config(tmp)
            with patches[0], patches[1], patches[2], patches[3], patches[4]:
                self._write_session(cfg.bridge_sessions_dir, "one", pid=1234, project="one")
                self._write_session(cfg.bridge_sessions_dir, "two", pid=1234, project="two")
                with (
                    patch("cerberus_re_skill.modules.bridge_runtime.check_pid_alive", return_value=True),
                    patch("cerberus_re_skill.modules.bridge_runtime.session_pid_alive", return_value=True),
                    patch("cerberus_re_skill.modules.bridge_runtime._terminate_pid") as terminate_pid,
                ):
                    result = close_bridge(requested_session="one")

                self.assertFalse(result["ok"])
                self.assertIn("shared", result["message"])
                terminate_pid.assert_not_called()

    def test_close_disarms_terminates_and_clears_selected_session(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            patches = self._with_bridge_config(tmp)
            with patches[0], patches[1], patches[2], patches[3], patches[4]:
                session_file = self._write_session(cfg.bridge_sessions_dir, "one", pid=1234)
                cfg.bridge_current_file.parent.mkdir(parents=True, exist_ok=True)
                cfg.bridge_current_file.write_text(
                    json.dumps({"session_file": str(session_file), "session_id": "one"}) + "\n",
                    encoding="utf-8",
                )
                with (
                    patch("cerberus_re_skill.modules.bridge_runtime.check_pid_alive", return_value=True),
                    patch("cerberus_re_skill.modules.bridge_runtime._is_safe_ghidra_pid", return_value=(True, "java ghidra.GhidraRun")),
                    patch("cerberus_re_skill.modules.bridge_runtime.wait_for_disarm", return_value=True),
                    patch(
                        "cerberus_re_skill.modules.bridge_runtime._terminate_pid",
                        return_value={"terminated": True, "method": "sigterm"},
                    ) as terminate_pid,
                ):
                    result = close_bridge(requested_session="one")

                self.assertTrue(result["ok"])
                self.assertEqual(result["pid"], 1234)
                terminate_pid.assert_called_once()
                self.assertFalse(session_file.exists())
                self.assertFalse(cfg.bridge_current_file.exists())

    def test_audit_reports_stale_session_without_pruning(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            patches = self._with_bridge_config(tmp)
            with patches[0], patches[1], patches[2], patches[3], patches[4]:
                session_file = self._write_session(cfg.bridge_sessions_dir, "stale", pid=9876)
                with (
                    patch("cerberus_re_skill.modules.bridge_runtime.check_pid_alive", return_value=False),
                    patch("cerberus_re_skill.modules.bridge_runtime._ghidra_processes", return_value=[]),
                ):
                    result = audit_bridge_state()

                self.assertFalse(result["ok"])
                self.assertIn(str(session_file), result["stale_session_files"])
                self.assertTrue(session_file.exists())

    def test_bridge_install_clears_stale_state_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            settings = root / "settings"
            ghidra_dir = root / "Ghidra.app"
            app_extensions = ghidra_dir / "Ghidra" / "Extensions"
            app_extensions.mkdir(parents=True)
            zip_path = root / "bridge.zip"
            with zipfile.ZipFile(zip_path, "w") as archive:
                archive.writestr("CodexGhidraBridge/extension.properties", "name=CodexGhidraBridge\n")

            patches = self._with_bridge_config(tmp)
            with (
                patches[0],
                patches[1],
                patches[2],
                patches[3],
                patches[4],
                patch.object(cfg, "ghidra_install_dir", ghidra_dir),
                patch("cerberus_re_skill.modules.bridge_install.require_tools"),
                patch("cerberus_re_skill.modules.bridge_install.build", return_value=zip_path),
                patch("cerberus_re_skill.modules.bridge_install.bridge_settings_dir", return_value=settings),
            ):
                cfg.bridge_config_dir.mkdir(parents=True)
                cfg.bridge_requests_dir.mkdir(parents=True)
                for path in [
                    cfg.bridge_current_file,
                    cfg.bridge_requests_dir / "pending.json",
                ]:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text("{}", encoding="utf-8")

                result = bridge_install.install()

                current_file = cfg.bridge_current_file
                pending_request = cfg.bridge_requests_dir / "pending.json"

            self.assertTrue(result["ok"])
            self.assertFalse(current_file.exists())
            self.assertFalse(pending_request.exists())
            self.assertTrue((settings / "Extensions" / "Ghidra" / "CodexGhidraBridge").exists())

    def test_ensure_bridge_enabled_repairs_installed_extension_configs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            settings = root / "settings"
            installed = settings / "Extensions" / "Ghidra" / "CodexGhidraBridge"
            installed.mkdir(parents=True)
            tools = settings / "tools"
            tools.mkdir(parents=True)
            code_browser = tools / "_code_browser.tcd"
            code_browser.write_text(
                '<TOOL><PACKAGE NAME="Ghidra Core" /></TOOL>', encoding="utf-8"
            )
            frontend = settings / "FrontEndTool.xml"
            frontend.write_text(
                '<TOOL><PACKAGE NAME="Ghidra Core" /></TOOL>', encoding="utf-8"
            )

            with (
                patch.object(cfg, "ghidra_install_dir", root / "Ghidra"),
                patch(
                    "cerberus_re_skill.modules.bridge_install.bridge_settings_dir",
                    return_value=settings,
                ),
            ):
                result = bridge_install.ensure_bridge_installed_and_enabled()

            self.assertEqual(result["action"], "repaired")
            self.assertTrue(result["enabled"])
            self.assertIn("codexghidrabridge.CodexBridgePlugin", code_browser.read_text())
            self.assertIn("codexghidrabridge.CodexBridgeFrontEndPlugin", frontend.read_text())

    def test_arm_timeout_reports_disabled_bridge_plugin(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "demo.gpr"
            project.touch()
            with (
                patch.object(cfg, "bridge_config_dir", Path(tmp) / "bridge"),
                patch.object(cfg, "bridge_sessions_dir", Path(tmp) / "bridge-sessions"),
                patch.object(cfg, "bridge_requests_dir", Path(tmp) / "bridge-requests"),
                patch.object(cfg, "bridge_current_file", Path(tmp) / "bridge-current.json"),
                patch.object(cfg, "bridge_install_state_file", Path(tmp) / "bridge-install.json"),
                patch.object(cfg, "project_file", return_value=project),
                patch("cerberus_re_skill.modules.bridge_install.require_tools"),
                patch("cerberus_re_skill.modules.bridge_install.ensure_workspace"),
                patch("cerberus_re_skill.modules.bridge_install.prune_stale_sessions"),
                patch("cerberus_re_skill.modules.bridge_install.resolve_session_file", side_effect=RuntimeError),
                patch("cerberus_re_skill.modules.bridge_install.write_request_file"),
                patch("cerberus_re_skill.modules.bridge_install.is_ghidra_running", return_value=False),
                patch("cerberus_re_skill.modules.bridge_install._launch_gui_project"),
                patch("cerberus_re_skill.modules.bridge_install.wait_for_session", return_value=None),
                patch(
                    "cerberus_re_skill.modules.bridge_install.ensure_bridge_installed_and_enabled",
                    return_value={
                        "installed": True,
                        "enabled": False,
                        "code_browser_enabled": False,
                        "frontend_enabled": True,
                        "action": "repaired",
                    },
                ),
            ):
                with self.assertRaisesRegex(
                    RuntimeError, "CodexBridgePlugin is not enabled in the Code Browser"
                ):
                    arm("demo", "Demo")


if __name__ == "__main__":
    unittest.main()
