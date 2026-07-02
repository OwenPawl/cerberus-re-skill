import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from cerberus_re_skill.core.config import cfg
from cerberus_re_skill.modules.bridge import audit_bridge_state, call_bridge, close_bridge
from cerberus_re_skill.modules import bridge_install


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
                }
            )
            + "\n",
            encoding="utf-8",
        )
        return session_file

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

            self.assertTrue(result["ok"])
            self.assertFalse(cfg.bridge_current_file.exists())
            self.assertFalse((cfg.bridge_requests_dir / "pending.json").exists())
            self.assertTrue((settings / "Extensions" / "Ghidra" / "CodexGhidraBridge").exists())


if __name__ == "__main__":
    unittest.main()
