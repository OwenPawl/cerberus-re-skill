from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from cerberus_re_skill.mcp_jobs import JobStore
from cerberus_re_skill.mcp_runtime import (
    MCPSettings,
    bridge_tier,
    classify,
    make_run_result,
    parse_json_output,
    passthrough_policy,
)

ROOT = Path(__file__).resolve().parents[1]


def test_settings(root: Path, cli_command: tuple[str, ...] | None = None) -> MCPSettings:
    state = root / ".cerberus-mcp"
    jobs = state / "jobs"
    return MCPSettings(
        cli_command=cli_command or (sys.executable, "-m", "cerberus_re_skill"),
        workspace=root,
        state_dir=state,
        jobs_dir=jobs,
        job_archive_dir=jobs / "archive",
        audit_log=state / "audit.jsonl",
        elicit_timeout=1.0,
    )


class MCPRuntimeTests(unittest.TestCase):
    def test_json_recovery_ignores_trailing_rich_prose(self) -> None:
        value = parse_json_output('{"ok":true,"output":"/tmp/evidence"}\nWrote /tmp/evidence')
        self.assertEqual(value["output"], "/tmp/evidence")

    def test_runtime_zero_hit_is_not_success(self) -> None:
        run = make_run_result(
            ["cerberus-re", "frida", "recheck-attach"],
            returncode=0,
            stdout=json.dumps({"ok": True, "hit_count": 0}),
            stderr="",
        )
        self.assertEqual(classify(run, kind="frida"), "no_hit")

    def test_bridge_endpoint_tiers_match_native_safety_contract(self) -> None:
        self.assertEqual(bridge_tier("/decompile"), "read")
        self.assertEqual(bridge_tier("/program/save"), "write")
        self.assertEqual(bridge_tier("/edit/comment"), "write")
        self.assertEqual(bridge_tier("/patch/bytes"), "destructive")
        self.assertEqual(bridge_tier("/function/delete"), "destructive")
        self.assertEqual(bridge_tier("/unknown/new-endpoint"), "write")

    def test_passthrough_cannot_bypass_runtime_or_bridge_gates(self) -> None:
        for argv in [
            ["validate", "lldb-trace", "p", "b"],
            ["frida", "recheck-attach", "--allow-runtime"],
            ["bridge", "call", "/edit/comment", "{}"],
            ["bridge", "close", "--project", "p"],
        ]:
            with self.subTest(argv=argv):
                self.assertEqual(passthrough_policy(argv)[0], "blocked")

        with patch.dict(os.environ, {"CERBERUS_MCP_ALLOW_UNSAFE_RUN": "1"}):
            self.assertEqual(
                passthrough_policy(["frida", "recheck-attach", "--allow-runtime"])[0],
                "blocked",
            )

    def test_detached_job_finishes_and_close_archives_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fake = root / "fake_cli.py"
            fake.write_text(
                "import json\nprint(json.dumps({'ok': True, 'output': '/tmp/job-evidence'}))\n",
                encoding="utf-8",
            )
            store = JobStore(test_settings(root, (sys.executable, str(fake))))
            job_id = store.start([], kind="generic", label="test")

            deadline = time.time() + 10
            record = store.read(job_id)
            while record and record["status"] in {"queued", "running"} and time.time() < deadline:
                time.sleep(0.05)
                record = store.read(job_id)

            self.assertIsNotNone(record)
            self.assertEqual(record["status"], "done")
            self.assertEqual(record["result"]["status"], "success")
            self.assertIn("/tmp/job-evidence", record["result"]["artifacts"])
            archived = store.archive(job_id)
            self.assertEqual(archived["status"], "success")
            self.assertTrue(store.path(job_id, archived=True).is_file())
            self.assertFalse(store.path(job_id).exists())

    @unittest.skipUnless(importlib.util.find_spec("mcp"), "MCP SDK is not installed")
    def test_server_registers_core_and_companion_status_tools(self) -> None:
        from cerberus_re_skill.mcp_server import create_server

        with tempfile.TemporaryDirectory() as tmp:
            server = create_server(test_settings(Path(tmp)))
            names = {tool.name for tool in server._tool_manager.list_tools()}
        for name in [
            "import_analyze",
            "export_apple_bundle",
            "lldb_trace",
            "frida_recheck_attach",
            "bridge_call",
            "cerberus_run",
            "job_status",
            "mission_companion_status",
        ]:
            self.assertIn(name, names)

    @unittest.skipUnless(importlib.util.find_spec("mcp"), "MCP SDK is not installed")
    def test_background_job_survives_stdio_server_exit(self) -> None:
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fake = root / "slow_cli.py"
            fake.write_text(
                "import json, sys, time\n"
                "if sys.argv[1:] != ['--help']:\n"
                "    time.sleep(0.75)\n"
                "print(json.dumps({'ok': True}))\n",
                encoding="utf-8",
            )
            environment = {
                **os.environ,
                "CERBERUS_BIN": f"{sys.executable} {fake}",
                "GHIDRA_WORKSPACE": str(root / "workspace"),
                "PYTHONPATH": str(ROOT),
            }

            async def start_job() -> str:
                parameters = StdioServerParameters(
                    command=sys.executable,
                    args=["-m", "cerberus_re_skill.mcp_server"],
                    env=environment,
                    cwd=ROOT,
                )
                async with stdio_client(parameters) as streams, ClientSession(
                    *streams
                ) as session:
                    await session.initialize()
                    result = await session.call_tool(
                        "import_analyze", {"binary": "/tmp/fake-binary"}
                    )
                    structured = result.structuredContent or {}
                    payload = structured.get("result", structured)
                    return payload["data"]["job_id"]

            job_id = asyncio.run(start_job())
            record_path = root / "workspace" / ".cerberus-mcp" / "jobs" / f"{job_id}.json"
            deadline = time.time() + 10
            record = json.loads(record_path.read_text(encoding="utf-8"))
            while record["status"] in {"queued", "running"} and time.time() < deadline:
                time.sleep(0.05)
                record = json.loads(record_path.read_text(encoding="utf-8"))

            self.assertEqual(record["status"], "done")
            self.assertEqual(record["result"]["status"], "success")

    def test_distribution_exposes_mcp_entrypoint_and_supported_sdk(self) -> None:
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('cerberus-mcp = "cerberus_re_skill.mcp_server:main"', pyproject)
        self.assertIn('"mcp>=1.29,<2"', pyproject)
