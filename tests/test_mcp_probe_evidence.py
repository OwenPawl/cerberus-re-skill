from __future__ import annotations

import asyncio
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

from cerberus_re_skill.mcp_probe_evidence import ProbeEvidenceMCP, TOOL_NAMES
from cerberus_re_skill.mcp_runtime import MCPSettings


ROOT = Path(__file__).resolve().parents[1]


def settings_for(workspace: Path) -> MCPSettings:
    state = workspace / ".cerberus-mcp"
    jobs = state / "jobs"
    return MCPSettings(
        cli_command=("unused",),
        workspace=workspace,
        state_dir=state,
        jobs_dir=jobs,
        job_archive_dir=jobs / "archive",
        audit_log=state / "audit.jsonl",
        elicit_timeout=1.0,
    )


def content_id(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


class ProbeEvidenceMCPTests(unittest.TestCase):
    def make_service(self, workspace: Path) -> ProbeEvidenceMCP:
        return ProbeEvidenceMCP(settings_for(workspace))

    def create_plan(self, service: ProbeEvidenceMCP, workspace: Path) -> dict:
        executable = workspace / "bin" / "Demo"
        executable.parent.mkdir(parents=True, exist_ok=True)
        executable.write_bytes(b"probe target")
        result = service.probe_plan_create(
            stable_target_key="com.example.demo",
            executable_path="bin/Demo",
            transport="frida",
            mode="attach",
            timeout_seconds=15,
            detach_policy="always",
            kill_policy="never",
            outputs={"events": "runs/events.json", "stderr": "runs/stderr.txt"},
            helpers=[{"name": "probe.js", "content": "send('ready');"}],
            expected_signals=["SIGTRAP"],
            platform="macos",
            architecture="arm64e",
        )
        self.assertEqual(result["status"], "success", result["note"])
        return result["data"]["plan"]

    def write_plan(
        self,
        service: ProbeEvidenceMCP,
        workspace: Path,
        plan: dict,
        path: str = "plans/probe-plan.json",
    ) -> Path:
        result = service.probe_plan_write(plan, path)
        self.assertEqual(result["status"], "success", result["note"])
        return workspace / path

    def test_plan_create_write_verify_and_lifecycle_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "workspace"
            service = self.make_service(workspace)
            plan = self.create_plan(service, workspace)
            plan_path = self.write_plan(service, workspace, plan)

            verified = service.probe_plan_verify(plan_path="plans/probe-plan.json")
            first_event = service.probe_lifecycle_record(
                "plans/probe-plan.json",
                "runs/lifecycle.json",
                "attach",
                "timed_out",
                observed_at="2026-08-29T00:00:00Z",
            )
            second_event = service.probe_lifecycle_record(
                "plans/probe-plan.json",
                "runs/lifecycle.json",
                "liveness",
                "observed",
                observed_at="2026-08-29T00:00:01Z",
            )
            summarized = service.probe_lifecycle_summarize(
                "plans/probe-plan.json",
                "runs/lifecycle.json",
            )

            self.assertEqual(verified["status"], "success")
            self.assertEqual(first_event["status"], "success")
            self.assertEqual(second_event["status"], "success")
            self.assertEqual(summarized["status"], "success")
            summary = summarized["data"]["summary"]
            self.assertEqual(summary["status"], "timeout")
            self.assertTrue(summary["timed_out"])
            self.assertFalse(summary["no_hit_explicit"])
            self.assertTrue(plan_path.is_file())
            self.assertTrue((workspace / "runs" / "lifecycle.json").is_file())

    def test_plan_verification_detects_helper_content_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "workspace"
            service = self.make_service(workspace)
            plan = self.create_plan(service, workspace)
            helper_path = Path(plan["helpers"][0]["path"])
            helper_path.chmod(0o644)
            helper_path.write_text("corrupt", encoding="utf-8")

            result = service.probe_plan_verify(plan=plan)

            self.assertEqual(result["status"], "failed")
            self.assertIn("helper", result["note"])

    def test_workspace_confinement_rejects_parent_and_symlink_escape(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            outside = root / "outside"
            outside.mkdir()
            service = self.make_service(workspace)
            executable = workspace / "Demo"
            executable.write_bytes(b"target")

            parent_escape = service.probe_plan_create(
                stable_target_key="demo",
                executable_path="Demo",
                transport="lldb",
                mode="launch",
                timeout_seconds=5,
                detach_policy="always",
                kill_policy="never",
                outputs={"events": "../outside/events.json"},
            )
            (workspace / "linked").symlink_to(outside, target_is_directory=True)
            symlink_escape = service.probe_plan_create(
                stable_target_key="demo",
                executable_path="Demo",
                transport="lldb",
                mode="launch",
                timeout_seconds=5,
                detach_policy="always",
                kill_policy="never",
                outputs={"events": "linked/events.json"},
            )
            immutable_overlap = service.probe_plan_create(
                stable_target_key="demo",
                executable_path="Demo",
                transport="lldb",
                mode="launch",
                timeout_seconds=5,
                detach_policy="always",
                kill_policy="never",
                outputs={"events": ".cerberus-mcp/probe-helpers/events.json"},
            )

            self.assertEqual(parent_escape["status"], "failed")
            self.assertIn("escapes", parent_escape["note"])
            self.assertEqual(symlink_escape["status"], "failed")
            self.assertIn("escapes", symlink_escape["note"])
            self.assertEqual(immutable_overlap["status"], "failed")
            self.assertIn("immutable helper store", immutable_overlap["note"])

    def test_plan_tools_reject_ambiguous_and_malformed_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "workspace"
            service = self.make_service(workspace)
            plan = self.create_plan(service, workspace)

            ambiguous = service.probe_plan_verify(plan=plan, plan_path="plan.json")
            malformed = dict(plan)
            malformed["unexpected"] = True
            rejected = service.probe_plan_verify(plan=malformed)

            self.assertEqual(ambiguous["status"], "failed")
            self.assertIn("exactly one", ambiguous["note"])
            self.assertEqual(rejected["status"], "failed")
            self.assertIn("fields do not match", rejected["note"])

    def test_evidence_append_gate_certify_query_and_export(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "workspace"
            service = self.make_service(workspace)
            (workspace / "proof").mkdir(parents=True)
            for name in ("raw.sha256", "observation.json", "finding.json"):
                (workspace / "proof" / name).write_text("verified\n", encoding="utf-8")
            raw_result = service.evidence_append(
                "graphs/demo",
                "raw_artifact",
                {"path": "Demo", "size": 4},
                content_identity=content_id(b"Demo"),
                verification_path="proof/raw.sha256",
            )
            self.assertEqual(raw_result["status"], "success", raw_result["note"])
            raw_id = raw_result["data"]["node"]["id"]
            observation_result = service.evidence_append(
                "graphs/demo",
                "normalized_observation",
                {"address": "0x1000", "value": "seen"},
                dependencies=[raw_id],
                verification_path="proof/observation.json",
            )
            observation_id = observation_result["data"]["node"]["id"]

            gate = service.evidence_certification_gate("graphs/demo", [observation_id])
            certified = service.evidence_certify(
                "graphs/demo",
                "demo.finding",
                "The behavior was observed",
                [observation_id],
                verification_path="proof/finding.json",
                details={"confidence": "runtime"},
            )
            queried = service.evidence_query(
                "graphs/demo",
                finding_key="demo.finding",
            )
            closure_query = service.evidence_query(
                "graphs/demo",
                node_id=certified["data"]["node"]["id"],
                include_dependency_closure=True,
            )
            exported = service.evidence_export("graphs/demo", "exports/demo-graph.json")

            self.assertEqual(gate["status"], "success", gate["note"])
            self.assertEqual(certified["status"], "success", certified["note"])
            self.assertEqual(queried["status"], "success", queried["note"])
            self.assertEqual(queried["data"]["total"], 1)
            self.assertEqual(closure_query["data"]["dependency_closure_total"], 2)
            self.assertEqual(exported["status"], "success", exported["note"])
            self.assertEqual(exported["data"]["node_count"], 3)
            self.assertTrue((workspace / "exports" / "demo-graph.json").is_file())

    def test_certification_gate_blocks_incomplete_closure_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "workspace"
            service = self.make_service(workspace)
            raw_result = service.evidence_append(
                "graphs/demo",
                "raw_artifact",
                {"path": "Demo"},
                content_identity=content_id(b"Demo"),
            )
            raw_id = raw_result["data"]["node"]["id"]

            gate = service.evidence_certification_gate("graphs/demo", [raw_id])
            forbidden_append = service.evidence_append(
                "graphs/demo",
                "finding",
                {},
                dependencies=[raw_id],
                finding_key="demo.finding",
                statement="unsupported",
                status="certified",
            )
            queried = service.evidence_query("graphs/demo")

            self.assertEqual(gate["status"], "blocked")
            self.assertIn("verification_path", gate["note"])
            self.assertEqual(forbidden_append["status"], "blocked")
            self.assertIn("evidence_certify", forbidden_append["note"])
            self.assertEqual(queried["data"]["total"], 1)

    def test_evidence_query_is_bounded_and_strict(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "workspace"
            service = self.make_service(workspace)
            for index in range(3):
                result = service.evidence_append(
                    "graphs/demo",
                    "raw_artifact",
                    {"index": index},
                    content_identity=content_id(f"raw-{index}".encode()),
                    verification_path=f"proof/raw-{index}.sha256",
                )
                self.assertEqual(result["status"], "success", result["note"])

            bounded = service.evidence_query("graphs/demo", limit=2)
            invalid = service.evidence_query("graphs/demo", limit=201)
            immutable_overlap = service.evidence_export(
                "graphs/demo",
                "graphs/demo/records/export.json",
            )

            self.assertEqual(bounded["data"]["total"], 3)
            self.assertEqual(len(bounded["data"]["nodes"]), 2)
            self.assertTrue(bounded["data"]["truncated"])
            self.assertEqual(invalid["status"], "failed")
            self.assertEqual(immutable_overlap["status"], "failed")
            self.assertIn("immutable evidence records", immutable_overlap["note"])

    def test_all_operations_emit_audited_envelopes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "workspace"
            service = self.make_service(workspace)
            failed = service.probe_plan_verify(plan={"schema": "wrong"})

            self.assertEqual(failed["status"], "failed")
            self.assertEqual(set(failed), {
                "status",
                "note",
                "artifacts",
                "warnings",
                "command",
                "exit_code",
                "stdout",
                "stderr",
                "data",
            })
            records = [
                json.loads(line)
                for line in service.settings.audit_log.read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(records[-1]["tier"], "probe_evidence")
            self.assertEqual(records[-1]["outcome"], "failed")

    def test_tool_name_set_is_stable(self) -> None:
        self.assertEqual(len(TOOL_NAMES), 10)
        self.assertEqual(len(set(TOOL_NAMES)), len(TOOL_NAMES))

    @unittest.skipUnless(importlib.util.find_spec("mcp"), "MCP SDK is not installed")
    def test_stdio_sdk_creates_probe_plan(self) -> None:
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            executable = workspace / "bin" / "Demo"
            executable.parent.mkdir(parents=True)
            executable.write_bytes(b"target")
            fake_cli = root / "fake_cli.py"
            fake_cli.write_text("print('{}')\n", encoding="utf-8")
            environment = {
                **os.environ,
                "CERBERUS_BIN": json.dumps([sys.executable, str(fake_cli)]),
                "GHIDRA_WORKSPACE": str(workspace),
                "PYTHONPATH": str(ROOT),
            }

            async def create_plan() -> dict:
                parameters = StdioServerParameters(
                    command=sys.executable,
                    args=["-m", "cerberus_re_skill.mcp_server"],
                    env=environment,
                    cwd=ROOT,
                )
                async with stdio_client(parameters) as streams, ClientSession(*streams) as session:
                    await session.initialize()
                    result = await session.call_tool(
                        "probe_plan_create",
                        {
                            "stable_target_key": "com.example.demo",
                            "executable_path": "bin/Demo",
                            "transport": "frida",
                            "mode": "attach",
                            "timeout_seconds": 10,
                            "detach_policy": "always",
                            "kill_policy": "never",
                            "outputs": {"events": "runs/events.json"},
                            "helpers": [{"name": "probe.js", "content": "send('ready');"}],
                        },
                    )
                    structured = result.structuredContent or {}
                    return structured.get("result", structured)

            payload = asyncio.run(create_plan())

            self.assertEqual(payload["status"], "success", payload["note"])
            self.assertEqual(payload["data"]["plan"]["schema"], "ghidra-re.probe-plan.v1")
            self.assertTrue(Path(payload["data"]["plan"]["helpers"][0]["path"]).is_file())


if __name__ == "__main__":
    unittest.main()
