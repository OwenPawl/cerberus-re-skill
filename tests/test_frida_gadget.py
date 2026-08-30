import json
import signal
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cerberus_re_skill.modules.frida_gadget import (
    EVENT_PREFIX,
    EVENT_SCHEMA,
    run_frida_gadget_probe,
)


def event(event_name: str, **details: object) -> str:
    payload = {"schema": EVENT_SCHEMA, "event": event_name, **details}
    return EVENT_PREFIX + json.dumps(payload, sort_keys=True) + "\n"


class FakeProcess:
    def __init__(
        self,
        output: str,
        *,
        return_code: int = 0,
        time_out: bool = False,
    ) -> None:
        self.pid = 4321
        self.returncode: int | None = None if time_out else return_code
        self._final_return_code = return_code
        self._output = output
        self._time_out = time_out
        self._communicate_count = 0
        self.terminated = False
        self.killed = False

    def communicate(self, timeout: float) -> tuple[str, None]:
        self._communicate_count += 1
        if self._time_out and self._communicate_count == 1:
            raise subprocess.TimeoutExpired(
                cmd="owned-fixture",
                timeout=timeout,
                output=self._output,
            )
        self.returncode = self._final_return_code
        return self._output, None

    def terminate(self) -> None:
        self.terminated = True
        self._final_return_code = -signal.SIGTERM

    def kill(self) -> None:
        self.killed = True
        self._final_return_code = -signal.SIGKILL


class FridaGadgetProbeTests(unittest.TestCase):
    def run_probe(
        self,
        root: Path,
        *,
        allow_runtime: bool,
        process: FakeProcess | None = None,
    ) -> dict[str, object]:
        target = root / "owned-fixture"
        gadget = root / "FridaGadget.dylib"
        script = root / "probe.js"
        target.write_bytes(b"owned executable")
        gadget.write_bytes(b"gadget")
        script.write_text("rpc.exports = {};\n", encoding="utf-8")
        with patch(
            "cerberus_re_skill.modules.frida_gadget.subprocess.Popen",
            side_effect=AssertionError("runtime launch was not expected")
            if process is None
            else None,
            return_value=process,
        ):
            return run_frida_gadget_probe(
                target,
                gadget,
                script,
                root / "evidence",
                stable_target_key="cerberus.test.owned-fixture",
                timeout_seconds=0.25,
                parameters={"symbol": "owned_target"},
                architecture="arm64",
                allow_runtime=allow_runtime,
            )

    def test_artifact_only_probe_never_launches_and_writes_verified_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = self.run_probe(root, allow_runtime=False)
            evidence = root / "evidence"
            plan = json.loads((evidence / "probe-plan.json").read_text(encoding="utf-8"))
            lifecycle = json.loads(
                (evidence / "probe-lifecycle.json").read_text(encoding="utf-8")
            )
            launch_helper = next(
                item for item in plan["helpers"] if item["name"] == "launch.json"
            )
            launch = json.loads(Path(launch_helper["path"]).read_text(encoding="utf-8"))
            raw_output_exists = Path(report["raw_output"]).is_file()

        self.assertTrue(report["ok"])
        self.assertEqual(report["status"], "skipped")
        self.assertFalse(report["runtime_attempted"])
        self.assertEqual(plan["process_policy"]["kill"], "owned-only-on-timeout")
        self.assertEqual([item["name"] for item in plan["helpers"]], [
            "FridaGadget.config",
            "FridaGadget.dylib",
            "launch.json",
            "probe.js",
        ])
        self.assertEqual(launch["arguments"], [])
        self.assertEqual(
            launch["target_executable_id"],
            report["target"]["executable"]["executable_id"],
        )
        self.assertEqual(report["hit_count"], 0)
        self.assertTrue(raw_output_exists)
        self.assertEqual(lifecycle["events"][-1]["outcome"], "skipped")

    def test_initialized_hit_terminates_only_owned_child_after_window(self) -> None:
        output = event("initialized", module="owned-fixture") + event(
            "hit", symbol="owned_target", invocation=1
        ) + event("objc-exception", name="ExpectedException")
        process = FakeProcess(output, time_out=True)
        with tempfile.TemporaryDirectory() as tmp:
            report = self.run_probe(Path(tmp), allow_runtime=True, process=process)

        self.assertTrue(report["ok"])
        self.assertEqual(report["status"], "hit")
        self.assertEqual(report["hit_count"], 1)
        self.assertEqual(report["objc_exception_count"], 1)
        self.assertTrue(report["window_elapsed"])
        self.assertTrue(process.terminated)
        self.assertFalse(process.killed)
        self.assertFalse(report["forced_kill"])
        self.assertEqual(report["lifecycle_summary"]["status"], "hit")

    def test_structured_rejection_is_preserved_as_nonpassing_evidence(self) -> None:
        process = FakeProcess(event("rejected", reason="symbol-not-found"))
        with tempfile.TemporaryDirectory() as tmp:
            report = self.run_probe(Path(tmp), allow_runtime=True, process=process)

        self.assertFalse(report["ok"])
        self.assertEqual(report["status"], "rejected")
        self.assertEqual(report["events"][0]["reason"], "symbol-not-found")
        self.assertEqual(report["lifecycle_summary"]["status"], "failed")

    def test_controlled_signal_crash_is_not_reported_as_success(self) -> None:
        process = FakeProcess(
            event("initialized", module="owned-fixture")
            + event("crash-backtrace", frames=["0x1000 owned_crash"]),
            return_code=-signal.SIGABRT,
        )
        with tempfile.TemporaryDirectory() as tmp:
            report = self.run_probe(Path(tmp), allow_runtime=True, process=process)

        self.assertFalse(report["ok"])
        self.assertEqual(report["status"], "crash")
        self.assertEqual(report["signal"], "SIGABRT")
        self.assertEqual(report["crash_backtrace_count"], 1)
        self.assertTrue(report["lifecycle_summary"]["crash_observed"])

    def test_launch_failure_still_writes_terminal_report_and_lifecycle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "owned-fixture"
            gadget = root / "FridaGadget.dylib"
            script = root / "probe.js"
            target.write_bytes(b"owned executable")
            gadget.write_bytes(b"gadget")
            script.write_text("rpc.exports = {};\n", encoding="utf-8")
            with patch(
                "cerberus_re_skill.modules.frida_gadget.subprocess.Popen",
                side_effect=PermissionError("not executable"),
            ):
                report = run_frida_gadget_probe(
                    target,
                    gadget,
                    script,
                    root / "evidence",
                    stable_target_key="cerberus.test.launch-failure",
                    allow_runtime=True,
                )
            persisted = json.loads(
                (root / "evidence" / "gadget-report.json").read_text(encoding="utf-8")
            )
            lifecycle = json.loads(
                (root / "evidence" / "probe-lifecycle.json").read_text(encoding="utf-8")
            )

        self.assertEqual(report, persisted)
        self.assertFalse(report["ok"])
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["error_type"], "PermissionError")
        self.assertEqual(lifecycle["events"][-1]["phase"], "launch")
        self.assertEqual(lifecycle["events"][-1]["outcome"], "failed")


if __name__ == "__main__":
    unittest.main()
