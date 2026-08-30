import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

from cerberus_re_skill.modules.probe_plan import (
    ProbePlanError,
    ProbePlanIntegrityError,
    build_executable_identity,
    build_probe_plan,
    build_target_identity,
    materialize_helper,
    new_probe_lifecycle,
    record_lifecycle_event,
    summarize_probe_lifecycle,
    verify_probe_plan,
    write_probe_lifecycle,
    write_probe_plan,
)


class ProbePlanTests(unittest.TestCase):
    def test_executable_identity_is_stable_across_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = root / "first" / "Demo"
            second = root / "second" / "Demo"
            first.parent.mkdir()
            second.parent.mkdir()
            first.write_bytes(b"same executable")
            second.write_bytes(b"same executable")

            first_identity = build_executable_identity(first, architecture="arm64e", object_uuid="ABC")
            second_identity = build_executable_identity(second, architecture="arm64e", object_uuid="abc")

        self.assertEqual(first_identity["executable_id"], second_identity["executable_id"])
        self.assertNotEqual(first_identity["path"], second_identity["path"])
        self.assertEqual(first_identity["object_uuid"], "abc")

    def test_target_identity_binds_stable_key_and_executable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            executable_path = Path(tmp) / "Demo"
            executable_path.write_bytes(b"version one")
            executable = build_executable_identity(executable_path)
            first = build_target_identity("com.example.demo", executable, platform="macos")
            repeated = build_target_identity("com.example.demo", executable, platform="macos")
            other = build_target_identity("com.example.other", executable, platform="macos")

        self.assertEqual(first, repeated)
        self.assertNotEqual(first["target_id"], other["target_id"])

    def test_executable_identity_rejects_false_supplied_digest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            executable_path = Path(tmp) / "Demo"
            executable_path.write_bytes(b"real content")

            with self.assertRaisesRegex(ProbePlanIntegrityError, "SHA-256 does not match"):
                build_executable_identity(
                    executable_path,
                    sha256="0" * 64,
                    size=executable_path.stat().st_size,
                )

    def test_plan_id_is_deterministic_after_normalization(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            executable_path = root / "Demo"
            executable_path.write_bytes(b"binary")
            target = build_target_identity("demo-target", build_executable_identity(executable_path))
            first_helper = materialize_helper(root / "helpers", "probe.js", "send('hit');")
            second_helper = materialize_helper(root / "helpers", "setup.py", "print('setup')")
            outputs = {"events": root / "events.json", "stderr": root / "stderr.txt"}
            first = build_probe_plan(
                target,
                transport="frida",
                mode="attach",
                timeout_seconds=30,
                detach_policy="always",
                kill_policy="never",
                expected_signals=["SIGTRAP", "SIGABRT", "SIGTRAP"],
                helpers=[second_helper, first_helper],
                outputs=outputs,
            )
            second = build_probe_plan(
                target,
                transport="FRIDA",
                mode="ATTACH",
                timeout_seconds=30,
                detach_policy="ALWAYS",
                kill_policy="NEVER",
                expected_signals=["SIGABRT", "SIGTRAP"],
                helpers=[first_helper, second_helper],
                outputs={"stderr": outputs["stderr"], "events": outputs["events"]},
            )

        self.assertEqual(first, second)
        self.assertEqual(first["plan_id"], verify_probe_plan(first)["plan_id"])
        self.assertEqual(first["transport"], {"engine": "frida", "mode": "attach"})

    def test_plan_id_binds_timeout_policy_helper_and_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            executable_path = root / "Demo"
            executable_path.write_bytes(b"binary")
            target = build_target_identity("demo-target", build_executable_identity(executable_path))
            helper = materialize_helper(root / "helpers", "trace.lldb", "breakpoint set")
            arguments = {
                "transport": "lldb",
                "mode": "launch",
                "timeout_seconds": 10,
                "detach_policy": "on-success",
                "kill_policy": "owned-only-on-timeout",
                "expected_signals": ["SIGTRAP"],
                "helpers": [helper],
                "outputs": {"trace": root / "trace.json"},
            }
            baseline = build_probe_plan(target, **arguments)
            timeout_changed = build_probe_plan(target, **{**arguments, "timeout_seconds": 11})
            policy_changed = build_probe_plan(target, **{**arguments, "detach_policy": "always"})
            output_changed = build_probe_plan(
                target,
                **{**arguments, "outputs": {"trace": root / "other-trace.json"}},
            )

        self.assertEqual(len({
            baseline["plan_id"],
            timeout_changed["plan_id"],
            policy_changed["plan_id"],
            output_changed["plan_id"],
        }), 4)

    def test_plan_validation_rejects_unsupported_or_ambiguous_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            executable_path = root / "Demo"
            executable_path.write_bytes(b"binary")
            target = build_target_identity("demo-target", build_executable_identity(executable_path))
            base = {
                "transport": "frida",
                "mode": "attach",
                "timeout_seconds": 5,
                "detach_policy": "always",
                "kill_policy": "never",
                "outputs": {"events": root / "events.json"},
            }
            with self.assertRaisesRegex(ProbePlanError, "transport must"):
                build_probe_plan(target, **{**base, "transport": "gdb"})
            with self.assertRaisesRegex(ProbePlanError, "positive integer"):
                build_probe_plan(target, **{**base, "timeout_seconds": 0})
            with self.assertRaisesRegex(ProbePlanError, "must be absolute"):
                build_probe_plan(target, **{**base, "outputs": {"events": "relative.json"}})
            with self.assertRaisesRegex(ProbePlanError, "kill_policy"):
                build_probe_plan(target, **{**base, "kill_policy": "kill-attached-target"})

    def test_materialize_helper_is_idempotent_content_addressed_and_immutable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            first = materialize_helper(Path(tmp), "probe.js", b"send('ready');", executable=False)
            second = materialize_helper(Path(tmp), "probe.js", b"send('ready');", executable=False)
            path = Path(first["path"])

            self.assertEqual(first, second)
            self.assertIn(first["sha256"], path.parts)
            self.assertEqual(path.read_bytes(), b"send('ready');")
            self.assertEqual(first["helper_id"], f"sha256:{first['sha256']}")
            self.assertEqual(path.stat().st_mode & stat.S_IWUSR, 0)
            self.assertFalse(first["executable"])
            self.assertEqual(list(path.parent.glob(".*.tmp")), [])

    def test_materialize_helper_recovers_read_only_temp_unlink(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            original_unlink = Path.unlink
            denied_once = False

            def windows_unlink(path: Path, *args: object, **kwargs: object) -> None:
                nonlocal denied_once
                if path.suffix == ".tmp" and not denied_once:
                    denied_once = True
                    raise PermissionError("simulated Windows read-only hard link")
                original_unlink(path, *args, **kwargs)

            with mock.patch.object(Path, "unlink", windows_unlink):
                helper = materialize_helper(Path(tmp), "probe.js", b"send('ready');")

            path = Path(helper["path"])
            self.assertTrue(denied_once)
            self.assertEqual(path.read_bytes(), b"send('ready');")
            self.assertEqual(path.stat().st_mode & stat.S_IWUSR, 0)
            self.assertEqual(list(path.parent.glob(".*.tmp")), [])

    def test_materialize_helper_detects_corrupt_existing_content(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            helper = materialize_helper(Path(tmp), "probe.js", b"original")
            path = Path(helper["path"])
            path.chmod(0o644)
            path.write_bytes(b"corrupt!")

            with self.assertRaisesRegex(ProbePlanIntegrityError, "conflicts with its SHA-256"):
                materialize_helper(Path(tmp), "probe.js", b"original")

    def test_materialize_helper_rejects_writable_existing_content(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            helper = materialize_helper(Path(tmp), "probe.js", b"original")
            path = Path(helper["path"])
            path.chmod(0o644)

            with self.assertRaisesRegex(ProbePlanIntegrityError, "is writable"):
                materialize_helper(Path(tmp), "probe.js", b"original")

    def test_materialize_helper_rejects_non_regular_existing_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            payload = b"helper"
            probe = materialize_helper(root, "probe.js", payload)
            path = Path(probe["path"])
            path.chmod(0o600)
            path.unlink()
            path.mkdir()

            with self.assertRaisesRegex(ProbePlanIntegrityError, "not a regular file"):
                materialize_helper(root, "probe.js", payload)

    def test_write_probe_plan_is_atomic_and_rejects_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            executable_path = root / "Demo"
            executable_path.write_bytes(b"binary")
            target = build_target_identity("demo-target", build_executable_identity(executable_path))
            plan = build_probe_plan(
                target,
                transport="lldb",
                mode="attach",
                timeout_seconds=5,
                detach_policy="always",
                kill_policy="never",
                outputs={"events": root / "events.json"},
            )
            output = root / "plan.json"
            write_probe_plan(output, plan)
            payload = json.loads(output.read_text(encoding="utf-8"))

            self.assertEqual(payload, plan)
            self.assertEqual(list(root.glob(".plan.json.*.tmp")), [])
            payload["timeout_seconds"] = 6
            with self.assertRaisesRegex(ProbePlanIntegrityError, "ID does not match"):
                verify_probe_plan(payload)

    def test_lifecycle_events_remain_independent(self) -> None:
        lifecycle = new_probe_lifecycle("sha256:" + "a" * 64)
        observations = [
            ("preflight", "succeeded"),
            ("attach", "timed_out"),
            ("liveness", "not_observed"),
            ("crash", "observed"),
            ("relaunch", "succeeded"),
            ("detach", "skipped"),
        ]
        for index, (phase, outcome) in enumerate(observations, start=1):
            record_lifecycle_event(
                lifecycle,
                phase,
                outcome,
                observed_at=f"2026-08-29T00:00:{index:02d}Z",
                details={"source": phase},
            )
        summary = summarize_probe_lifecycle(lifecycle)

        self.assertEqual([event["phase"] for event in lifecycle["events"]], [item[0] for item in observations])
        self.assertEqual(summary["status"], "crash")
        self.assertTrue(summary["timed_out"])
        self.assertTrue(summary["crash_observed"])
        self.assertTrue(summary["relaunched"])
        self.assertFalse(summary["no_hit_explicit"])

    def test_timeout_is_not_no_hit_and_explicit_no_hit_is_distinct(self) -> None:
        timed_out = new_probe_lifecycle("sha256:" + "b" * 64)
        record_lifecycle_event(
            timed_out,
            "attach",
            "timed_out",
            observed_at="2026-08-29T00:00:00Z",
        )
        timeout_summary = summarize_probe_lifecycle(timed_out)

        no_hit = new_probe_lifecycle("sha256:" + "c" * 64)
        record_lifecycle_event(
            no_hit,
            "hit",
            "not_observed",
            observed_at="2026-08-29T00:00:00Z",
        )
        no_hit_summary = summarize_probe_lifecycle(no_hit)

        self.assertEqual(timeout_summary["status"], "timeout")
        self.assertFalse(timeout_summary["no_hit_explicit"])
        self.assertEqual(no_hit_summary["status"], "no_hit")
        self.assertTrue(no_hit_summary["no_hit_explicit"])
        self.assertFalse(no_hit_summary["timed_out"])

    def test_hit_then_crash_preserves_both_observations(self) -> None:
        lifecycle = new_probe_lifecycle("sha256:" + "d" * 64)
        record_lifecycle_event(
            lifecycle,
            "hit",
            "observed",
            observed_at="2026-08-29T00:00:00Z",
        )
        record_lifecycle_event(
            lifecycle,
            "crash",
            "observed",
            observed_at="2026-08-29T00:00:01Z",
        )
        summary = summarize_probe_lifecycle(lifecycle)

        self.assertEqual(summary["status"], "hit_then_crash")
        self.assertTrue(summary["hit_observed"])
        self.assertTrue(summary["crash_observed"])

    def test_lifecycle_detects_event_content_tampering(self) -> None:
        lifecycle = new_probe_lifecycle("sha256:" + "e" * 64)
        event = record_lifecycle_event(
            lifecycle,
            "launch",
            "succeeded",
            observed_at="2026-08-29T00:00:00Z",
        )
        event["outcome"] = "failed"

        with self.assertRaisesRegex(ProbePlanIntegrityError, "event ID does not match"):
            summarize_probe_lifecycle(lifecycle)

    def test_write_probe_lifecycle_is_atomic(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            lifecycle = new_probe_lifecycle("sha256:" + "f" * 64)
            record_lifecycle_event(
                lifecycle,
                "preflight",
                "succeeded",
                observed_at="2026-08-29T00:00:00Z",
            )
            output = write_probe_lifecycle(root / "lifecycle.json", lifecycle)

            self.assertEqual(json.loads(output.read_text(encoding="utf-8")), lifecycle)
            self.assertEqual(list(root.glob(".lifecycle.json.*.tmp")), [])


if __name__ == "__main__":
    unittest.main()
