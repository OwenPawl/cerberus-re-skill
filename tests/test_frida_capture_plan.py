import json
import tempfile
import unittest
from pathlib import Path

from cerberus_re_skill.modules.frida_capture_plan import (
    FRIDA_CAPTURE_PLAN_SCHEMA,
    build_frida_capture_plan,
)


class FridaCapturePlanTests(unittest.TestCase):
    def test_build_frida_capture_plan_prefers_controlled_helper_when_daemon_is_protected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            live = root / "frida-live-attach.json"
            live.write_text(
                json.dumps(
                    {
                        "schema": "ghidra-re.frida-live-attach.v1",
                        "ok": False,
                        "status": "error",
                        "target_pid": 14307,
                        "class_name": "ExampleManagerAccessWrapper",
                        "selectors": ["getRecordsWithCompletion:"],
                        "errors": [
                            "Failed to attach: unexpected error while starting thread (thread_create returned '(os/kern) protection failure')"
                        ],
                    }
                ),
                encoding="utf-8",
            )
            recheck = root / "frida-runtime-recheck.json"
            recheck.write_text(
                json.dumps(
                    {
                        "schema": "ghidra-re.frida-runtime-recheck.v1",
                        "ok": True,
                        "status": "passed",
                        "target": "/tmp/exampleclient_completion_shape_probe",
                        "target_args": ["--preaction-delay=3"],
                        "symbol": "-[ExampleClient unsafeSetupXPCConnection]",
                        "runtime_hit_count": 2,
                        "runtime_hits_json": str(root / "runtime_hits.json"),
                        "readiness_observed": True,
                        "frida_event_summary": {"installed_count": 1},
                    }
                ),
                encoding="utf-8",
            )
            diagnostics = root / "frida-diagnostics.json"
            diagnostics.write_text(
                json.dumps(
                    {
                        "schema": "ghidra-re.frida-diagnostics.v1",
                        "ok": True,
                        "status": "diagnosed",
                        "target": "/tmp/exampleclient_completion_shape_probe",
                        "runtime_attach_blocked": False,
                    }
                ),
                encoding="utf-8",
            )
            enriched = root / "runtime_hits_enriched.json"
            enriched.write_text(
                json.dumps(
                    {
                        "schema": "ghidra-re.runtime-hits.v1",
                        "hit_count": 2,
                        "enriched": True,
                        "enrichment": {
                            "project": "current_exampleclient",
                            "program": "ExampleClient",
                            "matched_function_count": 2,
                            "slide_confidence": "medium",
                        },
                    }
                ),
                encoding="utf-8",
            )

            result = build_frida_capture_plan(
                live_attach=[f"daemon={live}"],
                runtime_recheck=[f"controlled={recheck}"],
                diagnostics=[f"host={diagnostics}"],
                enriched_runtime=[f"controlled={enriched}"],
                output=root / "frida-capture-plan.json",
                markdown_output=root / "frida-capture-plan.md",
            )
            payload = json.loads((root / "frida-capture-plan.json").read_text(encoding="utf-8"))
            markdown = (root / "frida-capture-plan.md").read_text(encoding="utf-8")

        self.assertTrue(result["ok"])
        self.assertEqual(payload["schema"], FRIDA_CAPTURE_PLAN_SCHEMA)
        self.assertEqual(payload["summary"]["protected_daemon_count"], 1)
        self.assertEqual(payload["summary"]["controlled_passed_count"], 1)
        self.assertEqual(payload["summary"]["controlled_runtime_hit_count"], 2)
        self.assertEqual(payload["summary"]["controlled_xpc_setup_count"], 1)
        self.assertEqual(payload["summary"]["readiness_observed_count"], 1)
        self.assertEqual(payload["summary"]["delayed_helper_count"], 1)
        self.assertEqual(payload["summary"]["timing_guard_count"], 1)
        self.assertEqual(payload["summary"]["enriched_matched_function_count"], 2)
        self.assertEqual(payload["summary"]["recommended_capture_path"], "controlled_helper_runtime_recheck")
        self.assertEqual(payload["recommendation"]["confidence"], "high")
        self.assertTrue(any(item["kind"] == "frida_attach_protection" for item in payload["friction"]))
        self.assertTrue(payload["runtime_recheck"][0]["timing_guard"])
        self.assertIn("controlled_helper_runtime_recheck", markdown)
        self.assertIn("Timing guards: 1", markdown)

    def test_build_frida_capture_plan_marks_controlled_run_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            live = root / "frida-live-attach.json"
            live.write_text(
                json.dumps(
                    {
                        "schema": "ghidra-re.frida-live-attach.v1",
                        "ok": False,
                        "status": "error",
                        "errors": ["thread_create returned '(os/kern) protection failure'"],
                    }
                ),
                encoding="utf-8",
            )
            recheck = root / "frida-runtime-recheck.json"
            recheck.write_text(
                json.dumps(
                    {
                        "schema": "ghidra-re.frida-runtime-recheck.v1",
                        "ok": True,
                        "status": "passed",
                        "target": "/tmp/run_single_action_delayed",
                        "target_args": ["com.example.actions.comment", "input"],
                        "symbol": "-[ExampleCommentAction runWithInput:error:]",
                        "runtime_hit_count": 2,
                        "runtime_hits_json": str(root / "runtime_hits.json"),
                    }
                ),
                encoding="utf-8",
            )

            build_frida_capture_plan(
                live_attach=[f"daemon={live}"],
                runtime_recheck=[f"action-run={recheck}"],
                output=root / "frida-capture-plan.json",
                markdown_output=root / "frida-capture-plan.md",
            )
            payload = json.loads((root / "frida-capture-plan.json").read_text(encoding="utf-8"))
            markdown = (root / "frida-capture-plan.md").read_text(encoding="utf-8")

        self.assertEqual(payload["summary"]["controlled_run_path_count"], 1)
        self.assertEqual(payload["summary"]["recommended_controlled_domain"], "action_invocation_path")
        self.assertEqual(payload["runtime_recheck"][0]["controlled_domain"], "action_invocation_path")
        self.assertIn("-[ExampleCommentAction runWithInput:error:]", payload["summary"]["controlled_symbols"])
        self.assertIn("Controlled action invocation helpers: 1", markdown)

    def test_build_frida_capture_plan_classifies_bounded_daemon_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            live = root / "frida-live-attach.json"
            live.write_text(
                json.dumps(
                    {
                        "schema": "ghidra-re.frida-live-attach.v1",
                        "ok": False,
                        "status": "attach_timeout_or_blocked",
                        "target_pid": 475,
                        "target_name": "exampled",
                        "symbol": "-[ExampleManagerAccessWrapper getRunIntentForTask:completion:]",
                        "errors": [
                            "frida.TransportError: timeout was reached",
                            "TimeoutError: bounded frida attach timed out after 8 seconds",
                        ],
                    }
                ),
                encoding="utf-8",
            )

            build_frida_capture_plan(
                live_attach=[f"daemon={live}"],
                output=root / "frida-capture-plan.json",
                markdown_output=root / "frida-capture-plan.md",
            )
            payload = json.loads((root / "frida-capture-plan.json").read_text(encoding="utf-8"))
            markdown = (root / "frida-capture-plan.md").read_text(encoding="utf-8")

        self.assertEqual(payload["summary"]["protected_daemon_count"], 1)
        self.assertEqual(payload["live_attach"][0]["classification"], "daemon_attach_timeout_or_blocked")
        self.assertEqual(payload["friction"][0]["kind"], "frida_attach_protection")
        self.assertIn("daemon_attach_timeout_or_blocked", markdown)


if __name__ == "__main__":
    unittest.main()
