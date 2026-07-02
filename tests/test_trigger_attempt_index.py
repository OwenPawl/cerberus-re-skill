import json
import tempfile
import unittest
from pathlib import Path

from cerberus_re_skill.modules.trigger_attempt_index import (
    TRIGGER_ATTEMPT_INDEX_SCHEMA,
    build_trigger_attempt_index,
)


class TriggerAttemptIndexTests(unittest.TestCase):
    def test_build_trigger_attempt_index_ranks_next_trigger(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attempt = root / "target-trigger-attempt.json"
            attempt.write_text(
                json.dumps(
                    {
                        "schema": "ghidra-re.target-trigger-attempt.v1",
                        "classification": "resolved_breakpoints_no_hits_after_non_mutating_trigger",
                        "trigger": {"name": "target_activation_and_public_cli_read_refresh"},
                        "target_process": {"name": "targetd", "pid": 123},
                        "selected_breakpoints": [
                            {"symbol": "-[TargetManagerAccessWrapper getItemCountWithCompletion:]"}
                        ],
                        "lldb_validation": {
                            "hit_count": 0,
                            "runtime_hit_count": 0,
                            "breakpoint_count": 1,
                            "resolved_breakpoint_locations": 1,
                            "breakpoints_hit": 0,
                        },
                        "frida_side_evidence": {
                            "previous_live_attach_blocker": {
                                "errors": [
                                    "NotSupportedError: unexpected error while starting thread (thread_create returned '(os/kern) protection failure')"
                                ]
                            }
                        },
                        "safety_result": ["No protected selector was directly invoked."],
                    }
                ),
                encoding="utf-8",
            )
            session_pack = root / "session-pack-report.json"
            session_pack.write_text(
                json.dumps(
                    {
                        "schema": "ghidra-re.re-session-pack-report.v1",
                        "validation": {
                            "errors": [],
                            "warnings": [],
                            "artifacts": [
                                {
                                    "kind": "xpc-method-inventory",
                                    "summary": {"needs_entitlement_count": 3},
                                }
                            ],
                        },
                    }
                ),
                encoding="utf-8",
            )

            result = build_trigger_attempt_index(
                attempts=[f"baseline={attempt}"],
                session_pack=session_pack,
                output=root / "trigger-attempt-index.json",
                markdown_output=root / "trigger-attempt-index.md",
            )
            payload = json.loads((root / "trigger-attempt-index.json").read_text(encoding="utf-8"))
            markdown = (root / "trigger-attempt-index.md").read_text(encoding="utf-8")

        self.assertTrue(result["ok"])
        self.assertEqual(payload["schema"], TRIGGER_ATTEMPT_INDEX_SCHEMA)
        self.assertEqual(payload["summary"]["attempt_count"], 1)
        self.assertEqual(payload["summary"]["resolved_no_hit_count"], 1)
        self.assertEqual(payload["summary"]["frida_attach_blocker_count"], 1)
        self.assertEqual(payload["summary"]["recommended_trigger"], "app_metadata_refresh_observation")
        self.assertEqual(payload["attempts"][0]["resolved_breakpoint_locations"], 1)
        self.assertEqual(payload["ranked_trigger_sources"][0]["replay_commands"]["status"], "ready")
        self.assertIn(
            "do not create, edit, delete, or run user data",
            payload["ranked_trigger_sources"][0]["replay_commands"]["non_mutating_controls"],
        )
        self.assertLess(
            _score(payload, "direct_xpc_safe_read"),
            _score(payload, "public_cli_read_activation"),
        )
        self.assertIn("app_metadata_refresh_observation", markdown)

    def test_build_trigger_attempt_index_counts_specific_observe_only_no_hit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attempt = root / "metadata-refresh-trigger-attempt.json"
            attempt.write_text(
                json.dumps(
                    {
                        "schema": "ghidra-re.target-trigger-attempt.v1",
                        "classification": "resolved_breakpoints_no_hits_after_observe_only_metadata_refresh",
                        "trigger": {"name": "app_metadata_refresh_observation"},
                        "selected_breakpoints": [
                            {"symbol": "-[TargetManager updateMetadataWithCompletion:]"}
                        ],
                        "lldb_validation": {
                            "hit_count": 0,
                            "runtime_hit_count": 0,
                            "breakpoint_count": 5,
                            "resolved_breakpoint_locations": 5,
                            "breakpoints_hit": 0,
                        },
                    }
                ),
                encoding="utf-8",
            )

            result = build_trigger_attempt_index(
                attempts=[f"metadata_refresh={attempt}"],
                output=root / "trigger-attempt-index.json",
                markdown_output=root / "trigger-attempt-index.md",
            )
            payload = json.loads((root / "trigger-attempt-index.json").read_text(encoding="utf-8"))

        self.assertTrue(result["ok"])
        self.assertEqual(payload["summary"]["resolved_no_hit_count"], 1)
        self.assertEqual(_score(payload, "app_metadata_refresh_observation"), 88)
        self.assertLess(
            _score(payload, "public_cli_read_activation"),
            _score(payload, "ui_open_read_refresh"),
        )

    def test_build_trigger_attempt_index_records_trigger_depth_and_capture_plan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attempt = root / "metadata-refresh-trigger-attempt.json"
            attempt.write_text(
                json.dumps(
                    {
                        "schema": "ghidra-re.target-trigger-attempt.v1",
                        "classification": "resolved_breakpoints_no_hits_after_observe_only_metadata_refresh",
                        "selected_breakpoints": [
                            {"symbol": "-[TargetManager updateMetadataWithCompletion:]"}
                        ],
                        "lldb_validation": {
                            "hit_count": 0,
                            "runtime_hit_count": 0,
                            "breakpoint_count": 5,
                            "resolved_breakpoint_locations": 5,
                            "breakpoints_hit": 0,
                        },
                        "safety_result": ["No protected selector was directly invoked."],
                    }
                ),
                encoding="utf-8",
            )
            live_attach = root / "frida-live-attach.json"
            live_attach.write_text(
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
            capture_plan = root / "frida-capture-plan.json"
            capture_plan.write_text(
                json.dumps(
                    {
                        "schema": "ghidra-re.frida-capture-plan.v1",
                        "summary": {
                            "protected_daemon_count": 1,
                            "controlled_passed_count": 1,
                            "recommended_capture_path": "controlled_helper_runtime_recheck",
                        },
                    }
                ),
                encoding="utf-8",
            )

            result = build_trigger_attempt_index(
                attempts=[f"metadata_refresh={attempt}"],
                instrumentation=[f"metadata_refresh={live_attach}"],
                frida_capture_plans=[f"fallback={capture_plan}"],
                output=root / "trigger-attempt-index.json",
                markdown_output=root / "trigger-attempt-index.md",
            )
            payload = json.loads((root / "trigger-attempt-index.json").read_text(encoding="utf-8"))
            markdown = (root / "trigger-attempt-index.md").read_text(encoding="utf-8")

        self.assertTrue(result["ok"])
        self.assertEqual(payload["summary"]["trigger_source_insufficient_count"], 1)
        self.assertEqual(payload["summary"]["protected_instrumentation_count"], 1)
        self.assertEqual(payload["summary"]["controlled_helper_available_count"], 1)
        self.assertEqual(payload["summary"]["controlled_run_path_available_count"], 0)
        self.assertEqual(payload["attempts"][0]["depth_classification"], "trigger_source_insufficient")
        self.assertTrue(
            any(item["kind"] == "protected_instrumentation" for item in payload["attempts"][0]["blocker_taxonomy"])
        )
        self.assertEqual(_score(payload, "controlled_helper_private_framework_recheck"), 86)
        self.assertIn("depth=`trigger_source_insufficient`", markdown)
        self.assertIn("Recommended capture paths: controlled_helper_runtime_recheck", markdown)

    def test_build_trigger_attempt_index_promotes_controlled_run_path_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attempt = root / "metadata-refresh-trigger-attempt.json"
            attempt.write_text(
                json.dumps(
                    {
                        "schema": "ghidra-re.target-trigger-attempt.v1",
                        "classification": "resolved_breakpoints_no_hits_after_observe_only_metadata_refresh",
                        "selected_breakpoints": [
                            {"symbol": "-[TargetManager updateMetadataWithCompletion:]"}
                        ],
                        "lldb_validation": {
                            "hit_count": 0,
                            "runtime_hit_count": 0,
                            "breakpoint_count": 5,
                            "resolved_breakpoint_locations": 5,
                            "breakpoints_hit": 0,
                        },
                    }
                ),
                encoding="utf-8",
            )
            capture_plan = root / "frida-capture-plan.json"
            capture_plan.write_text(
                json.dumps(
                    {
                        "schema": "ghidra-re.frida-capture-plan.v1",
                        "summary": {
                            "protected_daemon_count": 1,
                            "controlled_passed_count": 1,
                            "controlled_run_path_count": 1,
                            "controlled_domains": ["target_run_path"],
                            "recommended_capture_path": "controlled_helper_runtime_recheck",
                            "recommended_controlled_domain": "target_run_path",
                        },
                    }
                ),
                encoding="utf-8",
            )

            result = build_trigger_attempt_index(
                attempts=[f"metadata_refresh={attempt}"],
                frida_capture_plans=[f"fallback={capture_plan}"],
                output=root / "trigger-attempt-index.json",
                markdown_output=root / "trigger-attempt-index.md",
            )
            payload = json.loads((root / "trigger-attempt-index.json").read_text(encoding="utf-8"))
            markdown = (root / "trigger-attempt-index.md").read_text(encoding="utf-8")

        self.assertTrue(result["ok"])
        self.assertEqual(payload["summary"]["controlled_run_path_available_count"], 1)
        self.assertEqual(payload["summary"]["recommended_trigger"], "controlled_helper_run_path_recheck")
        self.assertEqual(_score(payload, "controlled_helper_run_path_recheck"), 92)
        self.assertIn("target_run_path", payload["frida_capture_plan_summary"]["controlled_domains"])
        self.assertIn("Controlled run-path helpers available: 1", markdown)

    def test_build_trigger_attempt_index_records_partial_breakpoint_setup(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attempt = root / "metadata-refresh-trigger-attempt.json"
            attempt.write_text(
                json.dumps(
                    {
                        "schema": "ghidra-re.target-trigger-attempt.v1",
                        "classification": "resolved_breakpoints_no_hits_after_observe_only_metadata_refresh",
                        "selected_breakpoints": [
                            {"symbol": "-[TargetManager updateMetadataWithCompletion:]"},
                            {"symbol": "-[TargetIndexUpdater start]"},
                        ],
                        "lldb_validation": {
                            "hit_count": 0,
                            "runtime_hit_count": 0,
                            "breakpoint_count": 16,
                            "resolved_breakpoint_locations": 12,
                            "unresolved_breakpoint_count": 4,
                            "breakpoints_hit": 0,
                        },
                    }
                ),
                encoding="utf-8",
            )

            result = build_trigger_attempt_index(
                attempts=[f"metadata_refresh={attempt}"],
                output=root / "trigger-attempt-index.json",
                markdown_output=root / "trigger-attempt-index.md",
            )
            payload = json.loads((root / "trigger-attempt-index.json").read_text(encoding="utf-8"))
            markdown = (root / "trigger-attempt-index.md").read_text(encoding="utf-8")

        self.assertTrue(result["ok"])
        self.assertEqual(payload["summary"]["trigger_source_insufficient_count"], 1)
        self.assertEqual(payload["summary"]["partial_breakpoint_setup_count"], 1)
        self.assertEqual(payload["attempts"][0]["breakpoint_setup_status"], "partial")
        self.assertEqual(payload["attempts"][0]["unresolved_breakpoint_count"], 4)
        self.assertTrue(
            any(item["kind"] == "partial_breakpoint_setup" for item in payload["attempts"][0]["blocker_taxonomy"])
        )
        self.assertIn("Partial breakpoint setup: 1", markdown)
        self.assertIn("breakpoint_setup=`partial`", markdown)


def _score(payload: dict, candidate_id: str) -> int:
    for item in payload["ranked_trigger_sources"]:
        if item["id"] == candidate_id:
            return int(item["score"])
    raise AssertionError(f"missing candidate {candidate_id}")


if __name__ == "__main__":
    unittest.main()
