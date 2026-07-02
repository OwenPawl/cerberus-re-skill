import json
import tempfile
import unittest
from pathlib import Path

from cerberus_re_skill.modules.xpc_allowed_class_focus import (
    XPC_ALLOWED_CLASS_FOCUS_SCHEMA,
    build_xpc_allowed_class_focus,
)


class XpcAllowedClassFocusTests(unittest.TestCase):
    def test_merges_probe_readiness_and_lldb_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            probe = root / "probe.json"
            probe.write_text(
                json.dumps(
                    {
                        "schema": "ghidra-re.phase12.allowed-class-focus-probe.v1",
                        "ok": True,
                        "remote_methods_invoked": False,
                        "connection_created": True,
                        "interface_source": "example_client_connection",
                        "selector_descriptions": [
                            {
                                "selector": "getNumberOfRecordsWithCompletion:",
                                "protocol_contains_selector": True,
                                "types": "v24@0:8@?16",
                            },
                            {
                                "selector": "getCachedRecords:",
                                "protocol_contains_selector": False,
                            },
                        ],
                        "allowed_class_entries": [
                            _entry("getNumberOfRecordsWithCompletion:", 0, False, []),
                            _entry("getNumberOfRecordsWithCompletion:", 0, True, []),
                            _entry("getNumberOfRecordsWithCompletion:", 1, True, ["NSError"]),
                            _entry("getCachedRecords:", 0, False, [], ok=False),
                        ],
                    }
                ),
                encoding="utf-8",
            )
            inventory = root / "inventory.json"
            inventory.write_text(
                json.dumps(
                    {
                        "interfaces": [
                            {
                                "method_candidates": [
                                    {
                                        "selector": "getNumberOfRecordsWithCompletion:",
                                        "input_shape_hints": [
                                            {"position": 1, "role": "completion_block", "label": "completion"}
                                        ],
                                        "configuration_backing": {
                                            "has_allowed_class_evidence": True,
                                            "allowed_class_evidence_count": 3,
                                        },
                                        "safety_classification": {
                                            "category": "safe_read",
                                            "probe_readiness": "blocked_pending_entitlement_and_input_shape",
                                        },
                                    }
                                ]
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            readiness = root / "readiness.json"
            readiness.write_text(
                json.dumps(
                    {
                        "ranked_methods": [
                            {
                                "selector": "getNumberOfRecordsWithCompletion:",
                                "readiness_bucket": "next_bounded_probe_candidate_policy_gated",
                                "remote_invocation_default": "blocked_no_remote_call",
                                "completion_contract": {
                                    "completion": "reply[0] NSUInteger; reply[1] NSError *",
                                    "reply_arguments": [
                                        {"index": 0, "role": "count", "kind": "primitive"},
                                        {"index": 1, "role": "error", "classes": ["NSError"]},
                                    ],
                                },
                            },
                            {
                                "selector": "getCachedRecords:",
                                "readiness_bucket": "local_cache_observation_only",
                                "remote_invocation_default": "blocked_no_remote_call",
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )
            static_config = root / "config.json"
            static_config.write_text(
                json.dumps(
                    {
                        "summary": {
                            "function_count": 2,
                            "pattern_function_count": 1,
                            "allowed_class_call_count": 7,
                            "interface_with_protocol_call_count": 1,
                        }
                    }
                ),
                encoding="utf-8",
            )
            lldb = root / "lldb.json"
            lldb.write_text(
                json.dumps(
                    {
                        "trace_status": "ok",
                        "hit_count": 20,
                        "json_report": str(lldb),
                        "trace": {
                            "breakpoint_count": 3,
                            "resolved_breakpoint_locations": 3,
                            "breakpoints_hit": 3,
                            "symbols_requested": ["-[NSXPCInterface classesForSelector:argumentIndex:ofReply:]"],
                        },
                    }
                ),
                encoding="utf-8",
            )
            output = root / "focus.json"
            markdown = root / "focus.md"

            result = build_xpc_allowed_class_focus(
                allowed_class_probe_path=probe,
                selectors=["getNumberOfRecordsWithCompletion:", "getCachedRecords:"],
                method_inventory_path=inventory,
                readiness_path=readiness,
                static_config_path=static_config,
                lldb_validation_path=lldb,
                output=output,
                markdown_output=markdown,
            )
            payload = json.loads(output.read_text(encoding="utf-8"))
            markdown_text = markdown.read_text(encoding="utf-8")

        self.assertTrue(result["ok"])
        self.assertEqual(payload["schema"], XPC_ALLOWED_CLASS_FOCUS_SCHEMA)
        self.assertEqual(payload["summary"]["selector_count"], 2)
        self.assertEqual(payload["summary"]["allowed_class_recovered_selector_count"], 1)
        self.assertEqual(payload["summary"]["non_protocol_selector_count"], 1)
        self.assertFalse(payload["summary"]["remote_methods_invoked"])
        self.assertEqual(payload["runtime_boundary"]["hit_count"], 20)
        self.assertEqual(payload["selectors"][0]["classification"], "allowed_classes_recovered")
        self.assertEqual(payload["selectors"][0]["allowed_class_slots"][1]["role"], "count")
        self.assertEqual(payload["selectors"][1]["classification"], "not_protocol_backed_or_local")
        self.assertIn("blocked_no_remote_methods_invoked", markdown_text)


def _entry(selector: str, index: int, of_reply: bool, classes: list[str], *, ok: bool = True) -> dict:
    return {
        "selector": selector,
        "argument_index": index,
        "of_reply": of_reply,
        "ok": ok,
        "classes": classes,
        "class_count": len(classes),
    }


if __name__ == "__main__":
    unittest.main()
