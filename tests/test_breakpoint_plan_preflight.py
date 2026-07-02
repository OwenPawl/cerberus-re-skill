import json
import tempfile
import unittest
from pathlib import Path

from cerberus_re_skill.modules.breakpoint_plan_preflight import (
    BREAKPOINT_PLAN_PREFLIGHT_SCHEMA,
    build_breakpoint_plan_preflight,
)


class BreakpointPlanPreflightTests(unittest.TestCase):
    def test_preflight_classifies_static_and_live_breakpoint_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan = root / "breakpoint-plan.json"
            plan.write_text(
                json.dumps(
                    {
                        "symbols": [
                            {"symbol": "-[ExampleManager updateCatalogWithCompletion:]", "group": "manager"},
                            {"symbol": "-[ExampleTopHitsUpdater updateWithCompletion:]", "group": "top_hits"},
                        ]
                    }
                ),
                encoding="utf-8",
            )
            function_inventory = root / "function_inventory.json"
            function_inventory.write_text(
                json.dumps(
                    {
                        "functions": [
                            {
                                "name": "-[ExampleManager_updateCatalogWithCompletion:]",
                                "address": "27a57659c",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            lldb_symbols = root / "lldb_symbols.json"
            lldb_symbols.write_text(
                json.dumps(
                    {
                        "binary_path": "/Users/example/ghidra-projects/sources/mac-image/ExampleClient",
                        "objc_methods": [
                            {
                                "name": "-[ExampleManager updateCatalogWithCompletion:]",
                                "address": "0x1000",
                            },
                            {
                                "name": "-[ExampleTopHitsUpdater updateWithCompletion:]",
                                "address": "0x2000",
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )
            program_summary = root / "program_summary.json"
            program_summary.write_text(
                json.dumps({"executable_path": "/Users/example/Codex Misc/dyld_extract_fast/ExampleClient"}),
                encoding="utf-8",
            )
            lldb_trace = root / "lldb_trace.json"
            lldb_trace.write_text(
                json.dumps(
                    {
                        "hit_count": 0,
                        "symbols_requested": [
                            "-[ExampleManager updateCatalogWithCompletion:]",
                            "-[ExampleTopHitsUpdater updateWithCompletion:]",
                        ],
                        "breakpoints": [
                            {"id": 1, "locs": 1, "hits": 0, "raw": "resolved"},
                            {"id": 2, "locs": 0, "hits": 0, "raw": "no locations (pending)."},
                        ],
                    }
                ),
                encoding="utf-8",
            )

            result = build_breakpoint_plan_preflight(
                plan=plan,
                function_inventory=function_inventory,
                lldb_symbols=lldb_symbols,
                program_summary=program_summary,
                lldb_trace=lldb_trace,
                output=root / "breakpoint-plan-preflight.json",
                markdown_output=root / "breakpoint-plan-preflight.md",
            )
            payload = json.loads((root / "breakpoint-plan-preflight.json").read_text(encoding="utf-8"))
            markdown = (root / "breakpoint-plan-preflight.md").read_text(encoding="utf-8")

        self.assertTrue(result["ok"])
        self.assertEqual(payload["schema"], BREAKPOINT_PLAN_PREFLIGHT_SCHEMA)
        self.assertEqual(payload["summary"]["symbol_count"], 2)
        self.assertEqual(payload["summary"]["function_inventory_match_count"], 1)
        self.assertEqual(payload["summary"]["lldb_symbol_match_count"], 2)
        self.assertEqual(payload["summary"]["resolved_live_count"], 1)
        self.assertEqual(payload["summary"]["pending_live_count"], 1)
        self.assertEqual(payload["summary"]["sidecar_only_live_pending_count"], 1)
        self.assertEqual(payload["summary"]["resolved_no_hit_count"], 1)
        self.assertEqual(payload["summary"]["sidecar_provenance_mismatch_count"], 1)
        self.assertEqual(payload["sidecar_provenance"]["status"], "mismatch")
        self.assertIn("lldb_symbol_sidecar_path_mismatch", payload["symbols"][0]["warnings"])
        self.assertEqual(payload["symbols"][1]["static_status"], "lldb_sidecar_only")
        self.assertIn("sidecar_only_symbol_pending_in_live_process", payload["symbols"][1]["warnings"])
        self.assertIn("Regenerate LLDB symbols from the same executable path", payload["recommendations"][0])
        self.assertIn("Sidecar provenance: mismatch", markdown)
        self.assertIn("Sidecar-only live-pending: 1", markdown)


if __name__ == "__main__":
    unittest.main()
