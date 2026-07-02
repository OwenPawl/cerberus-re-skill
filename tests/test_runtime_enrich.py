import json
import tempfile
import unittest
from pathlib import Path

from cerberus_re_skill.modules.runtime_enrich import enrich_runtime_hits


class RuntimeEnrichTests(unittest.TestCase):
    def test_enriches_frida_runtime_hit_by_objc_symbol(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inventory = root / "function_inventory.json"
            runtime_hits = root / "runtime_hits.json"
            output = root / "runtime_hits_enriched.json"

            inventory.write_text(
                json.dumps(
                    {
                        "functions": [
                            {
                                "name": "runWithInput:",
                                "namespace": "CodexProbe",
                                "entry": "100000928",
                                "body_size": 140,
                                "caller_count": 1,
                                "callee_count": 3,
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            runtime_hits.write_text(
                json.dumps(
                    {
                        "schema": "ghidra-re.runtime-hits.v1",
                        "hits": [
                            {
                                "schema": "ghidra-re.runtime-hit.v1",
                                "tool": "frida",
                                "event_type": "objc-call",
                                "symbol": "-[CodexProbe runWithInput:]",
                                "target": {"symbol": "-[CodexProbe runWithInput:]"},
                                "runtime": {"pc": "0x100000928"},
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            result = enrich_runtime_hits(
                "fixture_project",
                "FixtureProgram",
                runtime_hits,
                function_inventory_path=inventory,
                output=output,
            )
            enriched = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(result["matched_function_count"], 1)
        self.assertEqual(result["symbol_resolved_function_count"], 1)
        self.assertEqual(result["address_or_symbol_evidence_count"], 1)
        self.assertTrue(enriched["enriched"])
        self.assertEqual(enriched["enrichment"]["schema"], "ghidra-re.runtime-hit-enrichment.v1")
        self.assertEqual(enriched["hits"][0]["ghidra_function"]["namespace"], "CodexProbe")
        self.assertEqual(enriched["hits"][0]["ghidra_function"]["function_identity"]["project"], "fixture_project")
        self.assertEqual(enriched["hits"][0]["ghidra_function"]["function_identity"]["program"], "FixtureProgram")
        self.assertEqual(enriched["hits"][0]["runtime"]["static_address"], "0x100000928")

    def test_enriches_lldb_runtime_hit_by_static_address(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inventory = root / "function_inventory.json"
            runtime_hits = root / "runtime_hits.json"
            output = root / "runtime_hits_enriched.json"

            inventory.write_text(
                json.dumps(
                    {
                        "functions": [
                            {
                                "name": "main",
                                "namespace": "Global",
                                "entry": "100003f00",
                                "body_size": 64,
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            runtime_hits.write_text(
                json.dumps(
                    {
                        "schema": "ghidra-re.runtime-hits.v1",
                        "hits": [
                            {
                                "schema": "ghidra-re.runtime-hit.v1",
                                "tool": "lldb",
                                "event_type": "breakpoint-hit",
                                "runtime": {"pc": "0x180003f00", "static_address": "0x100003f00"},
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            result = enrich_runtime_hits(
                "fixture_project",
                "FixtureProgram",
                runtime_hits,
                function_inventory_path=inventory,
                output=output,
            )
            enriched = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(result["matched_function_count"], 1)
        self.assertEqual(enriched["hits"][0]["ghidra_function"]["name"], "main")
        self.assertEqual(enriched["hits"][0]["ghidra_addr"], "0x100003f00")

    def test_enriches_frida_hit_by_module_base_and_program_image_base(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inventory = root / "function_inventory.json"
            program_summary = root / "program_summary.json"
            runtime_hits = root / "runtime_hits.json"
            output = root / "runtime_hits_enriched.json"

            inventory.write_text(
                json.dumps(
                    {
                        "functions": [
                            {
                                "name": "FUN_100001000",
                                "entry": "100001000",
                                "body_size": 32,
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            program_summary.write_text(json.dumps({"image_base": "100000000"}), encoding="utf-8")
            runtime_hits.write_text(
                json.dumps(
                    {
                        "schema": "ghidra-re.runtime-hits.v1",
                        "hits": [
                            {
                                "schema": "ghidra-re.runtime-hit.v1",
                                "tool": "frida",
                                "event_type": "objc-call",
                                "symbol": "+[FixtureProgram secureCheck]",
                                "runtime": {
                                    "pc": "0x180001004",
                                    "module": {
                                        "name": "FixtureProgram",
                                        "path": "/System/Library/PrivateFrameworks/FixtureProgram.framework/FixtureProgram",
                                        "base": "0x180000000",
                                    },
                                },
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            result = enrich_runtime_hits(
                "fixture_project",
                "FixtureProgram",
                runtime_hits,
                function_inventory_path=inventory,
                output=output,
            )
            enriched = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(result["address_mapped_function_count"], 1)
        self.assertEqual(result["slide"], "0x80000000")
        self.assertEqual(result["slide_confidence"], "module_base")
        self.assertEqual(enriched["hits"][0]["ghidra_addr"], "0x100001004")
        self.assertEqual(enriched["hits"][0]["static_match"]["match_source"], "address")
        self.assertEqual(enriched["hits"][0]["runtime_image_match_status"], "same_image_runtime_hit")

    def test_marks_cross_image_native_runtime_hits(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inventory = root / "function_inventory.json"
            program_summary = root / "program_summary.json"
            runtime_hits = root / "runtime_hits.json"
            output = root / "runtime_hits_enriched.json"

            inventory.write_text(
                json.dumps(
                    {
                        "functions": [
                            {
                                "name": "_AFGetGlobalState",
                                "entry": "10001fb60",
                                "body_size": 16,
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            program_summary.write_text(json.dumps({"image_base": "100000000"}), encoding="utf-8")
            runtime_hits.write_text(
                json.dumps(
                    {
                        "schema": "ghidra-re.runtime-hits.v1",
                        "hits": [
                            {
                                "schema": "ghidra-re.runtime-hit.v1",
                                "tool": "frida",
                                "event_type": "native-call",
                                "symbol": "AFGetGlobalState",
                                "runtime": {
                                    "pc": "0x238952d20",
                                    "module": {
                                        "name": "ApplicationFirewall",
                                        "path": (
                                            "/System/Library/PrivateFrameworks/"
                                            "ApplicationFirewall.framework/ApplicationFirewall"
                                        ),
                                        "base": "0x238900000",
                                    },
                                },
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            result = enrich_runtime_hits(
                "fixture_project",
                "socketfilterfw.arm64e",
                runtime_hits,
                function_inventory_path=inventory,
                output=output,
            )
            enriched = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(result["cross_image_runtime_hit_count"], 1)
        self.assertEqual(enriched["enrichment"]["cross_image_runtime_hit_count"], 1)
        self.assertEqual(
            enriched["enrichment"]["cross_image_runtime_modules"][0]["module_name"],
            "ApplicationFirewall",
        )
        self.assertIn("cross-image evidence", enriched["enrichment"]["runtime_image_guidance"][1])
        self.assertEqual(enriched["hits"][0]["runtime_image_match_status"], "cross_image_runtime_hit")
        self.assertEqual(enriched["hits"][0]["runtime_image"]["expected_program"], "socketfilterfw.arm64e")

    def test_explicit_missing_lldb_symbols_path_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inventory = root / "function_inventory.json"
            runtime_hits = root / "runtime_hits.json"
            output = root / "runtime_hits_enriched.json"
            missing_symbols = root / "missing_lldb_symbols.json"

            inventory.write_text(json.dumps({"functions": []}), encoding="utf-8")
            runtime_hits.write_text(json.dumps({"schema": "ghidra-re.runtime-hits.v1", "hits": []}), encoding="utf-8")

            with self.assertRaisesRegex(RuntimeError, "missing LLDB symbols"):
                enrich_runtime_hits(
                    "fixture_project",
                    "FixtureProgram",
                    runtime_hits,
                    function_inventory_path=inventory,
                    lldb_symbols_path=missing_symbols,
                    output=output,
                )

            self.assertFalse(output.exists())

    def test_enriches_macho_c_export_when_runtime_omits_leading_underscore(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inventory = root / "function_inventory.json"
            runtime_hits = root / "runtime_hits.json"
            output = root / "runtime_hits_enriched.json"

            inventory.write_text(
                json.dumps({"functions": [{"name": "_TCCAccessPreflight", "entry": "37dc", "body_size": 64}]}),
                encoding="utf-8",
            )
            runtime_hits.write_text(
                json.dumps(
                    {
                        "schema": "ghidra-re.runtime-hits.v1",
                        "hits": [
                            {
                                "schema": "ghidra-re.runtime-hit.v1",
                                "tool": "lldb",
                                "event_type": "breakpoint-hit",
                                "target": {"symbol": "TCCAccessPreflight"},
                                "runtime": {"pc": "0x18bb1d7dc"},
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            result = enrich_runtime_hits(
                "fixture_project",
                "TCC",
                runtime_hits,
                function_inventory_path=inventory,
                output=output,
            )
            enriched = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(result["matched_function_count"], 1)
        self.assertEqual(enriched["hits"][0]["ghidra_function"]["name"], "_TCCAccessPreflight")
        self.assertEqual(enriched["hits"][0]["runtime"]["static_address"], "0x37dc")

    def test_enriches_objc_category_method_by_runtime_class_symbol(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inventory = root / "function_inventory.json"
            runtime_hits = root / "runtime_hits.json"
            output = root / "runtime_hits_enriched.json"

            inventory.write_text(
                json.dumps(
                    {
                        "functions": [
                            {
                                "name": "-[ExampleTask(Compatibility)_initWithName:description:associatedBundleIdentifier:actions:]",
                                "entry": "27c13e514",
                                "body_size": 56,
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            runtime_hits.write_text(
                json.dumps(
                    {
                        "schema": "ghidra-re.runtime-hits.v1",
                        "hits": [
                            {
                                "schema": "ghidra-re.runtime-hit.v1",
                                "tool": "frida",
                                "event_type": "objc-call",
                                "symbol": "-[ExampleTask initWithName:description:associatedBundleIdentifier:actions:]",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            result = enrich_runtime_hits(
                "fixture_project",
                "ExampleKit",
                runtime_hits,
                function_inventory_path=inventory,
                output=output,
            )
            enriched = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(result["matched_function_count"], 1)
        self.assertEqual(
            enriched["hits"][0]["ghidra_function"]["name"],
            "-[ExampleTask(Compatibility)_initWithName:description:associatedBundleIdentifier:actions:]",
        )
        self.assertEqual(enriched["hits"][0]["ghidra_addr"], "0x27c13e514")

    def test_enriches_proxy_hit_by_unique_selector_owner_without_slide(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inventory = root / "function_inventory.json"
            runtime_hits = root / "runtime_hits.json"
            output = root / "runtime_hits_enriched.json"
            selector = "runTaskWithDescriptor:request:inEnvironment:runningContext:completion:"

            inventory.write_text(
                json.dumps(
                    {
                        "functions": [
                            {
                                "name": selector,
                                "namespace": "ExampleBackgroundTaskRunner",
                                "entry": "003c9100",
                                "body_size": 256,
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            runtime_hits.write_text(
                json.dumps(
                    {
                        "schema": "ghidra-re.runtime-hits.v1",
                        "hits": [
                            {
                                "schema": "ghidra-re.runtime-hit.v1",
                                "tool": "frida",
                                "event_type": "objc-call",
                                "symbol": f"-[ExampleOutOfProcessTaskControllerXPCProxy {selector}]",
                                "selector": selector,
                                "runtime": {"pc": "0x1afc2a5d4"},
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            result = enrich_runtime_hits(
                "fixture_project",
                "ExampleKit",
                runtime_hits,
                function_inventory_path=inventory,
                output=output,
            )
            enriched = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(result["matched_function_count"], 1)
        self.assertEqual(enriched["hits"][0]["ghidra_function"]["namespace"], "ExampleBackgroundTaskRunner")
        self.assertEqual(enriched["hits"][0]["ghidra_addr"], "0x3c9100")

    def test_does_not_correlate_selector_when_multiple_static_owners_exist(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inventory = root / "function_inventory.json"
            runtime_hits = root / "runtime_hits.json"
            output = root / "runtime_hits_enriched.json"
            selector = "performQuery:inValueSet:toolInvocation:options:completionHandler:"

            inventory.write_text(
                json.dumps(
                    {
                        "functions": [
                            {"name": selector, "namespace": "FirstRunner", "entry": "1000"},
                            {"name": selector, "namespace": "SecondRunner", "entry": "2000"},
                        ]
                    }
                ),
                encoding="utf-8",
            )
            runtime_hits.write_text(
                json.dumps(
                    {
                        "schema": "ghidra-re.runtime-hits.v1",
                        "hits": [
                            {
                                "schema": "ghidra-re.runtime-hit.v1",
                                "tool": "frida",
                                "event_type": "objc-call",
                                "symbol": f"-[ExampleOutOfProcessTaskControllerXPCProxy {selector}]",
                                "selector": selector,
                                "runtime": {"pc": "0x3000"},
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            result = enrich_runtime_hits(
                "fixture_project",
                "ExampleKit",
                runtime_hits,
                function_inventory_path=inventory,
                output=output,
            )
            enriched = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(result["matched_function_count"], 0)
        self.assertNotIn("ghidra_function", enriched["hits"][0])

    def test_address_symbol_mismatch_does_not_count_as_clean_match(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inventory = root / "function_inventory.json"
            runtime_hits = root / "runtime_hits.json"
            output = root / "runtime_hits_enriched.json"

            inventory.write_text(
                json.dumps(
                    {
                        "functions": [
                            {"name": "get_id", "namespace": "Fixture.Consumer", "entry": "100026d40", "body_size": 128},
                            {"name": "_XAMIsAutomationModeEnabled", "entry": "10002728c"},
                        ]
                    }
                ),
                encoding="utf-8",
            )
            runtime_hits.write_text(
                json.dumps(
                    {
                        "schema": "ghidra-re.runtime-hits.v1",
                        "hits": [
                            {
                                "schema": "ghidra-re.runtime-hit.v1",
                                "tool": "frida",
                                "event_type": "native-call",
                                "symbol": "XAMIsAutomationModeEnabled",
                                "runtime": {"pc": "0x23e19b1f4"},
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            result = enrich_runtime_hits(
                "fixture_project",
                "FixtureProgram",
                runtime_hits,
                function_inventory_path=inventory,
                known_runtime_pc="0x23e19b1f4",
                known_static_addr="0x100026d6a",
                output=output,
            )
            enriched = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(result["matched_function_count"], 0)
        self.assertEqual(result["address_mapped_function_count"], 1)
        self.assertEqual(result["symbol_resolved_function_count"], 1)
        self.assertEqual(result["address_or_symbol_evidence_count"], 1)
        self.assertEqual(result["symbol_mismatch_count"], 1)
        self.assertEqual(result["symbol_resolved_mismatch_count"], 1)
        self.assertEqual(result["symbol_resolved_conflict_count"], 1)
        self.assertEqual(result["interior_boundary_mismatch_count"], 1)
        self.assertEqual(enriched["enrichment"]["symbol_mismatch_count"], 1)
        self.assertEqual(enriched["enrichment"]["symbol_resolved_function_count"], 1)
        self.assertEqual(enriched["enrichment"]["address_or_symbol_evidence_count"], 1)
        self.assertEqual(enriched["enrichment"]["symbol_resolved_mismatch_count"], 1)
        self.assertEqual(enriched["enrichment"]["symbol_resolved_conflict_count"], 1)
        self.assertEqual(enriched["enrichment"]["interior_boundary_mismatch_count"], 1)
        hit = enriched["hits"][0]
        self.assertEqual(hit["ghidra_function"]["name"], "get_id")
        self.assertEqual(hit["symbol_resolved_function"]["name"], "_XAMIsAutomationModeEnabled")
        self.assertEqual(hit["symbol_resolved_static_address"], "0x10002728c")
        self.assertEqual(hit["static_match_status"], "symbol_mismatch")
        self.assertEqual(hit["static_match"]["runtime_symbol"], "XAMIsAutomationModeEnabled")
        self.assertEqual(hit["static_match"]["symbol_resolution_status"], "symbol_disagrees_with_address")
        self.assertEqual(
            hit["static_match"]["symbol_resolution"]["symbol_resolved_function_name"],
            "_XAMIsAutomationModeEnabled",
        )
        self.assertEqual(
            hit["static_match"]["symbol_resolution"]["symbol_resolved_static_address"],
            "0x10002728c",
        )
        self.assertEqual(
            hit["static_match"]["symbol_resolution"]["address_mapped_function_name"],
            "get_id",
        )
        self.assertEqual(
            enriched["enrichment"]["symbol_resolved_conflicts"][0]["address_mapped_static_address"],
            "0x100026d6a",
        )
        self.assertEqual(
            enriched["enrichment"]["symbol_resolved_conflicts"][0]["symbol_boundary_status"],
            "distant_symbol_address_conflict",
        )
        self.assertEqual(hit["static_match"]["boundary_status"], "interior_symbol_mismatch")
        self.assertEqual(hit["static_match"]["address_offset_from_entry"], "0x2a")

    def test_symbol_resolved_conflict_classifies_neighboring_boundary_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inventory = root / "function_inventory.json"
            runtime_hits = root / "runtime_hits.json"
            output = root / "runtime_hits_enriched.json"

            inventory.write_text(
                json.dumps(
                    {
                        "functions": [
                            {
                                "name": "___Previous_block_invoke",
                                "entry": "1000",
                                "body_size": 64,
                            },
                            {
                                "name": "_TargetExport",
                                "entry": "1028",
                                "body_size": 64,
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )
            runtime_hits.write_text(
                json.dumps(
                    {
                        "schema": "ghidra-re.runtime-hits.v1",
                        "hits": [
                            {
                                "schema": "ghidra-re.runtime-hit.v1",
                                "tool": "frida",
                                "event_type": "native-call",
                                "symbol": "TargetExport",
                                "runtime": {"pc": "0x5018"},
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            enrich_runtime_hits(
                "fixture_project",
                "FixtureProgram",
                runtime_hits,
                function_inventory_path=inventory,
                known_runtime_pc="0x5018",
                known_static_addr="0x1018",
                output=output,
            )
            enriched = json.loads(output.read_text(encoding="utf-8"))

        conflict = enriched["enrichment"]["symbol_resolved_conflicts"][0]
        self.assertEqual(conflict["symbol_resolved_static_address"], "0x1028")
        self.assertEqual(conflict["address_mapped_static_address"], "0x1018")
        self.assertEqual(conflict["symbol_boundary_delta"], "0x10")
        self.assertEqual(conflict["symbol_boundary_status"], "neighboring_symbol_boundary_drift")
        self.assertEqual(conflict["symbol_boundary_direction"], "runtime_before_symbol_entry")
        self.assertEqual(conflict["address_mapped_function_kind"], "block")
        self.assertIn("function boundaries", conflict["boundary_recovery_hint"])

    def test_conflicting_slides_preserve_candidate_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inventory = root / "function_inventory.json"
            runtime_hits = root / "runtime_hits.json"
            output = root / "runtime_hits_enriched.json"

            inventory.write_text(
                json.dumps(
                    {
                        "functions": [
                            {"name": "_FirstBoundary", "entry": "1000", "body_size": 64},
                            {"name": "_SecondBoundary", "entry": "1100", "body_size": 64},
                        ]
                    }
                ),
                encoding="utf-8",
            )
            runtime_hits.write_text(
                json.dumps(
                    {
                        "schema": "ghidra-re.runtime-hits.v1",
                        "hits": [
                            {
                                "schema": "ghidra-re.runtime-hit.v1",
                                "tool": "frida",
                                "event_type": "native-call",
                                "symbol": "FirstBoundary",
                                "runtime": {"pc": "0x5000"},
                            },
                            {
                                "schema": "ghidra-re.runtime-hit.v1",
                                "tool": "frida",
                                "event_type": "native-call",
                                "symbol": "SecondBoundary",
                                "runtime": {"pc": "0x5110"},
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )

            result = enrich_runtime_hits(
                "fixture_project",
                "FixtureProgram",
                runtime_hits,
                function_inventory_path=inventory,
                output=output,
            )
            enriched = json.loads(output.read_text(encoding="utf-8"))

        self.assertTrue(result["slide_conflict"])
        self.assertEqual(result["slide_confidence"], "conflicting")
        self.assertEqual(len(result["slide_candidates"]), 2)
        self.assertTrue(enriched["enrichment"]["slide_conflict"])
        self.assertEqual(len(enriched["enrichment"]["slide_candidates"]), 2)


if __name__ == "__main__":
    unittest.main()
