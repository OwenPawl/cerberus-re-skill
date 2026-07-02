import json
import tempfile
import unittest
from pathlib import Path

from cerberus_re_skill.modules.lldb_enrich import enrich_lldb_trace


class LldbEnrichObjCMatchingTests(unittest.TestCase):
    def test_objc_runtime_symbol_matches_namespace_function_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inventory = root / "function_inventory.json"
            trace = root / "trace.json"
            output = root / "trace_enriched.json"

            inventory.write_text(
                json.dumps(
                    {
                        "functions": [
                            {
                                "name": "runWithInput:",
                                "namespace": "CodexProbe",
                                "entry": "100000928",
                                "body_size": 140,
                                "caller_count": 0,
                                "callee_count": 5,
                                "artifact_type": "function",
                                "block": "__text",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            trace.write_text(
                json.dumps(
                    {
                        "ok": True,
                        "hits": [
                            {
                                "pc": "0x100000928",
                                "symbol": "-[CodexProbe runWithInput:]",
                                "self_class": "CodexProbe",
                                "selector": "runWithInput:",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            result = enrich_lldb_trace(
                "fixture_project",
                "FixtureProgram",
                trace,
                function_inventory_path=inventory,
                output=output,
            )

            self.assertEqual(result["matched_function_count"], 1)
            self.assertEqual(result["address_mapped_function_count"], 1)
            self.assertEqual(result["symbol_resolved_function_count"], 1)
            self.assertEqual(result["address_or_symbol_evidence_count"], 1)
            self.assertEqual(result["symbol_mismatch_count"], 0)
            self.assertEqual(result["slide"], "0x0")

            enriched = json.loads(output.read_text(encoding="utf-8"))
            hit = enriched["hits"][0]
            self.assertEqual(hit["ghidra_addr"], "0x100000928")
            self.assertEqual(hit["static_match_status"], "verified")
            self.assertEqual(hit["ghidra_function"]["name"], "runWithInput:")
            self.assertEqual(hit["ghidra_function"]["namespace"], "CodexProbe")
            self.assertEqual(
                enriched["enrichment"]["slide_evidence"],
                [
                    {
                        "symbol": "-[CodexProbe runWithInput:]",
                        "runtime_pc": "0x100000928",
                        "static_addr": "0x100000928",
                        "source": "function_inventory",
                    }
                ],
            )

    def test_slide_evidence_deduplicates_alias_keys_per_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inventory = root / "function_inventory.json"
            symbols = root / "lldb_symbols.json"
            trace = root / "trace.json"
            output = root / "trace_enriched.json"

            inventory.write_text(
                json.dumps(
                    {
                        "functions": [
                            {
                                "name": "runWithInput:",
                                "namespace": "CodexProbe",
                                "entry": "100000928",
                                "body_size": 140,
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            symbols.write_text(
                json.dumps(
                    {
                        "objc_methods": [
                            {
                                "name": "-[CodexProbe runWithInput:]",
                                "address": "0x100000928",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            trace.write_text(
                json.dumps(
                    {
                        "ok": True,
                        "hits": [
                            {
                                "pc": "0x100000928",
                                "symbol": "-[CodexProbe runWithInput:]",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            enrich_lldb_trace(
                "fixture_project",
                "FixtureProgram",
                trace,
                function_inventory_path=inventory,
                lldb_symbols_path=symbols,
                output=output,
            )

            enriched = json.loads(output.read_text(encoding="utf-8"))
            evidence = enriched["enrichment"]["slide_evidence"]
            self.assertEqual(len(evidence), 2)
            self.assertEqual({item["source"] for item in evidence}, {"lldb_symbols", "function_inventory"})

    def test_explicit_missing_lldb_symbols_path_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inventory = root / "function_inventory.json"
            trace = root / "trace.json"
            output = root / "trace_enriched.json"
            missing_symbols = root / "missing_lldb_symbols.json"

            inventory.write_text(json.dumps({"functions": []}), encoding="utf-8")
            trace.write_text(json.dumps({"ok": True, "hits": []}), encoding="utf-8")

            with self.assertRaisesRegex(RuntimeError, "missing LLDB symbols"):
                enrich_lldb_trace(
                    "fixture_project",
                    "FixtureProgram",
                    trace,
                    function_inventory_path=inventory,
                    lldb_symbols_path=missing_symbols,
                    output=output,
                )

            self.assertFalse(output.exists())

    def test_conflicting_symbol_slides_are_not_reported_high_confidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inventory = root / "function_inventory.json"
            trace = root / "trace.json"
            output = root / "trace_enriched.json"
            inventory.write_text(
                json.dumps(
                    {
                        "functions": [
                            {"name": "first:", "namespace": "Runner", "entry": "1000", "body_size": 64},
                            {"name": "second:", "namespace": "Runner", "entry": "1100", "body_size": 64},
                        ]
                    }
                ),
                encoding="utf-8",
            )
            trace.write_text(
                json.dumps(
                    {
                        "ok": True,
                        "hits": [
                            {"pc": "0x5000", "symbol": "-[Runner first:]"},
                            {"pc": "0x5110", "symbol": "-[Runner second:]"},
                        ],
                    }
                ),
                encoding="utf-8",
            )

            result = enrich_lldb_trace(
                "fixture_project",
                "FixtureProgram",
                trace,
                function_inventory_path=inventory,
                output=output,
            )
            enriched = json.loads(output.read_text(encoding="utf-8"))

        self.assertTrue(result["slide_conflict"])
        self.assertEqual(result["slide_confidence"], "conflicting")
        self.assertEqual(len(result["slide_candidates"]), 2)
        self.assertTrue(enriched["enrichment"]["slide_conflict"])
        self.assertEqual(enriched["enrichment"]["slide_confidence"], "conflicting")

    def test_symbol_mismatch_does_not_count_as_clean_match(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inventory = root / "function_inventory.json"
            trace = root / "trace.json"
            output = root / "trace_enriched.json"

            inventory.write_text(
                json.dumps(
                    {
                        "functions": [
                            {
                                "name": "differentSelector",
                                "namespace": "CodexProbe",
                                "entry": "100000900",
                                "body_size": 80,
                            },
                            {
                                "name": "runWithInput:",
                                "namespace": "CodexProbe",
                                "entry": "100001000",
                                "body_size": 80,
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )
            trace.write_text(
                json.dumps(
                    {
                        "ok": True,
                        "hits": [
                            {
                                "pc": "0x100000920",
                                "symbol": "-[CodexProbe runWithInput:]",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            result = enrich_lldb_trace(
                "fixture_project",
                "FixtureProgram",
                trace,
                function_inventory_path=inventory,
                known_runtime_pc="0x100000920",
                known_static_addr="0x100000920",
                output=output,
            )

            self.assertEqual(result["matched_function_count"], 0)
            self.assertEqual(result["address_mapped_function_count"], 1)
            self.assertEqual(result["symbol_resolved_function_count"], 1)
            self.assertEqual(result["address_or_symbol_evidence_count"], 1)
            self.assertEqual(result["symbol_mismatch_count"], 1)
            self.assertEqual(result["symbol_resolved_mismatch_count"], 1)
            self.assertEqual(result["symbol_resolved_conflict_count"], 1)

            enriched = json.loads(output.read_text(encoding="utf-8"))
            hit = enriched["hits"][0]
            self.assertEqual(hit["static_match_status"], "symbol_mismatch")
            self.assertEqual(hit["static_match"]["runtime_symbol"], "-[CodexProbe runWithInput:]")
            self.assertEqual(hit["ghidra_function"]["name"], "differentSelector")
            self.assertEqual(hit["symbol_resolved_function"]["name"], "runWithInput:")
            self.assertEqual(hit["symbol_resolved_static_address"], "0x100001000")
            self.assertEqual(hit["static_match"]["symbol_resolution_status"], "symbol_disagrees_with_address")
            self.assertEqual(
                hit["static_match"]["symbol_resolution"]["symbol_resolved_function_name"],
                "runWithInput:",
            )
            self.assertEqual(
                hit["static_match"]["symbol_resolution"]["address_mapped_function_name"],
                "differentSelector",
            )
            self.assertEqual(enriched["enrichment"]["symbol_resolved_conflict_count"], 1)
            self.assertEqual(enriched["enrichment"]["symbol_resolved_function_count"], 1)
            self.assertEqual(enriched["enrichment"]["address_or_symbol_evidence_count"], 1)
            self.assertEqual(
                enriched["enrichment"]["symbol_resolved_conflicts"][0]["address_mapped_static_address"],
                "0x100000920",
            )
            self.assertEqual(
                enriched["enrichment"]["symbol_resolved_conflicts"][0]["symbol_boundary_status"],
                "distant_symbol_address_conflict",
            )
            self.assertEqual(enriched["enrichment"]["symbol_resolved_mismatch_count"], 1)
            self.assertEqual(hit["static_match"]["boundary_status"], "interior_symbol_mismatch")
            self.assertEqual(hit["static_match"]["address_offset_from_entry"], "0x20")
            self.assertTrue(hit["static_match"]["boundary_recovery_candidate"])
            self.assertEqual(result["interior_boundary_mismatch_count"], 1)

    def test_macho_c_export_underscore_matches_lldb_runtime_symbol(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inventory = root / "function_inventory.json"
            trace = root / "trace.json"
            output = root / "trace_enriched.json"

            inventory.write_text(
                json.dumps(
                    {
                        "functions": [
                            {"name": "_TCCAccessPreflight", "entry": "37dc", "body_size": 64},
                            {"name": "_TCCAccessRequest", "entry": "2b98", "body_size": 64},
                        ]
                    }
                ),
                encoding="utf-8",
            )
            trace.write_text(
                json.dumps(
                    {
                        "ok": True,
                        "hits": [
                            {"pc": "0x18bb1d7dc", "symbol": "TCCAccessPreflight"},
                            {"pc": "0x18bb1cb98", "symbol": "TCCAccessRequest"},
                        ],
                    }
                ),
                encoding="utf-8",
            )

            result = enrich_lldb_trace(
                "fixture_project",
                "TCC",
                trace,
                function_inventory_path=inventory,
                output=output,
            )
            enriched = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(result["matched_function_count"], 2)
        self.assertEqual(result["address_mapped_function_count"], 2)
        self.assertEqual(result["symbol_mismatch_count"], 0)
        self.assertEqual(result["slide"], "0x18bb1a000")
        self.assertEqual(enriched["hits"][0]["static_match_status"], "verified")


if __name__ == "__main__":
    unittest.main()
