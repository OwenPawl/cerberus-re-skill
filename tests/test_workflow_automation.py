import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cerberus_re_skill.modules.diffing import _semantic_rank
from cerberus_re_skill.modules.harness import generate_harness, validate_harness_source
from cerberus_re_skill.modules.xpc_graph import (
    _actionable_protocol_hint,
    _apply_registered_owners,
    _infer_edges,
    _parse_owner_hints,
    _suggest_follow_ups,
)
from cerberus_re_skill.modules.xpc_interface_dossier import _rank_candidates


class XpcWorkflowTests(unittest.TestCase):
    def test_generate_harness_can_compile_validate_with_runner(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            trace = root / "trace_enriched.json"
            trace.write_text(
                json.dumps(
                    {
                        "enrichment": {"project": "codex_objc_probe", "program": "CodexObjCProbe"},
                        "hits": [
                            {
                                "symbol": "-[CodexProbe runWithInput:]",
                                "runtime_pc": "0x100000928",
                                "ghidra_addr": "0x100000928",
                                "args": {"x0": "0x1", "x2": "0x2"},
                                "ghidra_function": {"name": "runWithInput:", "entry": "0x100000928"},
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            def runner(cmd):
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

            with patch("cerberus_re_skill.modules.harness.shutil.which", return_value="/usr/bin/clang"):
                result = generate_harness(
                    trace,
                    output=root / "Harness.m",
                    compile_harness=True,
                    compile_output=root / "Harness",
                    runner=runner,
                )

        self.assertTrue(result["ok"])
        self.assertEqual(result["language"], "objc")
        self.assertTrue(result["compile"]["ok"])
        self.assertIn("-framework", result["compile"]["command"])

    def test_generate_harness_does_not_infer_framework_from_class_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            trace = root / "trace_enriched.json"
            trace.write_text(
                json.dumps(
                    {
                        "enrichment": {"project": "proj"},
                        "hits": [
                            {
                                "symbol": "-[ExampleProbe run:]",
                                "runtime_pc": "0x100000928",
                                "ghidra_addr": "0x100000928",
                                "args": {"x0": "0x1"},
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            result = generate_harness(trace, output=root / "Harness.m")
            source = Path(result["output"]).read_text(encoding="utf-8")

        self.assertEqual(result["framework"], "TargetFramework")
        self.assertNotIn("ExampleKit", source)

    def test_generate_harness_uses_module_qualified_native_symbol_framework(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            trace = root / "trace_enriched.json"
            trace.write_text(
                json.dumps(
                    {
                        "enrichment": {"project": "proj"},
                        "hits": [
                            {
                                "symbol": "ExampleFramework!ExampleExport",
                                "runtime_pc": "0x100000928",
                                "ghidra_addr": "0x100000928",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            result = generate_harness(trace, output=root / "Harness.swift")

        self.assertEqual(result["framework"], "ExampleFramework")

    def test_validate_harness_source_reports_compile_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "Harness.m"
            source.write_text("int main(void) { return 0; }\n", encoding="utf-8")

            def runner(cmd):
                return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="compile failed")

            with patch("cerberus_re_skill.modules.harness.shutil.which", return_value="/usr/bin/clang"):
                result = validate_harness_source(source, language="objc", runner=runner)

        self.assertFalse(result["ok"])
        self.assertEqual(result["returncode"], 1)
        self.assertIn("compile failed", result["stderr"])

    def test_xpc_graph_suggests_missing_owner_and_unresolved_client(self) -> None:
        nodes = [
            {
                "id": "client:Client",
                "program": "Client",
                "services": [{"value": "com.example.missing-helper"}],
                "clients": ["ClientConnection"],
                "listeners": [],
                "protocols": ["ClientXPCProtocol"],
            }
        ]
        suggestions = _suggest_follow_ups(nodes, [])
        kinds = {item["kind"] for item in suggestions}
        self.assertIn("missing_service_owner", kinds)
        self.assertIn("client_without_resolved_service", kinds)

    def test_xpc_graph_owner_hints_resolve_missing_owner(self) -> None:
        nodes = [
            {
                "id": "workflow:ExampleKit",
                "program": "ExampleKit",
                "services": [{"value": "com.example.helper"}],
                "clients": ["HelperClient"],
                "listeners": [],
                "protocols": [],
            }
        ]
        hints = _parse_owner_hints(["com.example.helper=helper:Helper"])
        nodes = _apply_registered_owners(nodes, hints)
        edges = _infer_edges(nodes, hints)
        suggestions = _suggest_follow_ups(nodes, edges)

        self.assertIn(
            ("workflow:ExampleKit", "helper:Helper", "references_service"),
            {(edge["from"], edge["to"], edge["relation"]) for edge in edges},
        )
        self.assertNotIn("missing_service_owner", {item["kind"] for item in suggestions})

    def test_xpc_graph_filters_protocol_noise(self) -> None:
        self.assertFalse(_actionable_protocol_hint("_objc_msgSend$interfaceWithProtocol:"))
        self.assertFalse(_actionable_protocol_hint("_ExampleManagerXPCInterfaceMachServiceName"))
        self.assertTrue(_actionable_protocol_hint("_ExampleAutomationDaemonXPCInterface"))

    def test_xpc_interface_dossier_ranks_automation_interfaces(self) -> None:
        surfaces = [
            {
                "project": "examplekit_full_dyld_extract",
                "program": "ExampleKit",
                "topology_hints": {
                    "probable_services": [{"value": "com.example.automationd.xpc"}],
                    "probable_interfaces": [
                        {"name": "_ExampleAutomationDaemonXPCInterface"},
                        {"name": "_ExampleUIPresenterXPCInterface"},
                    ],
                    "probable_listeners": [{"name": "interfaceWithProtocol:"}],
                    "probable_clients": [{"name": "initWithMachServiceName:options:"}],
                },
                "xpc_classes": ["ExampleUIPresenterXPCConnection"],
            }
        ]
        edges = {
            "examplekit_full_dyld_extract:ExampleKit": [
                {
                    "from": "examplekit_full_dyld_extract:ExampleKit",
                    "to": "exampled_arm64e:exampled.arm64e",
                    "relation": "references_service",
                    "service": "com.example.automationd.xpc",
                }
            ]
        }

        candidates = _rank_candidates(surfaces, edges)

        self.assertGreaterEqual(len(candidates), 2)
        self.assertEqual(candidates[0]["interface"], "_ExampleAutomationDaemonXPCInterface")
        self.assertIn("automation", candidates[0]["reasons"])
        self.assertEqual(candidates[0]["owner_edges"][0]["service"], "com.example.automationd.xpc")

    def test_diff_semantic_rank_flags_security_interface_changes(self) -> None:
        rank = _semantic_rank(
            "validatePolicyDecision",
            {
                "signature": {"before": "int f()", "after": "bool f(int)"},
                "callee_count": {"before": 1, "after": 4},
            },
        )
        self.assertEqual(rank["risk"], "high")
        self.assertIn("security_relevant_name", {item["kind"] for item in rank["categories"]})
        self.assertIn("interface_boundary_changed", {item["kind"] for item in rank["categories"]})


if __name__ == "__main__":
    unittest.main()
