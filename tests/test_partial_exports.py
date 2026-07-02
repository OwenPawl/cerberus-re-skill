import json
import tempfile
import unittest
from pathlib import Path

from cerberus_re_skill.core.config import cfg
from cerberus_re_skill.modules.xpc_surface import build_xpc_surface


class PartialExportBundleTests(unittest.TestCase):
    def test_xpc_surface_tolerates_missing_optional_export_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "xpc_surface.json"
            markdown = root / "xpc_surface.md"

            result = build_xpc_surface(
                "partial_project",
                "PartialProgram",
                objc_metadata_path=root / "missing_objc.json",
                strings_path=root / "missing_strings.json",
                symbols_path=root / "missing_symbols.json",
                output=output,
                markdown_output=markdown,
            )

            self.assertTrue(result["ok"])
            self.assertEqual(result["service_name_count"], 0)
            self.assertEqual(result["xpc_symbol_count"], 0)
            self.assertEqual(result["missing_input_count"], 3)
            self.assertEqual(len(result["warnings"]), 3)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(report["summary"]["xpc_class_count"], 0)
            self.assertFalse(report["input_status"]["objc_metadata"]["exists"])
            markdown_text = markdown.read_text(encoding="utf-8")
            self.assertIn("# XPC Surface", markdown_text)
            self.assertIn("## Input Warnings", markdown_text)

    def test_xpc_surface_creates_default_markdown_parent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "nested" / "xpc_surface.json"
            old_exports_dir = cfg.exports_dir
            cfg.exports_dir = root / "exports"
            self.addCleanup(setattr, cfg, "exports_dir", old_exports_dir)

            result = build_xpc_surface(
                "external_output_project",
                "ExternalProgram",
                objc_metadata_path=root / "missing_objc.json",
                strings_path=root / "missing_strings.json",
                symbols_path=root / "missing_symbols.json",
                output=output,
            )

            self.assertTrue(result["ok"])
            self.assertTrue(output.exists())
            self.assertTrue(Path(result["markdown_output"]).exists())
            self.assertIn("# XPC Surface", Path(result["markdown_output"]).read_text(encoding="utf-8"))

    def test_xpc_surface_counts_explicit_export_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            objc = root / "objc_metadata.json"
            strings = root / "strings.json"
            symbols = root / "symbols.json"
            objc.write_text(
                json.dumps(
                    {
                        "classes": ["NSXPCConnection"],
                        "interface_classes": ["ExampleManagerXPCInterface"],
                        "selectors": ["initWithMachServiceName:options:", "remoteObjectProxyWithErrorHandler:"],
                        "ivars": ['T@"NSXPCConnection",&,N,V_xpcConnection'],
                        "protocol_refs": [
                            {
                                "name": "__OBJC_PROTOCOL_REFERENCE_$_ExampleManagerXPCInterface",
                                "source": "symbol",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            strings.write_text(
                json.dumps(
                    {
                        "strings": [
                            {
                                "value": "com.apple.example.xpc",
                                "address": "1000",
                                "xref_count": 1,
                                "xrefs": [{"from_function": "-[Client connect]"}],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            symbols.write_text(
                json.dumps(
                    {
                        "symbols": [
                            {
                                "name": "_objc_msgSend$setRemoteObjectInterface:",
                                "address": "2000",
                                "symbol_type": "Function",
                                "xref_count": 1,
                            },
                            {
                                "name": "$$distributed_thunk_method_descriptor_for_AppIntentsServices.RunnerServiceDispatcherActorProtocol.performIntent(AppIntentsServices.AppIntentsProtocol.PerformAction.Request)_async_throws_->_AppIntentsServices.AppIntentsProtocol.PerformAction.Response",
                                "address": "3000",
                                "symbol_type": "Function",
                                "xref_count": 2,
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            result = build_xpc_surface(
                "explicit_project",
                "ExplicitProgram",
                objc_metadata_path=objc,
                strings_path=strings,
                symbols_path=symbols,
                output=root / "xpc_surface.json",
                markdown_output=root / "xpc_surface.md",
            )

            self.assertEqual(result["missing_input_count"], 0)
            self.assertEqual(result["xpc_protocol_count"], 1)
            self.assertEqual(result["service_name_count"], 1)
            self.assertEqual(result["reverse_dns_service_hint_count"], 0)
            self.assertEqual(result["distributed_method_count"], 1)
            report = json.loads((root / "xpc_surface.json").read_text(encoding="utf-8"))
            self.assertEqual(report["xpc_protocols"][0]["name"], "ExampleManagerXPCInterface")
            self.assertTrue(report["input_status"]["symbols"]["exists"])
            self.assertEqual(report["distributed_methods"][0]["method"].split("(", 1)[0], "performIntent")
            self.assertEqual(report["distributed_methods"][0]["descriptor_kind"], "distributed_thunk")
            markdown_text = (root / "xpc_surface.md").read_text(encoding="utf-8")
            self.assertIn("## Swift Distributed Methods", markdown_text)
            self.assertIn("performIntent", markdown_text)

    def test_xpc_surface_uses_bundle_dir_for_inputs_and_default_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = root / "apple_bundle"
            bundle.mkdir()
            (bundle / "objc_metadata.json").write_text(
                json.dumps(
                    {
                        "classes": ["NSXPCConnection"],
                        "selectors": ["remoteObjectProxyWithErrorHandler:"],
                    }
                ),
                encoding="utf-8",
            )
            (bundle / "strings.json").write_text(
                json.dumps(
                    {
                        "strings": [
                            {
                                "value": "com.apple.example.service",
                                "address": "1000",
                                "xref_count": 1,
                                "xrefs": [{"from_function": "-[Example connect]"}],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            (bundle / "symbols.json").write_text(
                json.dumps({"symbols": [{"name": "_xpc_connection_create_mach_service", "address": "2000"}]}),
                encoding="utf-8",
            )

            result = build_xpc_surface(
                "bundle_project",
                "BundleProgram",
                bundle_dir=bundle,
            )

            self.assertEqual(result["missing_input_count"], 0)
            self.assertEqual(result["service_name_count"], 1)
            self.assertEqual(result["output"], str(bundle / "xpc_surface.json"))
            self.assertEqual(result["markdown_output"], str(bundle / "xpc_surface.md"))
            report = json.loads((bundle / "xpc_surface.json").read_text(encoding="utf-8"))
            self.assertEqual(report["inputs"]["bundle_dir"], str(bundle))
            self.assertEqual(report["inputs"]["strings"], str(bundle / "strings.json"))

    def test_xpc_surface_reports_bare_reverse_dns_service_hints(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            objc = root / "objc_metadata.json"
            strings = root / "strings.json"
            symbols = root / "symbols.json"
            objc.write_text(
                json.dumps(
                    {
                        "classes": ["NSXPCConnection"],
                        "selectors": ["initWithMachServiceName:options:"],
                    }
                ),
                encoding="utf-8",
            )
            strings.write_text(
                json.dumps(
                    {
                        "strings": [
                            {
                                "value": "com.apple.syspolicy.exec",
                                "address": "1000",
                                "xref_count": 0,
                                "xrefs": [],
                            },
                            {
                                "value": "com.apple.backgroundtaskmanagement",
                                "address": "1010",
                                "xref_count": 1,
                                "xrefs": [{"from_function": "-[BTMClient connect]"}],
                            },
                            {
                                "value": "com.apple.private.tcc.allow",
                                "address": "1020",
                                "xref_count": 1,
                                "xrefs": [{"from_function": "-[NotAService useEntitlement]"}],
                            },
                            {
                                "value": "com.apple.security.cs.disable-executable-page-protection",
                                "address": "1030",
                                "xref_count": 0,
                                "xrefs": [],
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )
            symbols.write_text(json.dumps({}), encoding="utf-8")

            result = build_xpc_surface(
                "reverse_dns_project",
                "ReverseDNSProgram",
                objc_metadata_path=objc,
                strings_path=strings,
                symbols_path=symbols,
                output=root / "xpc_surface.json",
                markdown_output=root / "xpc_surface.md",
            )

            self.assertEqual(result["service_name_count"], 0)
            self.assertEqual(result["reverse_dns_service_hint_count"], 2)
            report = json.loads((root / "xpc_surface.json").read_text(encoding="utf-8"))
            hints = {item["value"]: item for item in report["reverse_dns_service_hints"]}
            self.assertIn("com.apple.syspolicy.exec", hints)
            self.assertIn("com.apple.backgroundtaskmanagement", hints)
            self.assertNotIn("com.apple.private.tcc.allow", hints)
            self.assertNotIn("com.apple.security.cs.disable-executable-page-protection", hints)
            self.assertEqual(report["topology_hints"]["probable_services"], [])
            markdown_text = (root / "xpc_surface.md").read_text(encoding="utf-8")
            self.assertIn("## Reverse-DNS Service Hints", markdown_text)
            self.assertIn("com.apple.syspolicy.exec", markdown_text)

    def test_xpc_surface_does_not_promote_symbolic_service_name_keys(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            objc = root / "objc_metadata.json"
            strings = root / "strings.json"
            symbols = root / "symbols.json"
            objc.write_text(
                json.dumps(
                    {
                        "classes": ["NSXPCConnection"],
                        "selectors": ["initWithMachServiceName:options:"],
                    }
                ),
                encoding="utf-8",
            )
            strings.write_text(
                json.dumps(
                    {
                        "strings": [
                            {
                                "value": "_kMKBUserSwitchTaskMachServiceNameKey",
                                "address": "1000",
                                "xref_count": 1,
                                "xrefs": [{"from_function": None}],
                            },
                            {
                                "value": "com.apple.mobile.keybagd.xpc",
                                "address": "1010",
                                "xref_count": 0,
                                "xrefs": [],
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )
            symbols.write_text(json.dumps({}), encoding="utf-8")

            result = build_xpc_surface(
                "symbolic_key_project",
                "SymbolicKeyProgram",
                objc_metadata_path=objc,
                strings_path=strings,
                symbols_path=symbols,
                output=root / "xpc_surface.json",
                markdown_output=root / "xpc_surface.md",
            )

            self.assertEqual(result["service_name_count"], 1)
            report = json.loads((root / "xpc_surface.json").read_text(encoding="utf-8"))
            services = {item["value"] for item in report["service_names"]}
            self.assertEqual(services, {"com.apple.mobile.keybagd.xpc"})

    def test_xpc_surface_reports_symbolic_swift_distributed_requests(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            objc = root / "objc_metadata.json"
            strings = root / "strings.json"
            symbols = root / "symbols.json"
            objc.write_text(json.dumps({}), encoding="utf-8")
            strings.write_text(
                json.dumps(
                    {
                        "strings": [
                            {
                                "value": (
                                    "$s18AppIntentsServices06RemoteaB5ActorC21fetchOptionsForActiony"
                                    "AA0aB8ProtocolO05FetchghI0O8ResponseOAH7RequestVYaKFTE"
                                ),
                                "address": "1000",
                                "xref_count": 0,
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            symbols.write_text(
                json.dumps(
                    {
                        "symbols": [
                            {
                                "name": (
                                    "_symbolic______________________pIetMHnTgrzo__18AppIntentsServices"
                                    "0aB8ProtocolO21FetchOptionsForActionO7RequestV_AA06RemoteaB5ActorC_"
                                    "AE8ResponseO_s5ErrorP"
                                ),
                                "address": "2000",
                                "symbol_type": "Label",
                                "xref_count": 0,
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            result = build_xpc_surface(
                "swift_project",
                "SwiftProgram",
                objc_metadata_path=objc,
                strings_path=strings,
                symbols_path=symbols,
                output=root / "xpc_surface.json",
                markdown_output=root / "xpc_surface.md",
            )

            self.assertEqual(result["distributed_method_count"], 2)
            report = json.loads((root / "xpc_surface.json").read_text(encoding="utf-8"))
            kinds = {item["descriptor_kind"] for item in report["distributed_methods"]}
            self.assertIn("distributed_thunk_string", kinds)
            self.assertIn("symbolic_request_signature", kinds)
            self.assertTrue(
                any(item["method"] == "fetchOptionsForAction" for item in report["distributed_methods"])
            )
            self.assertTrue(
                any(item["method"] == "FetchOptionsForAction.Request" for item in report["distributed_methods"])
            )
            markdown_text = (root / "xpc_surface.md").read_text(encoding="utf-8")
            self.assertIn("fetchOptionsForAction", markdown_text)
            self.assertIn("FetchOptionsForAction.Request", markdown_text)

    def test_xpc_surface_reports_malformed_json_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            malformed = root / "strings.json"
            malformed.write_text("{not-json", encoding="utf-8")

            with self.assertRaisesRegex(RuntimeError, r"failed to parse JSON at .*strings\.json"):
                build_xpc_surface(
                    "partial_project",
                    "PartialProgram",
                    objc_metadata_path=root / "missing_objc.json",
                    strings_path=malformed,
                    symbols_path=root / "missing_symbols.json",
                    output=root / "xpc_surface.json",
                    markdown_output=root / "xpc_surface.md",
                )


if __name__ == "__main__":
    unittest.main()
