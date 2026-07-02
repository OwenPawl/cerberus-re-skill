import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cerberus_re_skill.modules.xpc_interface_factory import (
    XPC_INTERFACE_FACTORY_SCHEMA,
    build_xpc_interface_factory_catalog,
)


class XpcInterfaceFactoryTests(unittest.TestCase):
    def test_build_factory_catalog_from_inventory_and_dossier(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            exports = root / "exports"
            export_dir = exports / "proj" / "Program"
            export_dir.mkdir(parents=True)
            (export_dir / "function_inventory.json").write_text(
                json.dumps(
                    {
                        "functions": [
                            {
                                "name": "_ExampleUIPresenterXPCInterface",
                                "entry": "0x1000",
                                "signature": "undefined _ExampleUIPresenterXPCInterface()",
                                "is_external": False,
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            (export_dir / "symbols.json").write_text(
                json.dumps({"symbols": [{"name": "_ExampleUIPresenterXPCInterface", "address": "0x1000"}]}),
                encoding="utf-8",
            )
            (export_dir / "authstub_map.json").write_text(
                json.dumps({"stubs": {"slot_1": {"name": "ExampleAutomationDaemonXPCInterface", "source": "auth_stubs"}}}),
                encoding="utf-8",
            )
            inventory = root / "xpc-method-inventory.json"
            inventory.write_text(
                json.dumps(
                    {
                        "interfaces": [
                            {
                                "target": "proj:Program",
                                "interface": "_ExampleUIPresenterXPCInterface",
                                "method_count": 3,
                                "graph_context": {"services": ["com.apple.example.view-service"]},
                            },
                            {
                                "target": "proj:Program",
                                "interface": "_ExampleAutomationDaemonXPCInterface",
                                "method_count": 4,
                                "graph_context": {"services": ["com.apple.automationd.xpc"]},
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )
            dossier_dir = root / "dossier"
            dossier_dir.mkdir()
            (dossier_dir / "decompile.c").write_text(
                "_objc_msgSend_interfaceWithProtocol_(__OBJC_PROTOCOL_REFERENCE___ExampleUIPresenterInterface);\n",
                encoding="utf-8",
            )
            config = root / "nsxpc-interface-config.json"
            config.write_text(
                json.dumps(
                    {
                        "schema": "ghidra-re.nsxpc-interface-config.v1",
                        "project_name": "proj",
                        "program_name": "Program",
                        "summary": {"allowed_class_call_count": 1},
                        "functions": [
                            {
                                "function": "_ExampleUIPresenterXPCInterface",
                                "entry": "0x1000",
                                "allowed_class_call_count": 1,
                                "interface_with_protocol_call_count": 1,
                                "protocol_references": ["ExampleUIPresenterInterface"],
                                "selection_reasons": ["explicit:function"],
                                "allowed_class_calls": [
                                    {
                                        "selector": "setClasses:forSelector:argumentIndex:ofReply:",
                                        "line_number": 8,
                                        "line": "_objc_msgSend_setClasses_forSelector_argumentIndex_ofReply_();",
                                    }
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            output = root / "factory.json"
            markdown = root / "factory.md"

            with patch("cerberus_re_skill.modules.xpc_interface_factory.cfg.exports_dir", exports):
                result = build_xpc_interface_factory_catalog(
                    ["proj:Program"],
                    xpc_method_inventory_path=inventory,
                    interface_config_paths=[str(config)],
                    function_dossiers=[f"_ExampleUIPresenterXPCInterface={dossier_dir}"],
                    output=output,
                    markdown_output=markdown,
                )
            payload = json.loads(output.read_text(encoding="utf-8"))
            markdown_text = markdown.read_text(encoding="utf-8")

        self.assertTrue(result["ok"])
        self.assertEqual(payload["schema"], XPC_INTERFACE_FACTORY_SCHEMA)
        self.assertEqual(payload["summary"]["factory_count"], 2)
        self.assertEqual(payload["summary"]["local_factory_count"], 1)
        self.assertEqual(payload["summary"]["unresolved_authstub_count"], 1)
        self.assertEqual(payload["factories"][0]["protocol_references"], ["ExampleUIPresenterInterface"])
        self.assertEqual(payload["factories"][0]["allowed_class_call_count"], 1)
        self.assertEqual(payload["factories"][0]["allowed_class_selectors"], ["setClasses:forSelector:argumentIndex:ofReply:"])
        self.assertIn("com.apple.example.view-service", markdown_text)
        self.assertIn("Allowed-class selectors", markdown_text)

    def test_explicit_interface_takes_priority_over_inventory_limit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            exports = root / "exports"
            export_dir = exports / "proj" / "Program"
            export_dir.mkdir(parents=True)
            (export_dir / "function_inventory.json").write_text(
                json.dumps(
                    {
                        "functions": [
                            {
                                "name": "_ExplicitInterface",
                                "entry": "0x2000",
                                "signature": "undefined _ExplicitInterface()",
                                "is_external": False,
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            (export_dir / "symbols.json").write_text(json.dumps({"symbols": []}), encoding="utf-8")
            (export_dir / "authstub_map.json").write_text(json.dumps({"stubs": {}}), encoding="utf-8")
            inventory = root / "xpc-method-inventory.json"
            inventory.write_text(
                json.dumps(
                    {
                        "interfaces": [
                            {
                                "target": "proj:Program",
                                "interface": "_WrongRankedInterface",
                                "method_count": 3,
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            output = root / "factory.json"
            markdown = root / "factory.md"

            with patch("cerberus_re_skill.modules.xpc_interface_factory.cfg.exports_dir", exports):
                build_xpc_interface_factory_catalog(
                    ["proj:Program"],
                    xpc_method_inventory_path=inventory,
                    interfaces=["_ExplicitInterface"],
                    output=output,
                    markdown_output=markdown,
                    limit=1,
                )
            payload = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(payload["summary"]["factory_count"], 1)
        self.assertEqual(payload["factories"][0]["interface"], "_ExplicitInterface")
        self.assertEqual(payload["factories"][0]["context"]["source"], "explicit")


if __name__ == "__main__":
    unittest.main()
