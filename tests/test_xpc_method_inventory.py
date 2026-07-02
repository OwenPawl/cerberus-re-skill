import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cerberus_re_skill.modules.xpc_method_inventory import XPC_METHOD_INVENTORY_SCHEMA, build_xpc_method_inventory


class XpcMethodInventoryTests(unittest.TestCase):
    def test_build_xpc_method_inventory_from_dossier_and_exports(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            exports = root / "exports"
            export_dir = exports / "proj" / "Program"
            export_dir.mkdir(parents=True)
            (export_dir / "objc_metadata.json").write_text(
                json.dumps(
                    {
                        "selector_strings": [
                            "runTaskWithDescriptor:request:completion:",
                            "cancelTaskWithIdentifier:",
                            "unrelatedSelector",
                        ]
                    }
                ),
                encoding="utf-8",
            )
            (export_dir / "symbols.json").write_text(
                json.dumps(
                    {
                        "symbols": [
                            {
                                "name": "__OBJC_$_PROTOCOL_INSTANCE_METHODS__ExampleTaskControllerHostXPCInterface",
                                "address": "0x1000",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            dossier = root / "dossier.json"
            dossier.write_text(
                json.dumps(
                    {
                        "candidates": [
                            {
                                "target": "proj:Program",
                                "interface": "_ExampleTaskControllerHostXPCInterface",
                                "score": 84,
                                "services": ["com.example.task.test"],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            config = root / "nsxpc-config.json"
            config.write_text(
                json.dumps(
                    {
                        "schema": "ghidra-re.nsxpc-interface-config.v1",
                        "project_name": "proj",
                        "program_name": "Program",
                        "functions": [
                            {
                                "function": "_ExampleTaskControllerHostXPCInterface",
                                "entry": "0x1000",
                                "selection_reasons": ["explicit:function"],
                                "protocol_references": ["_ExampleTaskControllerHostXPCInterface"],
                                "allowed_class_call_count": 0,
                                "interface_with_protocol_call_count": 1,
                                "allowed_class_calls": [],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            allowed = root / "allowed-classes.json"
            allowed.write_text(
                json.dumps(
                    {
                        "schema": "ghidra-re.test.allowed-classes.v1",
                        "allowed_class_entries": [
                            {
                                "selector": "runTaskWithDescriptor:request:completion:",
                                "argument_index": 0,
                                "of_reply": False,
                                "classes": ["ExampleTaskDescriptor"],
                            },
                            {
                                "selector": "runTaskWithDescriptor:request:completion:",
                                "argument_index": 1,
                                "of_reply": True,
                                "classes": ["NSError"],
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )
            output = root / "inventory.json"
            markdown = root / "inventory.md"
            harness_dir = root / "harnesses"

            with patch("cerberus_re_skill.modules.xpc_method_inventory.cfg.exports_dir", exports):
                result = build_xpc_method_inventory(
                    ["proj:Program"],
                    xpc_dossier_path=dossier,
                    interface_config_paths=[str(config)],
                    allowed_class_paths=[str(allowed)],
                    output=output,
                    markdown_output=markdown,
                    harness_output_dir=harness_dir,
                )
            payload = json.loads(output.read_text(encoding="utf-8"))
            harnesses = list(harness_dir.glob("*.m"))
            harness_text = harnesses[0].read_text(encoding="utf-8")

        self.assertTrue(result["ok"])
        self.assertEqual(payload["schema"], XPC_METHOD_INVENTORY_SCHEMA)
        self.assertEqual(payload["summary"]["interface_count"], 1)
        item = payload["interfaces"][0]
        self.assertEqual(item["extraction_status"], "objc_protocol_symbols")
        self.assertTrue(item["method_candidates"])
        self.assertEqual(item["configuration_context"]["pattern_function_count"], 1)
        self.assertEqual(item["typed_method_candidate_count"], 2)
        self.assertEqual(item["reply_block_candidate_count"], 1)
        run_method = next(
            method
            for method in item["method_candidates"]
            if method["selector"] == "runTaskWithDescriptor:request:completion:"
        )
        self.assertEqual(run_method["signature_hint"]["argument_count"], 3)
        self.assertEqual(run_method["input_shape_hints"][-1]["role"], "completion_block")
        self.assertEqual(run_method["safety_classification"]["category"], "state_changing")
        self.assertEqual(run_method["remote_invocation_default"], "blocked_state_or_ui_effects")
        self.assertEqual(run_method["configuration_backing"]["allowed_class_evidence_count"], 2)
        self.assertEqual(
            run_method["configuration_backing"]["argument_allowed_classes"][0]["classes"],
            ["ExampleTaskDescriptor"],
        )
        self.assertEqual(run_method["configuration_backing"]["reply_allowed_classes"][0]["classes"], ["NSError"])
        self.assertEqual(item["allowed_class_backed_method_count"], 1)
        self.assertEqual(payload["summary"]["configured_interface_count"], 1)
        self.assertEqual(payload["summary"]["state_changing_method_count"], 2)
        self.assertTrue(harnesses)
        self.assertIn("args=3", harness_text)
        self.assertIn("safety=state_changing", harness_text)
        self.assertIn("completion=completion_block[block]", harness_text)
        self.assertIn("no-call: do not invoke this selector", harness_text)
        self.assertIn("Safety default", harness_text)
        self.assertNotIn("Remote proxy placeholder: %@", harness_text)

    def test_explicit_interface_takes_priority_over_dossier_limit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            exports = root / "exports"
            export_dir = exports / "proj" / "Program"
            export_dir.mkdir(parents=True)
            (export_dir / "objc_metadata.json").write_text(
                json.dumps(
                    {
                        "selector_strings": [
                            "dialogAlertPresenterDidDeactivateAlert:",
                            "getRecordsWithAccessToken:completion:",
                        ]
                    }
                ),
                encoding="utf-8",
            )
            (export_dir / "symbols.json").write_text(json.dumps({"symbols": []}), encoding="utf-8")
            dossier = root / "dossier.json"
            dossier.write_text(
                json.dumps(
                    {
                        "candidates": [
                            {
                                "target": "proj:Program",
                                "interface": "_ExampleUIPresenterHostXPCInterface",
                                "score": 99,
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            output = root / "inventory.json"
            markdown = root / "inventory.md"

            with patch("cerberus_re_skill.modules.xpc_method_inventory.cfg.exports_dir", exports):
                build_xpc_method_inventory(
                    ["proj:Program"],
                    xpc_dossier_path=dossier,
                    interfaces=["_ExampleActionManagerXPCInterface"],
                    output=output,
                    markdown_output=markdown,
                    limit=1,
                )
            payload = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(payload["summary"]["interface_count"], 1)
        self.assertEqual(payload["interfaces"][0]["interface"], "_ExampleActionManagerXPCInterface")
        method = payload["interfaces"][0]["method_candidates"][0]
        self.assertEqual(method["selector"], "getRecordsWithAccessToken:completion:")
        self.assertEqual(method["input_shape_hints"][0]["role"], "access_context")
        self.assertEqual(method["input_shape_hints"][0]["type_hints"], ["NSObject", "NSString"])

    def test_build_xpc_method_inventory_decodes_macho_protocol_methods(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            exports = root / "exports"
            export_dir = exports / "proj" / "Program"
            export_dir.mkdir(parents=True)
            macho = root / "fixture.macho"
            _write_minimal_protocol_method_macho(macho)
            (export_dir / "objc_metadata.json").write_text(json.dumps({"selector_strings": []}), encoding="utf-8")
            (export_dir / "symbols.json").write_text(
                json.dumps(
                    {
                        "symbols": [
                            {
                                "name": "__OBJC_$_PROTOCOL_INSTANCE_METHODS_TestRunnerInterface",
                                "address": "1000",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            output = root / "inventory.json"
            markdown = root / "inventory.md"

            with patch("cerberus_re_skill.modules.xpc_method_inventory.cfg.exports_dir", exports):
                result = build_xpc_method_inventory(
                    ["proj:Program"],
                    interfaces=["TestRunnerInterface"],
                    macho_paths=[str(macho)],
                    output=output,
                    markdown_output=markdown,
                )
            payload = json.loads(output.read_text(encoding="utf-8"))
            item = payload["interfaces"][0]
            method = item["method_candidates"][0]
            markdown_text = markdown.read_text(encoding="utf-8")

        self.assertTrue(result["ok"])
        self.assertEqual(payload["summary"]["macho_protocol_method_count"], 1)
        self.assertEqual(item["extraction_status"], "objc_protocol_methods")
        self.assertEqual(item["macho_protocol_method_count"], 1)
        self.assertEqual(method["selector"], "requestTransportForRunnerWithReply:")
        self.assertEqual(method["type_encoding"], "v24@0:8@?16")
        self.assertEqual(method["source"], "macho_protocol_method_list")
        self.assertEqual(method["signature_hint"]["objc_type_encoding"], "v24@0:8@?16")
        self.assertIn("Mach-O protocol methods: 1", markdown_text)


def _write_minimal_protocol_method_macho(path: Path) -> None:
    data = bytearray(0x700)
    nsects = 4
    cmdsize = 72 + nsects * 80
    struct.pack_into("<IiiIIIII", data, 0, 0xFEED_FACF, 0x0100000C, 0, 2, 1, cmdsize, 0, 0)
    struct.pack_into(
        "<II16sQQQQiiII",
        data,
        32,
        0x19,
        cmdsize,
        b"__TEXT\0".ljust(16, b"\0"),
        0x1000,
        0x4000,
        0,
        len(data),
        7,
        5,
        nsects,
        0,
    )
    sections = [
        ("__objc_methlist", 0x1000, 0x20, 0x300),
        ("__objc_selrefs", 0x2000, 0x08, 0x400),
        ("__objc_methname", 0x3000, 0x80, 0x500),
        ("__objc_methtype", 0x4000, 0x40, 0x600),
    ]
    cursor = 32 + 72
    for name, addr, size, offset in sections:
        struct.pack_into(
            "<16s16sQQIIIIIIII",
            data,
            cursor,
            name.encode("ascii").ljust(16, b"\0"),
            b"__TEXT\0".ljust(16, b"\0"),
            addr,
            size,
            offset,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        )
        cursor += 80
    selector = b"requestTransportForRunnerWithReply:\0"
    type_encoding = b"v24@0:8@?16\0"
    data[0x500 : 0x500 + len(selector)] = selector
    data[0x600 : 0x600 + len(type_encoding)] = type_encoding
    struct.pack_into("<Q", data, 0x400, 0x3000)
    method_list_address = 0x1000
    entry_address = method_list_address + 8
    struct.pack_into("<II", data, 0x300, 0x8000000C, 1)
    struct.pack_into("<iii", data, 0x308, 0x2000 - entry_address, 0x4000 - (entry_address + 4), 0)
    path.write_bytes(bytes(data))


if __name__ == "__main__":
    unittest.main()
