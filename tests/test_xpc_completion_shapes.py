import json
import tempfile
import unittest
from pathlib import Path

from cerberus_re_skill.modules.xpc_completion_shapes import (
    XPC_COMPLETION_SHAPES_SCHEMA,
    build_xpc_completion_shapes,
)
from cerberus_re_skill.modules.xpc_method_inventory import _selector_signature_hint


class XpcCompletionShapesTests(unittest.TestCase):
    def test_builds_completion_shapes_from_probe_and_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inventory = root / "xpc-method-inventory.json"
            inventory.write_text(
                json.dumps(
                    {
                        "schema": "ghidra-re.xpc-method-inventory.v1",
                        "interfaces": [
                            {
                                "target": "proj:Program",
                                "project": "proj",
                                "program": "Program",
                                "interface": "ExampleProtocol",
                                "method_count": 2,
                                "method_candidates": [
                                    _method(
                                        "getExampleItemsWithCompletion:",
                                        reply=[
                                            {"argument_index": 0, "classes": ["NSArray", "ExampleItem"]},
                                            {"argument_index": 1, "classes": ["NSError"]},
                                        ],
                                    ),
                                    _method(
                                        "getNumberOfExampleItemsWithCompletion:",
                                        reply=[{"argument_index": 1, "classes": ["NSError"]}],
                                    ),
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            probe = root / "completion-probe.json"
            probe.write_text(
                json.dumps(
                    {
                        "schema": "ghidra-re.test-completion-probe.v1",
                        "selectors": [
                            {
                                "selector": "getExampleItemsWithCompletion:",
                                "protocol_types": "v24@0:8@?16",
                            },
                            {
                                "selector": "getNumberOfExampleItemsWithCompletion:",
                                "protocol_types": "v24@0:8@?16",
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )
            output = root / "completion-shapes.json"
            markdown = root / "completion-shapes.md"

            result = build_xpc_completion_shapes(
                ["proj:Program"],
                xpc_method_inventory_path=inventory,
                completion_probe_paths=[probe],
                output=output,
                markdown_output=markdown,
            )
            payload = json.loads(output.read_text(encoding="utf-8"))
            markdown_text = markdown.read_text(encoding="utf-8")

        self.assertTrue(result["ok"])
        self.assertEqual(payload["schema"], XPC_COMPLETION_SHAPES_SCHEMA)
        self.assertEqual(payload["summary"]["completion_method_count"], 2)
        self.assertEqual(payload["summary"]["primitive_reply_count"], 1)
        methods = {item["selector"]: item for item in payload["interfaces"][0]["methods"]}
        self.assertEqual(
            methods["getExampleItemsWithCompletion:"]["completion_shape"]["completion"],
            "reply[0] NSArray *; reply[1] NSError *",
        )
        count_args = methods["getNumberOfExampleItemsWithCompletion:"]["completion_shape"]["reply_arguments"]
        self.assertEqual(count_args[0]["type"], "NSUInteger")
        self.assertEqual(count_args[0]["kind"], "primitive")
        self.assertIn("getNumberOfExampleItemsWithCompletion:", markdown_text)

    def test_static_block_descriptors_raise_confidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inventory = root / "xpc-method-inventory.json"
            inventory.write_text(
                json.dumps(
                    {
                        "interfaces": [
                            {
                                "target": "proj:Program",
                                "project": "proj",
                                "program": "Program",
                                "interface": "ExampleProtocol",
                                "method_count": 1,
                                "method_candidates": [
                                    _method(
                                        "getExampleItemsWithCompletion:",
                                        reply=[
                                            {"argument_index": 0, "classes": ["NSArray", "ExampleItem"]},
                                            {"argument_index": 1, "classes": ["NSError"]},
                                        ],
                                    )
                                ],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            dossier = root / "dossier"
            dossier.mkdir()
            (dossier / "context.json").write_text(
                json.dumps({"function": {"name": "___73-[ExampleClient getExampleItemsWithCompletion:]_block_invoke"}}),
                encoding="utf-8",
            )
            (dossier / "decompile.c").write_text(
                "&___block_descriptor_48_e8_32bs40bs_e29_v24__0__NSArray_8__NSError_16l\n",
                encoding="utf-8",
            )
            output = root / "completion-shapes.json"
            markdown = root / "completion-shapes.md"

            build_xpc_completion_shapes(
                ["proj:Program"],
                xpc_method_inventory_path=inventory,
                function_dossier_dirs=[dossier],
                output=output,
                markdown_output=markdown,
            )
            payload = json.loads(output.read_text(encoding="utf-8"))

        method = payload["interfaces"][0]["methods"][0]
        self.assertEqual(method["completion_shape"]["confidence"], "high")
        self.assertIn("ghidra_block_descriptors", method["completion_shape"]["source"])
        self.assertEqual(payload["summary"]["static_block_descriptor_count"], 1)

    def test_direct_completion_invocation_and_runtime_probe_fill_residual_shape(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inventory = root / "xpc-method-inventory.json"
            selector = "getFeatureEnablementForIdentifier:signature:completion:"
            inventory.write_text(
                json.dumps(
                    {
                        "interfaces": [
                            {
                                "target": "proj:Program",
                                "project": "proj",
                                "program": "Program",
                                "interface": "ExampleProtocol",
                                "method_count": 1,
                                "method_candidates": [_method(selector, reply=[])],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            dossier = root / "dossier"
            dossier.mkdir()
            (dossier / "context.json").write_text(
                json.dumps({"function": {"name": f"-[ExampleClient(FeatureState)_{selector}]"}}),
                encoding="utf-8",
            )
            (dossier / "decompile.c").write_text(
                "(**(code **)(in_x4 + 0x10))(in_x4,1,0);\n",
                encoding="utf-8",
            )
            probe = root / "spotlight-probe.json"
            probe.write_text(
                json.dumps(
                    {
                        "schema": "ghidra-re.example-completion-probe.v1",
                        "invocations": [
                            {
                                "selector": selector,
                                "completion_called": True,
                                "completion_enabled": True,
                                "completion_error": {"is_nil": True},
                                "remote_methods_invoked": False,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            output = root / "completion-shapes.json"
            markdown = root / "completion-shapes.md"

            build_xpc_completion_shapes(
                ["proj:Program"],
                xpc_method_inventory_path=inventory,
                completion_probe_paths=[probe],
                function_dossier_dirs=[dossier],
                output=output,
                markdown_output=markdown,
            )
            payload = json.loads(output.read_text(encoding="utf-8"))
            markdown_text = markdown.read_text(encoding="utf-8")

        method = payload["interfaces"][0]["methods"][0]
        shape = method["completion_shape"]
        self.assertEqual(shape["completion"], "reply[0] BOOL; reply[1] NSError *")
        self.assertEqual(shape["reply_arguments"][0]["role"], "enabled")
        self.assertEqual(shape["reply_arguments"][1]["role"], "error")
        self.assertNotIn("no_reply_arguments_recovered", shape["residual_gaps"])
        self.assertEqual(shape["confidence"], "high")
        self.assertIn("ghidra_direct_completion_invoke", shape["source"])
        self.assertIn("runtime_completion_observation", shape["source"])
        self.assertEqual(payload["summary"]["direct_completion_invocation_count"], 1)
        self.assertEqual(payload["summary"]["runtime_completion_observation_count"], 1)
        self.assertIn("Direct completion invoke", markdown_text)


def _method(selector: str, *, reply: list[dict]) -> dict:
    hint = _selector_signature_hint(selector)
    method = {
        "selector": selector,
        "score": 30,
        "signature_hint": hint,
        "safety_classification": {"category": "safe_read"},
        "configuration_backing": {
            "allowed_class_evidence_count": len(reply),
            "reply_allowed_classes": reply,
        },
    }
    return method


if __name__ == "__main__":
    unittest.main()
