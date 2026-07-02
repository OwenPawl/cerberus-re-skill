import json
import tempfile
import unittest
from pathlib import Path

from cerberus_re_skill.modules.xpc_method_inventory import _selector_signature_hint
from cerberus_re_skill.modules.xpc_safe_read_dossier import (
    XPC_SAFE_READ_DOSSIER_SCHEMA,
    build_xpc_safe_read_dossier,
)


class XpcSafeReadDossierTests(unittest.TestCase):
    def test_builds_strict_safe_read_dossier_from_policy_and_no_call_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stderr = root / "connection.stderr.log"
            stderr.write_text(
                "No ObjC protocol named _ExampleManagerConfigureXPCInterface was registered\n"
                "Remote proxy placeholder acquired without description\n",
                encoding="utf-8",
            )
            inventory = root / "xpc-method-inventory.json"
            inventory.write_text(
                json.dumps(
                    {
                        "schema": "ghidra-re.xpc-method-inventory.v1",
                        "interfaces": [
                            {
                                "target": "ExampleClient_arm64e:ExampleClient",
                                "project": "ExampleClient_arm64e",
                                "program": "ExampleClient",
                                "interface": "_ExampleManagerConfigureXPCInterface",
                                "method_count": 3,
                                "allowed_class_backed_method_count": 0,
                                "graph_context": {"services": ["com.example.client.xpc"]},
                                "configuration_context": {"allowed_class_call_count": 0},
                                "method_candidates": [
                                    _method("getExampleClientWithAccessSpecifier:completion:"),
                                    _method("getNumberOfExampleClientWithAccessSpecifier:completion:"),
                                    _method("requestDataMigrationWithCompletion:"),
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            policy = root / "access-policy.json"
            policy.write_text(
                json.dumps(
                    {
                        "safe_read_requirements": {
                            "list_selector": "-[ExampleManager getExampleClientWithAccessSpecifier:completion:]",
                            "count_selector": "-[ExampleManager getNumberOfExampleClientWithAccessSpecifier:completion:]",
                            "access_policy": "associatedAppBundleIdentifier filters visible workflows",
                            "direct_xpc_status": "blocked_until_connection_entitlement_and_allowed-class behavior are recovered",
                            "completion_shapes": [
                                {
                                    "selector": "getExampleClientWithAccessSpecifier:completion:",
                                    "completion": "NSArray *voiceExampleApp, NSError *error",
                                },
                                {
                                    "selector": "getNumberOfExampleClientWithAccessSpecifier:completion:",
                                    "completion": "NSUInteger count, NSError *error",
                                },
                            ],
                        }
                    }
                ),
                encoding="utf-8",
            )
            connection = root / "connection.json"
            connection.write_text(
                json.dumps(
                    {
                        "schema": "ghidra-re.xpc-connection-evidence.v1",
                        "connections": [
                            {
                                "target": "ExampleClient_arm64e:ExampleClient",
                                "interface": "_ExampleManagerConfigureXPCInterface",
                                "service": "com.example.client.xpc",
                                "harness_source": "harness.m",
                                "compile": {"ok": True},
                                "run": {
                                    "ok": True,
                                    "status": "connection_object_created_no_call",
                                    "blocker_classification": "none_observed",
                                    "observations": ["connection object created and resumed"],
                                    "stderr": str(stderr),
                                },
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            output = root / "safe-read.json"
            markdown = root / "safe-read.md"

            result = build_xpc_safe_read_dossier(
                ["ExampleClient_arm64e:ExampleClient"],
                xpc_method_inventory_path=inventory,
                access_policy_path=policy,
                connection_evidence_path=connection,
                interfaces=["_ExampleManagerConfigureXPCInterface=com.example.client.xpc"],
                output=output,
                markdown_output=markdown,
            )
            payload = json.loads(output.read_text(encoding="utf-8"))
            markdown_text = markdown.read_text(encoding="utf-8")

        self.assertTrue(result["ok"])
        self.assertEqual(payload["schema"], XPC_SAFE_READ_DOSSIER_SCHEMA)
        self.assertEqual(payload["summary"]["safe_read_candidate_count"], 2)
        self.assertEqual(payload["summary"]["blocked_read_candidate_count"], 1)
        interface = payload["interfaces"][0]
        selectors = [item["selector"] for item in interface["safe_read_candidates"]]
        self.assertIn("getExampleClientWithAccessSpecifier:completion:", selectors)
        self.assertIn("getNumberOfExampleClientWithAccessSpecifier:completion:", selectors)
        self.assertEqual(interface["connection_evidence"]["remote_protocol_registered"], False)
        blockers = interface["safe_read_candidates"][0]["blockers"]
        self.assertIn("allowed_class_behavior_unrecovered", blockers)
        self.assertIn("access_specifier_policy_required", blockers)
        self.assertIn("remote_protocol_not_registered_in_harness_process", blockers)
        self.assertIn("requestDataMigrationWithCompletion:", interface["blocked_read_candidates"][0]["selector"])
        self.assertIn("XPC Safe-Read Dossier", markdown_text)

    def test_selector_hint_classifies_access_specifier(self) -> None:
        hint = _selector_signature_hint("getExampleClientWithAccessSpecifier:completion:")
        roles = {item["label"]: item for item in hint["argument_hints"]}

        self.assertEqual(roles["getExampleClientWithAccessSpecifier"]["role"], "access_context")
        self.assertEqual(roles["getExampleClientWithAccessSpecifier"]["type_hints"], ["NSObject", "NSString"])
        self.assertEqual(roles["completion"]["role"], "completion_block")

    def test_numberof_completion_label_remains_completion_block(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            method = _method("getNumberOfExampleClientWithCompletion:")
            method["configuration_backing"] = {
                "allowed_class_evidence_count": 1,
                "reply_allowed_classes": [{"argument_index": 1, "classes": ["NSError"], "artifact": "allowed.json"}],
            }
            inventory = root / "xpc-method-inventory.json"
            inventory.write_text(
                json.dumps(
                    {
                        "interfaces": [
                            {
                                "target": "current_exampleclient:ExampleClient",
                                "project": "current_exampleclient",
                                "program": "ExampleClient",
                                "interface": "ExampleManagerXPCInterface",
                                "method_count": 1,
                                "allowed_class_backed_method_count": 1,
                                "method_candidates": [method],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            output = root / "safe-read.json"
            markdown = root / "safe-read.md"

            build_xpc_safe_read_dossier(
                ["current_exampleclient:ExampleClient"],
                xpc_method_inventory_path=inventory,
                interfaces=["ExampleManagerXPCInterface=com.example.client.xpc"],
                output=output,
                markdown_output=markdown,
            )
            payload = json.loads(output.read_text(encoding="utf-8"))

        roles = payload["interfaces"][0]["safe_read_candidates"][0]["argument_roles"]
        self.assertEqual(roles[0]["role"], "completion_block")

    def test_allowed_class_evidence_clears_method_specific_blockers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inventory = root / "xpc-method-inventory.json"
            method = _method("getExampleClientWithCompletion:")
            method["configuration_backing"] = {
                "allowed_class_evidence_count": 2,
                "argument_allowed_classes": [],
                "reply_allowed_classes": [
                    {"argument_index": 0, "classes": ["NSArray", "ExampleItem"], "artifact": "allowed.json"},
                    {"argument_index": 1, "classes": ["NSError"], "artifact": "allowed.json"},
                ],
            }
            inventory.write_text(
                json.dumps(
                    {
                        "schema": "ghidra-re.xpc-method-inventory.v1",
                        "interfaces": [
                            {
                                "target": "current_exampleclient:ExampleClient",
                                "project": "current_exampleclient",
                                "program": "ExampleClient",
                                "interface": "ExampleManagerXPCInterface",
                                "method_count": 1,
                                "allowed_class_backed_method_count": 1,
                                "graph_context": {"services": ["com.example.client.xpc"]},
                                "method_candidates": [method],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            output = root / "safe-read.json"
            markdown = root / "safe-read.md"

            build_xpc_safe_read_dossier(
                ["current_exampleclient:ExampleClient"],
                xpc_method_inventory_path=inventory,
                interfaces=["ExampleManagerXPCInterface=com.example.client.xpc"],
                output=output,
                markdown_output=markdown,
            )
            payload = json.loads(output.read_text(encoding="utf-8"))

        candidate = payload["interfaces"][0]["safe_read_candidates"][0]
        self.assertEqual(candidate["selector"], "getExampleClientWithCompletion:")
        self.assertNotIn("allowed_class_behavior_unrecovered", candidate["blockers"])
        self.assertNotIn("completion_shape_unverified", candidate["blockers"])
        self.assertEqual(candidate["completion_contract"]["source"], "nsxpc_allowed_classes")
        self.assertEqual(candidate["allowed_class_evidence"]["evidence_count"], 2)

    def test_registered_protocol_connection_clears_remote_protocol_blocker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stderr = root / "connection.stderr.log"
            stderr.write_text(
                "Protocol before framework loads: missing\n"
                "Loaded framework /System/Library/PrivateFrameworks/ExampleClient.framework/ExampleClient\n"
                "Protocol after framework loads: registered\n"
                "Configured remoteObjectInterface with protocol ExampleManagerXPCInterface\n"
                "Remote proxy placeholder acquired without description\n",
                encoding="utf-8",
            )
            method = _method("getExampleClientWithCompletion:")
            method["configuration_backing"] = {
                "allowed_class_evidence_count": 2,
                "reply_allowed_classes": [
                    {"argument_index": 0, "classes": ["NSArray", "ExampleItem"], "artifact": "allowed.json"},
                    {"argument_index": 1, "classes": ["NSError"], "artifact": "allowed.json"},
                ],
            }
            inventory = root / "xpc-method-inventory.json"
            inventory.write_text(
                json.dumps(
                    {
                        "schema": "ghidra-re.xpc-method-inventory.v1",
                        "interfaces": [
                            {
                                "target": "current_exampleclient:ExampleClient",
                                "project": "current_exampleclient",
                                "program": "ExampleClient",
                                "interface": "ExampleManagerXPCInterface",
                                "method_count": 1,
                                "allowed_class_backed_method_count": 1,
                                "graph_context": {"services": ["com.example.client.xpc"]},
                                "method_candidates": [method],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            connection = root / "connection.json"
            connection.write_text(
                json.dumps(
                    {
                        "schema": "ghidra-re.xpc-connection-evidence.v1",
                        "connections": [
                            {
                                "target": "current_exampleclient:ExampleClient",
                                "interface": "ExampleManagerXPCInterface",
                                "service": "com.example.client.xpc",
                                "framework_loads": [
                                    "/System/Library/PrivateFrameworks/ExampleClient.framework/ExampleClient"
                                ],
                                "compile": {"ok": True},
                                "run": {
                                    "ok": True,
                                    "status": "connection_object_created_no_call",
                                    "blocker_classification": "none_observed",
                                    "remote_protocol_registered": True,
                                    "stderr": str(stderr),
                                },
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            output = root / "safe-read.json"
            markdown = root / "safe-read.md"

            build_xpc_safe_read_dossier(
                ["current_exampleclient:ExampleClient"],
                xpc_method_inventory_path=inventory,
                connection_evidence_path=connection,
                interfaces=["ExampleManagerXPCInterface=com.example.client.xpc"],
                output=output,
                markdown_output=markdown,
            )
            payload = json.loads(output.read_text(encoding="utf-8"))

        interface = payload["interfaces"][0]
        candidate = interface["safe_read_candidates"][0]
        self.assertIs(interface["connection_evidence"]["remote_protocol_registered"], True)
        self.assertNotIn("remote_protocol_not_registered_in_harness_process", candidate["blockers"])
        self.assertEqual(candidate["remote_invocation_default"], "candidate_requires_final_runtime_gate")

    def test_completion_shapes_enrich_contracts_and_preserve_gaps(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            count_method = _method("getNumberOfExampleClientWithCompletion:")
            count_method["configuration_backing"] = {
                "allowed_class_evidence_count": 1,
                "reply_allowed_classes": [{"argument_index": 1, "classes": ["NSError"], "artifact": "allowed.json"}],
            }
            spotlight_method = _method("getSpotlightAutoExampleAppEnablementForBundleIdentifier:phraseSignature:completion:")
            spotlight_method["configuration_backing"] = {"allowed_class_evidence_count": 1, "reply_allowed_classes": []}
            inventory = root / "xpc-method-inventory.json"
            inventory.write_text(
                json.dumps(
                    {
                        "schema": "ghidra-re.xpc-method-inventory.v1",
                        "interfaces": [
                            {
                                "target": "current_exampleclient:ExampleClient",
                                "project": "current_exampleclient",
                                "program": "ExampleClient",
                                "interface": "ExampleManagerXPCInterface",
                                "method_count": 2,
                                "allowed_class_backed_method_count": 2,
                                "graph_context": {"services": ["com.example.client.xpc"]},
                                "method_candidates": [count_method, spotlight_method],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            completion_shapes = root / "completion-shapes.json"
            completion_shapes.write_text(
                json.dumps(
                    {
                        "schema": "ghidra-re.xpc-completion-shapes.v1",
                        "ok": True,
                        "summary": {"completion_method_count": 2, "reply_shape_count": 1, "primitive_reply_count": 1},
                        "interfaces": [
                            {
                                "target": "current_exampleclient:ExampleClient",
                                "interface": "ExampleManagerXPCInterface",
                                "methods": [
                                    {
                                        "selector": "getNumberOfExampleClientWithCompletion:",
                                        "protocol_types": "v24@0:8@?16",
                                        "static_block_evidence": {"block_descriptors": []},
                                        "completion_shape": {
                                            "source": "nsxpc_allowed_classes+protocol_method_types",
                                            "confidence": "medium",
                                            "completion": "reply[0] NSUInteger; reply[1] NSError *",
                                            "reply_arguments": [
                                                {"index": 0, "kind": "primitive", "type": "NSUInteger", "role": "count"},
                                                {"index": 1, "kind": "object", "type": "NSError *", "role": "error"},
                                            ],
                                            "residual_gaps": [],
                                        },
                                    },
                                    {
                                        "selector": "getSpotlightAutoExampleAppEnablementForBundleIdentifier:phraseSignature:completion:",
                                        "completion_shape": {
                                            "source": "unrecovered",
                                            "confidence": "low",
                                            "completion": "",
                                            "reply_arguments": [],
                                            "residual_gaps": ["no_reply_arguments_recovered"],
                                        },
                                    },
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            output = root / "safe-read.json"
            markdown = root / "safe-read.md"

            build_xpc_safe_read_dossier(
                ["current_exampleclient:ExampleClient"],
                xpc_method_inventory_path=inventory,
                completion_shapes_path=completion_shapes,
                interfaces=["ExampleManagerXPCInterface=com.example.client.xpc"],
                output=output,
                markdown_output=markdown,
            )
            payload = json.loads(output.read_text(encoding="utf-8"))

        candidates = {item["selector"]: item for item in payload["interfaces"][0]["safe_read_candidates"]}
        count = candidates["getNumberOfExampleClientWithCompletion:"]
        self.assertEqual(count["completion_contract"]["source"], "xpc_completion_shapes")
        self.assertIn("reply[0] NSUInteger", count["completion_contract"]["completion"])
        self.assertNotIn("completion_shape_unverified", count["blockers"])
        self.assertEqual(payload["summary"]["completion_shape_backed_method_count"], 1)

        spotlight = candidates["getSpotlightAutoExampleAppEnablementForBundleIdentifier:phraseSignature:completion:"]
        self.assertEqual(spotlight["completion_contract"]["source"], "xpc_completion_shapes")
        self.assertIn("no_reply_arguments_recovered", spotlight["completion_contract"]["residual_gaps"])
        self.assertIn("completion_shape_unverified", spotlight["blockers"])


def _method(selector: str) -> dict:
    hint = _selector_signature_hint(selector)
    category = "safe_read"
    if selector.startswith("request"):
        category = "safe_read"
    return {
        "selector": selector,
        "score": 30,
        "signature_hint": hint,
        "input_shape_hints": hint["argument_hints"],
        "safety_classification": {
            "category": category,
            "confidence": "low",
            "reasons": ["selector_mentions_read_status"],
        },
    }


if __name__ == "__main__":
    unittest.main()
