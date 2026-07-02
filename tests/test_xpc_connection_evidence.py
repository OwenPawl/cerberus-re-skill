import json
import tempfile
import unittest
from pathlib import Path

from cerberus_re_skill.modules.xpc_connection_evidence import (
    XPC_CONNECTION_EVIDENCE_SCHEMA,
    _classify_run,
    build_xpc_connection_evidence,
)


class XpcConnectionEvidenceTests(unittest.TestCase):
    def test_build_xpc_connection_evidence_from_method_inventory(self) -> None:
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
                                "interface": "_ExampleAutomationDaemonXPCInterface",
                                "method_count": 4,
                                "graph_context": {
                                    "services": [
                                        "_AutomationDaemonXPCInterfaceMachServiceName",
                                        "com.apple.background-helper.xpc",
                                        "com.apple.automationd.xpc",
                                    ]
                                },
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            output = root / "connection.json"
            markdown = root / "connection.md"
            harness_dir = root / "harnesses"

            result = build_xpc_connection_evidence(
                ["proj:Program"],
                xpc_method_inventory_path=inventory,
                framework_loads=["/System/Library/PrivateFrameworks/Example.framework/Example"],
                output=output,
                markdown_output=markdown,
                harness_output_dir=harness_dir,
            )
            payload = json.loads(output.read_text(encoding="utf-8"))
            harnesses = list(harness_dir.glob("*.m"))
            harness_text = harnesses[0].read_text(encoding="utf-8")

        self.assertTrue(result["ok"])
        self.assertEqual(payload["schema"], XPC_CONNECTION_EVIDENCE_SCHEMA)
        self.assertEqual(payload["summary"]["connection_count"], 1)
        self.assertEqual(payload["summary"]["framework_load_count"], 1)
        self.assertEqual(payload["connections"][0]["service"], "com.apple.automationd.xpc")
        self.assertEqual(
            payload["connections"][0]["framework_loads"],
            ["/System/Library/PrivateFrameworks/Example.framework/Example"],
        )
        self.assertTrue(harnesses)
        self.assertIn("dlopen", harness_text)
        self.assertIn("Protocol before framework loads", harness_text)
        self.assertIn("/System/Library/PrivateFrameworks/Example.framework/Example", harness_text)
        self.assertIn("Remote proxy placeholder acquired without description", harness_text)
        self.assertIn("never invokes a remote method", harness_text)

    def test_explicit_connection_takes_priority_over_inventory_limit(self) -> None:
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
                                "interface": "_WrongRankedInterface",
                                "method_count": 4,
                                "graph_context": {"services": ["com.apple.wrong"]},
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            output = root / "connection.json"
            markdown = root / "connection.md"

            build_xpc_connection_evidence(
                ["proj:Program"],
                xpc_method_inventory_path=inventory,
                interfaces=["_ExplicitInterface=com.apple.explicit"],
                output=output,
                markdown_output=markdown,
                limit=1,
            )
            payload = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(payload["summary"]["connection_count"], 1)
        self.assertEqual(payload["connections"][0]["interface"], "_ExplicitInterface")
        self.assertEqual(payload["connections"][0]["service"], "com.apple.explicit")
        self.assertEqual(payload["connections"][0]["source"], "explicit")

    def test_framework_loads_are_serialized_as_apple_posix_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "connection.json"

            build_xpc_connection_evidence(
                ["proj:Program"],
                interfaces=["_ExplicitInterface=com.apple.explicit"],
                framework_loads=[r"\System\Library\PrivateFrameworks\ExampleKit.framework\ExampleKit"],
                output=output,
                markdown_output=root / "connection.md",
            )
            payload = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(
            payload["inputs"]["framework_loads"],
            ["/System/Library/PrivateFrameworks/ExampleKit.framework/ExampleKit"],
        )

    def test_classify_proxy_logging_exception_as_harness_crash(self) -> None:
        result = _classify_run(
            134,
            "",
            "Created XPC connection\n*** Terminating app due to uncaught exception 'NSInvalidArgumentException'",
        )

        self.assertEqual(result["status"], "harness_crashed")
        self.assertEqual(result["blocker_classification"], "harness_exception")

    def test_classify_clean_no_call_connection(self) -> None:
        result = _classify_run(
            0,
            "",
            "Created XPC connection\nRemote proxy placeholder acquired without description\nNo-call connection evidence complete",
        )

        self.assertEqual(result["status"], "connection_object_created_no_call")
        self.assertEqual(result["blocker_classification"], "none_observed")
        self.assertEqual(len(result["observations"]), 3)

    def test_classify_framework_registered_protocol(self) -> None:
        result = _classify_run(
            0,
            "",
            "Protocol before framework loads: missing\n"
            "Loaded framework /System/Library/PrivateFrameworks/ExampleClient.framework/ExampleClient\n"
            "Protocol after framework loads: registered\n"
            "Configured remoteObjectInterface with protocol ExampleManagerXPCInterface\n"
            "Created XPC connection\n"
            "Remote proxy placeholder acquired without description\n"
            "No-call connection evidence complete",
        )

        self.assertEqual(result["status"], "connection_object_created_no_call")
        self.assertEqual(result["blocker_classification"], "none_observed")
        self.assertEqual(result["framework_load_attempt_count"], 1)
        self.assertEqual(result["framework_load_ok_count"], 1)
        self.assertIs(result["remote_protocol_registered"], True)
        self.assertIn("framework load registered previously missing ObjC protocol", result["observations"])

    def test_classify_missing_protocol_as_blocked(self) -> None:
        result = _classify_run(
            0,
            "",
            "No ObjC protocol named ExampleManagerXPCInterface was registered\nNo-call connection evidence complete",
        )

        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["blocker_classification"], "remote_protocol_not_registered")
        self.assertIs(result["remote_protocol_registered"], False)


if __name__ == "__main__":
    unittest.main()
