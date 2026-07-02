import json
import tempfile
import unittest
from pathlib import Path

from cerberus_re_skill.modules.nil_selector_triage import NIL_SELECTOR_TRIAGE_SCHEMA, build_nil_selector_triage


class NilSelectorTriageTests(unittest.TestCase):
    def test_build_nil_selector_triage_classifies_storage_backed_nil(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = root / "repeat_fixture.json"
            fixture.write_text(
                json.dumps(
                    {
                        "schema": "ghidra-re.action-context-fixture.v1",
                        "class_name": "ExampleRepeatAction",
                        "identifier": "is.workflow.actions.repeat.count",
                        "context_slots": {
                            "workflow": {"constructed": True},
                            "variable_source": {"constructed": True},
                        },
                        "action_specific_selector_probes": [
                            {
                                "selector": "repeatInputWithVariableSource:",
                                "method_present": True,
                                "result": "nil",
                                "argument_slot": "variable_source",
                            }
                        ],
                        "repeat_mutation_probes": [
                            {
                                "getter": "repeatInputWithVariableSource:",
                                "getter_present": True,
                                "setter": "setRepeatInput:withVariableSource:",
                                "setter_present": True,
                                "read_before": "nil",
                                "read_after": "ExampleContentCollection: <mock>",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            inventory = root / "function_inventory.json"
            inventory.write_text(
                json.dumps(
                    {
                        "functions": [
                            {
                                "name": "-[ExampleRepeatAction_repeatInputWithVariableSource:]",
                                "entry": "1000",
                                "signature": "undefined f()",
                                "body_size": 24,
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            strings = root / "strings.json"
            strings.write_text(json.dumps({"strings": [{"value": "repeatInputWithVariableSource:"}]}), encoding="utf-8")
            dossier_dir = root / "dossier"
            dossier_dir.mkdir()
            (dossier_dir / "context.json").write_text(
                json.dumps({"function": {"name": "-[ExampleRepeatAction_repeatInputWithVariableSource:]"}}),
                encoding="utf-8",
            )
            (dossier_dir / "decompile.c").write_text("outlined_authstub_objc_retain_x0(param_3);\n", encoding="utf-8")

            result = build_nil_selector_triage(
                artifacts=[f"repeat={fixture}"],
                function_inventory=inventory,
                strings=strings,
                dossiers=[f"repeat-input={dossier_dir}"],
                output=root / "nil-selector-triage.json",
                markdown_output=root / "nil-selector-triage.md",
            )
            payload = json.loads((root / "nil-selector-triage.json").read_text(encoding="utf-8"))
            markdown = (root / "nil-selector-triage.md").read_text(encoding="utf-8")

        self.assertTrue(result["ok"])
        self.assertEqual(payload["schema"], NIL_SELECTOR_TRIAGE_SCHEMA)
        self.assertEqual(payload["summary"]["candidate_count"], 1)
        self.assertEqual(payload["summary"]["nil_until_initialized_storage_backed_count"], 1)
        self.assertEqual(payload["summary"]["static_match_count"], 1)
        self.assertEqual(payload["summary"]["authstub_only_dossier_count"], 1)
        self.assertEqual(payload["candidates"][0]["classification"], "nil_until_initialized_storage_backed")
        self.assertEqual(payload["candidates"][0]["next_runtime_recheck"]["priority"], "high")
        self.assertIn("Storage-backed nils: 1", markdown)

    def test_build_nil_selector_triage_classifies_scalar_probe_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = root / "repeat_fixture.json"
            fixture.write_text(
                json.dumps(
                    {
                        "schema": "ghidra-re.action-context-fixture.v1",
                        "class_name": "ExampleRepeatAction",
                        "action_specific_selector_probes": [
                            {"selector": "repeatCountWithVariableSource:", "method_present": True, "result": "nil"}
                        ],
                        "repeat_mutation_probes": [
                            {
                                "getter": "repeatCountWithVariableSource:",
                                "getter_present": True,
                                "setter": "setRepeatCount:withVariableSource:",
                                "setter_present": True,
                                "read_before": 0,
                                "read_after": 2,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            build_nil_selector_triage(
                artifacts=[f"repeat={fixture}"],
                output=root / "nil-selector-triage.json",
                markdown_output=root / "nil-selector-triage.md",
            )
            payload = json.loads((root / "nil-selector-triage.json").read_text(encoding="utf-8"))

        self.assertEqual(payload["summary"]["scalar_default_or_probe_shape_mismatch_count"], 1)
        self.assertEqual(payload["candidates"][0]["classification"], "scalar_default_or_probe_shape_mismatch")

    def test_build_nil_selector_triage_classifies_scalar_storage_backed_with_method_types(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = root / "repeat_fixture.json"
            fixture.write_text(
                json.dumps(
                    {
                        "schema": "ghidra-re.action-context-fixture.v1",
                        "class_name": "ExampleRepeatAction",
                        "method_type_encodings": {
                            "ExampleRepeatAction": [
                                {
                                    "selector": "repeatCountWithVariableSource:",
                                    "present": True,
                                    "type_encoding": "q24@0:8@16",
                                    "return_type": "q",
                                    "return_shape": "integer",
                                    "argument_types": ["@", ":", "@"],
                                    "argument_shapes": ["object", "selector", "object"],
                                }
                            ]
                        },
                        "action_specific_selector_probes": [
                            {"selector": "repeatCountWithVariableSource:", "method_present": True, "result": "nil"}
                        ],
                        "repeat_mutation_probes": [
                            {
                                "getter": "repeatCountWithVariableSource:",
                                "getter_present": True,
                                "getter_method_type": {
                                    "selector": "repeatCountWithVariableSource:",
                                    "present": True,
                                    "return_type": "q",
                                    "return_shape": "integer",
                                },
                                "setter": "setRepeatCount:withVariableSource:",
                                "setter_present": True,
                                "read_before": 0,
                                "read_after": 2,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            build_nil_selector_triage(
                artifacts=[f"repeat={fixture}"],
                output=root / "nil-selector-triage.json",
                markdown_output=root / "nil-selector-triage.md",
            )
            payload = json.loads((root / "nil-selector-triage.json").read_text(encoding="utf-8"))
            markdown = (root / "nil-selector-triage.md").read_text(encoding="utf-8")

        candidate = payload["candidates"][0]
        self.assertEqual(payload["summary"]["scalar_default_integer_storage_backed_count"], 1)
        self.assertEqual(payload["summary"]["scalar_default_or_probe_shape_mismatch_count"], 0)
        self.assertEqual(candidate["classification"], "scalar_default_integer_storage_backed")
        self.assertEqual(candidate["method_type_evidence"][0]["return_shape"], "integer")
        self.assertIn("Scalar storage-backed defaults: 1", markdown)


if __name__ == "__main__":
    unittest.main()
