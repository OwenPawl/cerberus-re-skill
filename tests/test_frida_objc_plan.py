import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cerberus_re_skill.modules.frida_objc_plan import (
    generate_objc_plan_script,
    parse_objc_plan_events,
    write_objc_plan_artifact,
)


def safe_plan() -> dict:
    return {
        "schema": "ghidra-re.objc-plan.v1",
        "steps": [
            {"id": "bundle", "op": "string", "value": "com.example.Actions"},
            {"id": "action", "op": "string", "value": "DoThing"},
            {"id": "empty", "op": "empty-dictionary"},
            {
                "id": "intent",
                "op": "construct",
                "class": "INAppIntent",
                "selector": "initWithAppBundleIdentifier:appIntentIdentifier:serializedParameters:",
                "args": ["$bundle", "$action", "$empty"],
            },
            {"id": "value", "op": "read", "receiver": "$intent", "selector": "asLNValue"},
        ],
    }


class FridaObjCPlanTests(unittest.TestCase):
    def test_generates_bounded_constructor_and_read_script(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "plan.js"
            trace = generate_objc_plan_script(plan=safe_plan(), output=output)
            script = output.read_text(encoding="utf-8")

        self.assertEqual(trace["step_count"], 5)
        self.assertIn("GHIDRA_PLAN", script)
        self.assertIn("initWithAppBundleIdentifier", script)
        self.assertIn("asLNValue", script)
        self.assertIn("objc_setAssociatedObject", script)

    def test_rejects_mutating_or_out_of_order_plan_steps(self) -> None:
        bad_selector = safe_plan()
        bad_selector["steps"][-1]["selector"] = "saveUpdatedAction:"
        bad_selector["steps"][-1]["op"] = "call"
        bad_selector["steps"][-1]["args"] = ["$empty"]
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(RuntimeError, "unsafe selector"):
                generate_objc_plan_script(plan=bad_selector, output=Path(tmp) / "bad.js")
            with self.assertRaisesRegex(RuntimeError, "earlier step"):
                generate_objc_plan_script(
                    plan={
                        "schema": "ghidra-re.objc-plan.v1",
                        "steps": [{"id": "read", "op": "read", "receiver": "$missing", "selector": "value"}],
                    },
                    output=Path(tmp) / "missing.js",
                )
            with self.assertRaisesRegex(RuntimeError, "unsafe selector"):
                generate_objc_plan_script(
                    plan={
                        "schema": "ghidra-re.objc-plan.v1",
                        "steps": [
                            {"id": "value", "op": "nil"},
                            {"id": "set", "op": "call", "receiver": "$value", "selector": "setValue:", "args": ["$value"]},
                        ],
                    },
                    output=Path(tmp) / "generic-set.js",
                )

    def test_allows_explicit_ephemeral_parameter_configuration(self) -> None:
        plan = {
            "schema": "ghidra-re.objc-plan.v1",
            "allow_ephemeral_configuration": True,
            "steps": [
                {"id": "provider", "op": "class-read", "class": "ExampleConfiguredActionProvider", "selector": "sharedProvider"},
                {"id": "key", "op": "string", "value": "operation"},
                {"id": "value", "op": "string", "value": "turn"},
                {
                    "id": "state",
                    "op": "construct",
                    "class": "ExampleLinkEnumerationState",
                    "selector": "initWithValue:",
                    "args": ["$value"],
                },
                {"id": "action", "op": "call", "receiver": "$provider", "selector": "linkActionWithStaccatoIdentifier:", "args": ["$value"]},
                {"id": "configured", "op": "configure-parameter-state", "receiver": "$action", "state": "$state", "key": "$key"},
                {"id": "serialized", "op": "read", "receiver": "$configured", "selector": "serializedParameters"},
            ],
        }
        without_opt_in = dict(plan)
        without_opt_in.pop("allow_ephemeral_configuration")
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(RuntimeError, "allow_ephemeral_configuration"):
                generate_objc_plan_script(plan=without_opt_in, output=Path(tmp) / "blocked.js")
            output = Path(tmp) / "configured.js"
            trace = generate_objc_plan_script(plan=plan, output=output)
            script = output.read_text(encoding="utf-8")

        self.assertEqual(trace["step_count"], 7)
        self.assertIn("sharedProvider", script)
        self.assertIn("setParameterState_forKey_", script)

    def test_supports_typed_boolean_constructor_arguments(self) -> None:
        plan = {
            "schema": "ghidra-re.objc-plan.v1",
            "steps": [
                {"id": "flag", "op": "boolean", "value": False},
                {
                    "id": "state",
                    "op": "construct",
                    "class": "ExampleBooleanState",
                    "selector": "initWithBoolValue:",
                    "args": ["$flag"],
                },
            ],
        }
        invalid = {"schema": "ghidra-re.objc-plan.v1", "steps": [{"id": "flag", "op": "boolean", "value": "false"}]}
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(RuntimeError, "JSON true or false"):
                generate_objc_plan_script(plan=invalid, output=Path(tmp) / "invalid.js")
            output = Path(tmp) / "bool.js"
            trace = generate_objc_plan_script(plan=plan, output=output)
            script = output.read_text(encoding="utf-8")

        self.assertEqual(trace["step_count"], 2)
        self.assertIn('"op": "boolean"', script)
        self.assertIn("initWithBoolValue", script)

    def test_reads_named_lnentity_property_through_getters_only(self) -> None:
        plan = safe_plan()
        plan["steps"].extend(
            [
                {
                    "id": "encoded",
                    "op": "ln-entity-property",
                    "receiver": "$value",
                    "identifier": "displayName",
                },
                {"id": "encoded_text", "op": "read", "receiver": "$encoded", "selector": "value"},
            ]
        )
        invalid = {
            "schema": "ghidra-re.objc-plan.v1",
            "steps": [
                {"id": "value", "op": "nil"},
                {"id": "property", "op": "ln-entity-property", "receiver": "$value", "identifier": ""},
            ],
        }
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(RuntimeError, "property identifier"):
                generate_objc_plan_script(plan=invalid, output=Path(tmp) / "invalid.js")
            output = Path(tmp) / "entity-property.js"
            trace = generate_objc_plan_script(plan=plan, output=output)
            script = output.read_text(encoding="utf-8")

        self.assertEqual(trace["step_count"], 7)
        self.assertIn("lnEntityPropertyValue", script)
        self.assertIn("properties()", script)
        self.assertIn("displayName", script)

    def test_attached_runtime_plan_requires_explicit_opt_in(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            plan = Path(tmp) / "plan.json"
            plan.write_text(json.dumps(safe_plan()), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "--allow-attached-plan"):
                write_objc_plan_artifact(plan_path=plan, attach_pid=1234, allow_runtime=True, output_dir=tmp)

    def test_records_successful_runtime_plan_steps(self) -> None:
        def runner(command, _timeout):
            lines = [
                f'GHIDRA_FRIDA_OBJC_PLAN {json.dumps({"kind": "step", "id": step["id"], "op": step["op"], "ok": True})}'
                for step in safe_plan()["steps"]
            ]
            lines.append('GHIDRA_FRIDA_OBJC_PLAN {"kind":"done","ok":true}')
            return {
                "returncode": 0,
                "stdout": "\n".join(lines),
                "stderr": "",
                "command": [str(part) for part in command],
            }

        with tempfile.TemporaryDirectory() as tmp:
            plan = Path(tmp) / "plan.json"
            plan.write_text(json.dumps(safe_plan()), encoding="utf-8")
            with patch("cerberus_re_skill.modules.frida_objc_plan.known_frida_tool", return_value="/usr/bin/frida"):
                report = write_objc_plan_artifact(
                    plan_path=plan,
                    attach_pid=1234,
                    allow_runtime=True,
                    allow_attached_plan=True,
                    output_dir=Path(tmp) / "report",
                    runner=runner,
                )

        self.assertTrue(report["ok"])
        self.assertEqual(report["completed_step_count"], 5)
        self.assertTrue(report["sequence_ok"])
        self.assertEqual(parse_objc_plan_events('GHIDRA_FRIDA_OBJC_PLAN {"kind":"done","ok":true}\n'), [{"kind": "done", "ok": True}])

    def test_reports_trailing_replay_without_inflating_completed_steps(self) -> None:
        def runner(command, _timeout):
            lines = [
                f'GHIDRA_FRIDA_OBJC_PLAN {json.dumps({"kind": "step", "id": step["id"], "op": step["op"], "ok": True})}'
                for step in safe_plan()["steps"]
            ]
            lines.extend(
                [
                    'GHIDRA_FRIDA_OBJC_PLAN {"kind":"done","ok":true}',
                    'GHIDRA_FRIDA_OBJC_PLAN {"kind":"step","id":"intent","op":"construct","ok":true}',
                ]
            )
            return {"returncode": 124, "stdout": "\n".join(lines), "stderr": "timed out", "command": command}

        with tempfile.TemporaryDirectory() as tmp:
            plan = Path(tmp) / "plan.json"
            plan.write_text(json.dumps(safe_plan()), encoding="utf-8")
            with patch("cerberus_re_skill.modules.frida_objc_plan.known_frida_tool", return_value="/usr/bin/frida"):
                report = write_objc_plan_artifact(
                    plan_path=plan,
                    attach_pid=1234,
                    allow_runtime=True,
                    allow_attached_plan=True,
                    output_dir=Path(tmp) / "report",
                    runner=runner,
                )

        self.assertTrue(report["ok"])
        self.assertEqual(report["status"], "passed_with_trailing_events")
        self.assertEqual(report["completed_step_count"], 5)
        self.assertEqual(report["trailing_step_count"], 1)

    def test_reports_process_guard_suppression_without_replay_steps(self) -> None:
        def runner(command, _timeout):
            lines = [
                f'GHIDRA_FRIDA_OBJC_PLAN {json.dumps({"kind": "step", "id": step["id"], "op": step["op"], "ok": True})}'
                for step in safe_plan()["steps"]
            ]
            lines.extend(
                [
                    'GHIDRA_FRIDA_OBJC_PLAN {"kind":"done","ok":true}',
                    'GHIDRA_FRIDA_OBJC_PLAN {"kind":"suppressed","ok":true,"status":"already-executed"}',
                    'GHIDRA_FRIDA_OBJC_PLAN {"kind":"done","ok":true,"status":"already-executed"}',
                ]
            )
            return {"returncode": 124, "stdout": "\n".join(lines), "stderr": "timed out", "command": command}

        with tempfile.TemporaryDirectory() as tmp:
            plan = Path(tmp) / "plan.json"
            plan.write_text(json.dumps(safe_plan()), encoding="utf-8")
            with patch("cerberus_re_skill.modules.frida_objc_plan.known_frida_tool", return_value="/usr/bin/frida"):
                report = write_objc_plan_artifact(
                    plan_path=plan,
                    attach_pid=1234,
                    allow_runtime=True,
                    allow_attached_plan=True,
                    output_dir=Path(tmp) / "report",
                    runner=runner,
                )

        self.assertTrue(report["ok"])
        self.assertEqual(report["status"], "passed_with_suppressed_replay")
        self.assertEqual(report["trailing_step_count"], 0)
        self.assertEqual(report["suppressed_replay_count"], 1)

    def test_materializes_explicit_base64_step_output(self) -> None:
        plan = {
            "schema": "ghidra-re.objc-plan.v1",
            "steps": [{"id": "payload", "op": "string", "value": "YnBsaXN0MDBmaXh0dXJl"}],
        }

        def runner(command, _timeout):
            return {
                "returncode": 0,
                "stdout": (
                    'GHIDRA_FRIDA_OBJC_PLAN {"kind":"step","id":"payload","op":"string","ok":true,'
                    '"result":{"kind":"objc","text":"YnBsaXN0MDBmaXh0dXJl"}}\n'
                    'GHIDRA_FRIDA_OBJC_PLAN {"kind":"done","ok":true}'
                ),
                "stderr": "",
                "command": command,
            }

        with tempfile.TemporaryDirectory() as tmp:
            plan_file = Path(tmp) / "plan.json"
            plan_file.write_text(json.dumps(plan), encoding="utf-8")
            with patch("cerberus_re_skill.modules.frida_objc_plan.known_frida_tool", return_value="/usr/bin/frida"):
                report = write_objc_plan_artifact(
                    plan_path=plan_file,
                    attach_pid=1234,
                    allow_runtime=True,
                    allow_attached_plan=True,
                    extract_base64_steps=["payload"],
                    output_dir=Path(tmp) / "report",
                    runner=runner,
                )
            output = Path(report["extracted_outputs"][0]["path"])
            self.assertEqual(output.read_bytes(), b"bplist00fixture")

        self.assertTrue(report["ok"])
        self.assertEqual(report["extracted_outputs"][0]["byte_length"], 15)
        self.assertEqual(report["extracted_outputs"][0]["step_id"], "payload")

    def test_rejects_missing_or_invalid_base64_extraction_step(self) -> None:
        def runner(command, _timeout):
            return {
                "returncode": 0,
                "stdout": (
                    'GHIDRA_FRIDA_OBJC_PLAN {"kind":"step","id":"payload","op":"string","ok":true,'
                    '"result":{"kind":"objc","text":"not base64!"}}\n'
                    'GHIDRA_FRIDA_OBJC_PLAN {"kind":"done","ok":true}'
                ),
                "stderr": "",
                "command": command,
            }

        with tempfile.TemporaryDirectory() as tmp:
            plan_file = Path(tmp) / "plan.json"
            plan_file.write_text(
                json.dumps({"schema": "ghidra-re.objc-plan.v1", "steps": [{"id": "payload", "op": "string", "value": "x"}]}),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(RuntimeError, "name a plan step"):
                write_objc_plan_artifact(plan_path=plan_file, attach_pid=1, extract_base64_steps=["missing"], output_dir=tmp)
            with patch("cerberus_re_skill.modules.frida_objc_plan.known_frida_tool", return_value="/usr/bin/frida"):
                report = write_objc_plan_artifact(
                    plan_path=plan_file,
                    attach_pid=1234,
                    allow_runtime=True,
                    allow_attached_plan=True,
                    extract_base64_steps=["payload"],
                    output_dir=Path(tmp) / "report",
                    runner=runner,
                )

        self.assertFalse(report["ok"])
        self.assertEqual(report["status"], "extraction_failed")
        self.assertFalse(report["extracted_outputs"][0]["ok"])


if __name__ == "__main__":
    unittest.main()
