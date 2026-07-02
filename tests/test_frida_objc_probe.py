import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cerberus_re_skill.modules.frida_objc_probe import (
    generate_objc_probe_script,
    parse_objc_probe_events,
    write_objc_probe_artifact,
)


class FridaObjCProbeTests(unittest.TestCase):
    def test_objc_probe_is_skipped_without_runtime_permission(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = write_objc_probe_artifact(
                attach_pid=1234,
                classes=["CodexProbe"],
                calls=["CodexProbe.shared.isEnabled"],
                output_dir=tmp,
            )
            self.assertTrue(Path(report["trace"]["output"]).exists())

        self.assertTrue(report["ok"])
        self.assertEqual(report["status"], "skipped")
        self.assertEqual(report["classes"], ["CodexProbe"])
        self.assertEqual(report["calls"], ["CodexProbe.shared.isEnabled"])

    def test_objc_probe_generates_bounded_string_argument_call(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = write_objc_probe_artifact(
                attach_pid=1234,
                string_calls=["CodexProbe.shared.valueForType:=ActionButton"],
                output_dir=tmp,
            )
            script = Path(report["trace"]["output"]).read_text(encoding="utf-8")

        self.assertEqual(report["string_calls"], ["CodexProbe.shared.valueForType:=ActionButton"])
        self.assertIn("const GHIDRA_STRING_CALLS", script)
        self.assertIn("NSString.stringWithString_", script)
        self.assertIn("finalSelector.replace(/:/g", script)

    def test_objc_probe_rejects_multi_argument_string_selector(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(RuntimeError, "exactly one string argument"):
                write_objc_probe_artifact(
                    attach_pid=1234,
                    string_calls=["CodexProbe.shared.save:forType:=ActionButton"],
                    output_dir=tmp,
                )

    def test_objc_probe_requires_opt_in_for_attached_string_call(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(RuntimeError, "--allow-attached-call"):
                write_objc_probe_artifact(
                    attach_pid=1234,
                    string_calls=["CodexProbe.shared.valueForType:=ActionButton"],
                    output_dir=tmp,
                    allow_runtime=True,
                )

    def test_objc_probe_parses_console_events_and_requires_call_success(self) -> None:
        commands = []

        def runner(command, _timeout):
            commands.append([str(part) for part in command])
            return {
                "returncode": 0,
                "stdout": "\n".join(
                    [
                        'GHIDRA_FRIDA_OBJC_PROBE {"kind":"status","ok":true,"status":"objc-available"}',
                        'GHIDRA_FRIDA_OBJC_PROBE {"kind":"class","name":"CodexProbe","surface":{"present":true,"methods":["+ shared","- isEnabled"]}}',
                        'GHIDRA_FRIDA_OBJC_PROBE {"kind":"call","chain":"CodexProbe.shared.isEnabled","ok":true,"status":"called","result":{"kind":"boolean","text":"true"}}',
                        'GHIDRA_FRIDA_OBJC_PROBE {"kind":"done","ok":true}',
                    ]
                ),
                "stderr": "",
                "command": [str(part) for part in command],
            }

        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch("cerberus_re_skill.modules.frida_objc_probe.known_frida_tool", return_value="/usr/bin/frida"),
                patch("cerberus_re_skill.modules.frida_objc_probe.find_tool", return_value=None),
            ):
                report = write_objc_probe_artifact(
                    attach_pid=1234,
                    classes=["CodexProbe"],
                    calls=["CodexProbe.shared.isEnabled"],
                    output_dir=tmp,
                    allow_runtime=True,
                    require_successful_call=True,
                    runner=runner,
                )
                payload = json.loads(Path(report["json_report"]).read_text(encoding="utf-8"))

        self.assertTrue(report["ok"])
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["successful_call_count"], 1)
        self.assertEqual(commands[0][:3], ["/usr/bin/frida", "-p", "1234"])
        self.assertIn("--runtime=v8", commands[0])
        self.assertEqual(payload["events"][-1]["kind"], "done")

    def test_objc_probe_counts_successful_string_call(self) -> None:
        def runner(command, _timeout):
            return {
                "returncode": 0,
                "stdout": "\n".join(
                    [
                        'GHIDRA_FRIDA_OBJC_PROBE {"kind":"string-call","chain":"CodexProbe.shared.valueForType:","ok":true,"status":"called","result":{"kind":"objc","className":"CodexResult","text":"result"}}',
                        'GHIDRA_FRIDA_OBJC_PROBE {"kind":"done","ok":true}',
                    ]
                ),
                "stderr": "",
                "command": [str(part) for part in command],
            }

        with tempfile.TemporaryDirectory() as tmp:
            with patch("cerberus_re_skill.modules.frida_objc_probe.known_frida_tool", return_value="/usr/bin/frida"):
                report = write_objc_probe_artifact(
                    attach_pid=1234,
                    string_calls=["CodexProbe.shared.valueForType:=ActionButton"],
                    output_dir=tmp,
                    allow_runtime=True,
                    require_successful_call=True,
                    allow_attached_call=True,
                    runner=runner,
                )

        self.assertTrue(report["ok"])
        self.assertEqual(report["successful_call_count"], 1)
        self.assertEqual(report["successful_string_call_count"], 1)

    def test_objc_probe_reports_no_successful_call(self) -> None:
        def runner(command, _timeout):
            return {
                "returncode": 0,
                "stdout": "\n".join(
                    [
                        'GHIDRA_FRIDA_OBJC_PROBE {"kind":"call","chain":"CodexProbe.shared","ok":false,"status":"missing-member"}',
                        'GHIDRA_FRIDA_OBJC_PROBE {"kind":"done","ok":true}',
                    ]
                ),
                "stderr": "",
                "command": [str(part) for part in command],
            }

        with tempfile.TemporaryDirectory() as tmp:
            with patch("cerberus_re_skill.modules.frida_objc_probe.known_frida_tool", return_value="/usr/bin/frida"):
                report = write_objc_probe_artifact(
                    attach_pid=1234,
                    calls=["CodexProbe.shared"],
                    output_dir=tmp,
                    allow_runtime=True,
                    require_successful_call=True,
                    runner=runner,
                )

        self.assertFalse(report["ok"])
        self.assertEqual(report["status"], "no-successful-call")

    def test_script_generation_and_event_parser(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "probe.js"
            trace = generate_objc_probe_script(["CodexProbe"], ["CodexProbe.shared"], output)
            script = output.read_text(encoding="utf-8")

        self.assertTrue(trace["ok"])
        self.assertIn("const GHIDRA_CLASSES", script)
        self.assertIn("function callChain", script)
        self.assertIn("function collectionPreview", script)
        self.assertIn("allKeys", script)
        self.assertIn('value.compare(ptr("0x10000")) < 0', script)
        events = parse_objc_probe_events(
            'ignore\nGHIDRA_FRIDA_OBJC_PROBE {"kind":"done","ok":true}\n'
            'GHIDRA_FRIDA_OBJC_PROBE {"kind":"done","ok":true}\n'
            'GHIDRA_FRIDA_OBJC_PROBE {"kind":"call","ok":true,"result":{"collection":{"kind":"dictionary","keys":["a"]}}}\n'
        )
        self.assertEqual(
            events,
            [
                {"kind": "done", "ok": True},
                {"kind": "call", "ok": True, "result": {"collection": {"kind": "dictionary", "keys": ["a"]}}},
            ],
        )


if __name__ == "__main__":
    unittest.main()
