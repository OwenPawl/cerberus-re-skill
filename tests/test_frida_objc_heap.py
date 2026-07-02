import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cerberus_re_skill.modules.frida_objc_heap import (
    generate_objc_heap_script,
    parse_objc_heap_events,
    write_objc_heap_artifact,
)


class FridaObjCHeapTests(unittest.TestCase):
    def test_objc_heap_is_skipped_without_runtime_permission(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = write_objc_heap_artifact(
                attach_pid=1234,
                classes=["CodexProbe"],
                getters=["value"],
                output_dir=tmp,
            )
            self.assertTrue(Path(report["trace"]["output"]).exists())

        self.assertTrue(report["ok"])
        self.assertEqual(report["status"], "skipped")
        self.assertEqual(report["classes"], ["CodexProbe"])
        self.assertEqual(report["getters"], ["value"])

    def test_objc_heap_parses_instances_and_requires_instance(self) -> None:
        commands = []

        def runner(command, _timeout):
            commands.append([str(part) for part in command])
            return {
                "returncode": 0,
                "stdout": "\n".join(
                    [
                        'GHIDRA_FRIDA_OBJC_HEAP {"kind":"status","ok":true,"status":"objc-available"}',
                        'GHIDRA_FRIDA_OBJC_HEAP {"kind":"instance","className":"CodexProbe","index":1,"object":{"kind":"objc","text":"<CodexProbe>"}}',
                        'GHIDRA_FRIDA_OBJC_HEAP {"kind":"class-complete","className":"CodexProbe","present":true,"observedCount":1,"emittedCount":1}',
                        'GHIDRA_FRIDA_OBJC_HEAP {"kind":"done","ok":true}',
                    ]
                ),
                "stderr": "",
                "command": [str(part) for part in command],
            }

        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch("cerberus_re_skill.modules.frida_objc_heap.known_frida_tool", return_value="/usr/bin/frida"),
                patch("cerberus_re_skill.modules.frida_objc_heap.find_tool", return_value=None),
            ):
                report = write_objc_heap_artifact(
                    attach_pid=1234,
                    classes=["CodexProbe"],
                    getters=["value"],
                    output_dir=tmp,
                    allow_runtime=True,
                    require_instance=True,
                    runner=runner,
                )
                payload = json.loads(Path(report["json_report"]).read_text(encoding="utf-8"))

        self.assertTrue(report["ok"])
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["instance_count"], 1)
        self.assertEqual(commands[0][:3], ["/usr/bin/frida", "-p", "1234"])
        self.assertIn("--runtime=v8", commands[0])
        self.assertEqual(payload["events"][-1]["kind"], "done")

    def test_objc_heap_reports_no_instances(self) -> None:
        def runner(command, _timeout):
            return {
                "returncode": 0,
                "stdout": "\n".join(
                    [
                        'GHIDRA_FRIDA_OBJC_HEAP {"kind":"class-complete","className":"CodexProbe","present":true,"observedCount":0,"emittedCount":0}',
                        'GHIDRA_FRIDA_OBJC_HEAP {"kind":"done","ok":true}',
                    ]
                ),
                "stderr": "",
                "command": [str(part) for part in command],
            }

        with tempfile.TemporaryDirectory() as tmp:
            with patch("cerberus_re_skill.modules.frida_objc_heap.known_frida_tool", return_value="/usr/bin/frida"):
                report = write_objc_heap_artifact(
                    attach_pid=1234,
                    classes=["CodexProbe"],
                    output_dir=tmp,
                    allow_runtime=True,
                    require_instance=True,
                    runner=runner,
                )

        self.assertFalse(report["ok"])
        self.assertEqual(report["status"], "no-instances")

    def test_script_generation_and_event_parser(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "heap.js"
            trace = generate_objc_heap_script(
                classes=["CodexProbe"],
                getters=["value"],
                output=output,
                include_ivars=True,
                max_instances=3,
            )
            script = output.read_text(encoding="utf-8")

        self.assertTrue(trace["ok"])
        self.assertIn("const GHIDRA_CLASSES", script)
        self.assertIn("function ivarSnapshot", script)
        self.assertIn("GHIDRA_MAX_INSTANCES = 3", script)
        events = parse_objc_heap_events(
            'ignore\nGHIDRA_FRIDA_OBJC_HEAP {"kind":"done","ok":true}\n'
            'GHIDRA_FRIDA_OBJC_HEAP {"kind":"done","ok":true}\n'
        )
        self.assertEqual(events, [{"kind": "done", "ok": True}])


if __name__ == "__main__":
    unittest.main()
