import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cerberus_re_skill.modules.frida_objc_archive import (
    generate_objc_archive_script,
    parse_objc_archive_events,
    write_objc_archive_artifact,
)


class FridaObjCArchiveTests(unittest.TestCase):
    def test_objc_archive_is_skipped_without_runtime_permission(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "fixture.archive"
            archive.write_bytes(b"fixture-bytes")
            report = write_objc_archive_artifact(
                attach_pid=1234,
                archive_path=archive,
                class_name="CodexProbe",
                getters=["value"],
                output_dir=tmp,
            )
            script = Path(report["trace"]["output"]).read_text(encoding="utf-8")

        self.assertTrue(report["ok"])
        self.assertEqual(report["status"], "skipped")
        self.assertEqual(report["class_name"], "CodexProbe")
        self.assertIn("Zml4dHVyZS1ieXRlcw==", script)

    def test_objc_archive_parses_decoded_object(self) -> None:
        commands = []

        def runner(command, _timeout):
            commands.append([str(part) for part in command])
            return {
                "returncode": 0,
                "stdout": "\n".join(
                    [
                        'GHIDRA_FRIDA_OBJC_ARCHIVE {"kind":"decode","ok":true,"className":"CodexProbe","object":{"kind":"objc","text":"<CodexProbe>"}}',
                        'GHIDRA_FRIDA_OBJC_ARCHIVE {"kind":"getter","getter":"value","ok":true,"result":{"kind":"string","text":"x"}}',
                        'GHIDRA_FRIDA_OBJC_ARCHIVE {"kind":"done","ok":true}',
                    ]
                ),
                "stderr": "",
                "command": [str(part) for part in command],
            }

        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "fixture.archive"
            archive.write_bytes(b"fixture-bytes")
            with (
                patch("cerberus_re_skill.modules.frida_objc_archive.known_frida_tool", return_value="/usr/bin/frida"),
                patch("cerberus_re_skill.modules.frida_objc_archive.find_tool", return_value=None),
            ):
                report = write_objc_archive_artifact(
                    attach_pid=1234,
                    archive_path=archive,
                    class_name="CodexProbe",
                    getters=["value"],
                    output_dir=tmp,
                    allow_runtime=True,
                    runner=runner,
                )
                payload = json.loads(Path(report["json_report"]).read_text(encoding="utf-8"))

        self.assertTrue(report["ok"])
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["decoded_object_count"], 1)
        self.assertEqual(report["primary_suppressed_count"], 0)
        self.assertEqual(report["trailing_read_count"], 0)
        self.assertEqual(report["suppressed_replay_count"], 0)
        self.assertEqual(commands[0][:3], ["/usr/bin/frida", "-p", "1234"])
        self.assertEqual(payload["events"][-1]["kind"], "done")

    def test_objc_archive_fails_when_decode_is_missing(self) -> None:
        def runner(command, _timeout):
            return {
                "returncode": 0,
                "stdout": "\n".join(
                    [
                        'GHIDRA_FRIDA_OBJC_ARCHIVE {"kind":"decode","ok":false,"status":"unarchive-failed"}',
                        'GHIDRA_FRIDA_OBJC_ARCHIVE {"kind":"done","ok":true}',
                    ]
                ),
                "stderr": "",
                "command": [str(part) for part in command],
            }

        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "fixture.archive"
            archive.write_bytes(b"fixture-bytes")
            with patch("cerberus_re_skill.modules.frida_objc_archive.known_frida_tool", return_value="/usr/bin/frida"):
                report = write_objc_archive_artifact(
                    attach_pid=1234,
                    archive_path=archive,
                    class_name="CodexProbe",
                    output_dir=tmp,
                    allow_runtime=True,
                    runner=runner,
                )

        self.assertFalse(report["ok"])
        self.assertEqual(report["status"], "decode-failed")

    def test_objc_archive_reports_trailing_replay_without_inflating_readback(self) -> None:
        def runner(command, _timeout):
            return {
                "returncode": 124,
                "stdout": "\n".join(
                    [
                        'GHIDRA_FRIDA_OBJC_ARCHIVE {"kind":"decode","ok":true,"object":{"handle":"0x1"}}',
                        'GHIDRA_FRIDA_OBJC_ARCHIVE {"kind":"getter","getter":"value","ok":true}',
                        'GHIDRA_FRIDA_OBJC_ARCHIVE {"kind":"done","ok":true}',
                        'GHIDRA_FRIDA_OBJC_ARCHIVE {"kind":"decode","ok":true,"object":{"handle":"0x2"}}',
                        'GHIDRA_FRIDA_OBJC_ARCHIVE {"kind":"getter","getter":"value","ok":true}',
                    ]
                ),
                "stderr": "timed out",
                "command": [str(part) for part in command],
            }

        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "fixture.archive"
            archive.write_bytes(b"fixture-bytes")
            with patch("cerberus_re_skill.modules.frida_objc_archive.known_frida_tool", return_value="/usr/bin/frida"):
                report = write_objc_archive_artifact(
                    attach_pid=1234,
                    archive_path=archive,
                    class_name="CodexProbe",
                    getters=["value"],
                    output_dir=tmp,
                    allow_runtime=True,
                    runner=runner,
                )

        self.assertTrue(report["ok"])
        self.assertEqual(report["status"], "passed_with_trailing_events")
        self.assertEqual(report["decoded_object_count"], 1)
        self.assertEqual(report["trailing_read_count"], 2)

    def test_objc_archive_reports_process_guard_suppression(self) -> None:
        def runner(command, _timeout):
            return {
                "returncode": 124,
                "stdout": "\n".join(
                    [
                        'GHIDRA_FRIDA_OBJC_ARCHIVE {"kind":"decode","ok":true,"object":{"handle":"0x1"}}',
                        'GHIDRA_FRIDA_OBJC_ARCHIVE {"kind":"done","ok":true}',
                        'GHIDRA_FRIDA_OBJC_ARCHIVE {"kind":"suppressed","ok":true,"status":"already-executed"}',
                        'GHIDRA_FRIDA_OBJC_ARCHIVE {"kind":"done","ok":true,"status":"already-executed"}',
                    ]
                ),
                "stderr": "timed out",
                "command": [str(part) for part in command],
            }

        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "fixture.archive"
            archive.write_bytes(b"fixture-bytes")
            with patch("cerberus_re_skill.modules.frida_objc_archive.known_frida_tool", return_value="/usr/bin/frida"):
                report = write_objc_archive_artifact(
                    attach_pid=1234,
                    archive_path=archive,
                    class_name="CodexProbe",
                    output_dir=tmp,
                    allow_runtime=True,
                    runner=runner,
                )

        self.assertTrue(report["ok"])
        self.assertEqual(report["status"], "passed_with_suppressed_replay")
        self.assertEqual(report["decoded_object_count"], 1)
        self.assertEqual(report["trailing_read_count"], 0)
        self.assertEqual(report["suppressed_replay_count"], 1)

    def test_objc_archive_reports_suppression_only_without_claiming_decode_failure(self) -> None:
        def runner(command, _timeout):
            return {
                "returncode": 124,
                "stdout": "\n".join(
                    [
                        'GHIDRA_FRIDA_OBJC_ARCHIVE {"kind":"suppressed","ok":true,"status":"already-executed"}',
                        'GHIDRA_FRIDA_OBJC_ARCHIVE {"kind":"done","ok":true,"status":"already-executed"}',
                    ]
                ),
                "stderr": "timed out",
                "command": [str(part) for part in command],
            }

        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "fixture.archive"
            archive.write_bytes(b"fixture-bytes")
            with patch("cerberus_re_skill.modules.frida_objc_archive.known_frida_tool", return_value="/usr/bin/frida"):
                report = write_objc_archive_artifact(
                    attach_pid=1234,
                    archive_path=archive,
                    class_name="CodexProbe",
                    output_dir=tmp,
                    allow_runtime=True,
                    runner=runner,
                )

        self.assertFalse(report["ok"])
        self.assertEqual(report["status"], "suppressed_without_primary_readback")
        self.assertEqual(report["decoded_object_count"], 0)
        self.assertEqual(report["primary_suppressed_count"], 1)

    def test_script_generation_and_event_parser(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "archive.js"
            trace = generate_objc_archive_script(
                archive_bytes=b"fixture",
                class_name="CodexProbe",
                getters=["value", "setter:"],
                output=output,
            )
            script = output.read_text(encoding="utf-8")

        self.assertTrue(trace["ok"])
        self.assertIn("GHIDRA_ARCHIVE_BASE64", script)
        self.assertIn("unarchivedObjectOfClass_fromData_error_", script)
        self.assertIn("objc_setAssociatedObject", script)
        self.assertIn("RUN_GUARD", script)
        self.assertIn('status: "requires-arguments"', script)
        events = parse_objc_archive_events(
            'ignore\nGHIDRA_FRIDA_OBJC_ARCHIVE {"kind":"done","ok":true}\n'
            'GHIDRA_FRIDA_OBJC_ARCHIVE {"kind":"done","ok":true}\n'
        )
        self.assertEqual(events, [{"kind": "done", "ok": True}, {"kind": "done", "ok": True}])


if __name__ == "__main__":
    unittest.main()
