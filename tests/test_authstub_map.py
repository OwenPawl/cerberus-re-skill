import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cerberus_re_skill.core.config import cfg
from cerberus_re_skill.modules.authstub_map import build_authstub_map


class AuthstubMapTests(unittest.TestCase):
    def test_build_authstub_map_merges_otool_names_with_report_slots(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "ExampleClient"
            binary.write_text("mach-o", encoding="utf-8")
            out_dir = root / "exports" / "proj" / "ExampleClient"
            out_dir.mkdir(parents=True)
            (out_dir / "swift_outlined_resolved.json").write_text(
                json.dumps(
                    {
                        "renames": [
                            {
                                "entry": "27a5ef018",
                                "category": "authstub",
                                "old_name": "_OUTLINED_FUNCTION_1",
                                "new_name": "outlined$authstub$slot_299d66e70",
                            },
                            {
                                "entry": "27a5ef028",
                                "category": "authstub",
                                "old_name": "_OUTLINED_FUNCTION_2",
                                "new_name": "outlined$authstub$slot_299d66e78",
                            },
                            {
                                "entry": "27a5ef038",
                                "category": "authstub",
                                "old_name": "_OUTLINED_FUNCTION_3",
                                "new_name": "outlined$authstub$objc_msgSend",
                            },
                            {
                                "entry": "27a5ef048",
                                "category": "authstub",
                                "old_name": "_OUTLINED_FUNCTION_4",
                                "new_name": "outlined$authstub$0000",
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )

            def fake_run_tool(argv: list[str], *, timeout: float) -> subprocess.CompletedProcess[str]:
                if argv[:2] == ["dyld_info", "-no_validate"]:
                    return subprocess.CompletedProcess(
                        argv,
                        0,
                        stdout="      _swift_task_alloc  (from libswift_Concurrency)\n",
                        stderr="",
                    )
                return subprocess.CompletedProcess(
                    argv,
                    0,
                    stdout=(
                        "Indirect symbols for (__TEXT,__auth_stubs) 3 entries\n"
                        "address            index name\n"
                        "0x000000027a5ef018  12 _swift_task_alloc\n"
                        "0x000000027a5ef028 LOCAL ABSOLUTE\n"
                    ),
                    stderr="",
                )

            with (
                patch.object(cfg, "exports_dir", root / "exports"),
                patch("cerberus_re_skill.modules.authstub_map._run_tool", side_effect=fake_run_tool),
            ):
                result = build_authstub_map(
                    "proj",
                    "ExampleClient",
                    binary=binary,
                    generate_report=False,
                    ghidra_probe=False,
                )

            self.assertTrue(result["ok"])
            payload = json.loads(Path(result["output"]).read_text(encoding="utf-8"))
            self.assertEqual(payload["stubs"]["0x27a5ef018"]["name"], "swift_task_alloc")
            self.assertEqual(payload["stubs"]["0x27a5ef018"]["dyld_library"], "libswift_Concurrency")
            self.assertEqual(payload["slots"]["0x299d66e70"]["name"], "swift_task_alloc")
            self.assertEqual(payload["stubs"]["0x27a5ef028"]["slot"], "0x299d66e78")
            self.assertEqual(payload["stubs"]["0x27a5ef038"]["name"], "objc_msgSend")
            self.assertEqual(payload["stubs"]["0x27a5ef048"]["name"], "")
            self.assertEqual(payload["stats"]["resolved_stub_count"], 2)

    def test_explicit_missing_swift_report_fails_loudly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "Program"
            binary.write_text("mach-o", encoding="utf-8")
            with patch.object(cfg, "exports_dir", root / "exports"):
                with self.assertRaises(FileNotFoundError):
                    build_authstub_map(
                        "proj",
                        "Program",
                        binary=binary,
                        swift_outlined_report=root / "missing.json",
                        generate_report=False,
                        ghidra_probe=False,
                    )

    def test_build_authstub_map_generates_missing_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "Program"
            binary.write_text("mach-o", encoding="utf-8")

            def fake_resolve(*args, **kwargs):
                out_dir = Path(kwargs["output_dir"])
                out_dir.mkdir(parents=True, exist_ok=True)
                (out_dir / "swift_outlined_resolved.json").write_text('{"renames":[]}', encoding="utf-8")
                return {"ok": True}

            with (
                patch.object(cfg, "exports_dir", root / "exports"),
                patch("cerberus_re_skill.modules.authstub_map._run_tool") as run_tool,
                patch("cerberus_re_skill.modules.swift_outlined.resolve_swift_outlined", side_effect=fake_resolve),
            ):
                run_tool.return_value = subprocess.CompletedProcess([], 0, stdout="", stderr="")
                result = build_authstub_map("proj", "Program", binary=binary, ghidra_probe=False)

            self.assertTrue(Path(result["swift_outlined_report"]).exists())

    def test_custom_output_dir_still_uses_canonical_program_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "Program"
            binary.write_text("mach-o", encoding="utf-8")
            canonical = root / "exports" / "proj" / "Program"
            custom = root / "custom"
            canonical.mkdir(parents=True)
            (canonical / "program_summary.json").write_text(
                json.dumps({"executable_path": str(binary)}),
                encoding="utf-8",
            )
            (custom / "swift_outlined_resolved.json").parent.mkdir(parents=True)
            (custom / "swift_outlined_resolved.json").write_text('{"renames":[]}', encoding="utf-8")

            def fake_run_tool(argv: list[str], *, timeout: float) -> subprocess.CompletedProcess[str]:
                self.assertEqual(Path(argv[-1]), binary)
                return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

            with (
                patch.object(cfg, "exports_dir", root / "exports"),
                patch("cerberus_re_skill.modules.authstub_map._run_tool", side_effect=fake_run_tool),
            ):
                result = build_authstub_map(
                    "proj",
                    "Program",
                    output_dir=custom,
                    generate_report=False,
                    ghidra_probe=False,
                )

            self.assertEqual(result["binary"], str(binary))


if __name__ == "__main__":
    unittest.main()
