import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cerberus_re_skill.modules.lldb_validation import ProcessResult, validate_lldb_trace


class LldbValidationTests(unittest.TestCase):
    def test_validate_lldb_trace_runs_symbols_trace_and_enrich(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            function_inventory = report_dir / "saved-function-inventory.json"
            commands: list[list[str]] = []

            def fake_runner(command, cwd, timeout):
                commands.append(list(command))
                if "ghidra_lldb_trace" in command[0]:
                    out_arg = next(arg for arg in command if arg.startswith("output="))
                    trace_path = Path(out_arg.split("=", 1)[1])
                    trace_path.write_text(
                        json.dumps(
                            {
                                "ok": True,
                                "hit_count": 1,
                                "hits": [{"pc": "0x1000", "symbol": "-[CodexProbe runWithInput:]"}],
                                "breakpoints": [{"hits": 1}],
                                "runtime_modules": [
                                    {
                                        "name": "Program",
                                        "path": "/tmp/Program",
                                        "uuid": "00000000-0000-0000-0000-000000000001",
                                    }
                                ],
                            }
                        ),
                        encoding="utf-8",
                    )
                return ProcessResult(0, "ok", "")

            with patch(
                "cerberus_re_skill.modules.lldb_validation.enrich_lldb_trace",
                return_value={"ok": True, "output": str(report_dir / "enriched.json"), "matched_function_count": 1},
            ) as enrich:
                result = validate_lldb_trace(
                    project="proj",
                    program="Program",
                    launch_cmd="/tmp/probe",
                    symbols="-[CodexProbe runWithInput:]",
                    binary="/tmp/probe",
                    function_inventory=function_inventory,
                    output_dir=report_dir,
                    include_decompile=True,
                    runner=fake_runner,
                )
                markdown = Path(result["markdown_report"]).read_text(encoding="utf-8")

        self.assertTrue(result["ok"])
        self.assertEqual(result["trace_status"], "ok")
        self.assertEqual(result["hit_count"], 1)
        self.assertEqual(result["runtime_hit_count"], 1)
        self.assertEqual(result["runtime_modules"][0]["name"], "Program")
        self.assertTrue(result["runtime_hits_json"].endswith("runtime_hits.json"))
        self.assertEqual(result["matched_function_count"], 1)
        self.assertTrue(any("ghidra_lldb_symbols" in command[0] for command in commands))
        self.assertTrue(any("ghidra_lldb_trace" in command[0] for command in commands))
        enrich.assert_called_once()
        self.assertEqual(enrich.call_args.kwargs["function_inventory_path"], function_inventory)

        self.assertIn("## Runtime Modules", markdown)
        self.assertIn("00000000-0000-0000-0000-000000000001", markdown)

    def test_validate_lldb_trace_normalizes_repeated_symbols_and_addresses(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            commands: list[list[str]] = []

            def fake_runner(command, cwd, timeout):
                commands.append(list(command))
                out_arg = next(arg for arg in command if arg.startswith("output="))
                Path(out_arg.split("=", 1)[1]).write_text(
                    json.dumps({"ok": True, "hit_count": 0, "hits": [], "breakpoints": []}),
                    encoding="utf-8",
                )
                return ProcessResult(0, "ok", "")

            validate_lldb_trace(
                project="proj",
                program="Program",
                launch_cmd="/tmp/probe",
                symbols=["FirstBoundary,SecondBoundary", " ThirdBoundary ", "SecondBoundary"],
                addresses=["0x1000", "0x2000, 0x1000"],
                output_dir=report_dir,
                runner=fake_runner,
            )

        trace_command = next(command for command in commands if any(arg.startswith("symbols=") for arg in command))
        self.assertIn("symbols=FirstBoundary,SecondBoundary,ThirdBoundary", trace_command)
        self.assertIn("addresses=0x1000,0x2000", trace_command)

    def test_validate_lldb_trace_passes_explicit_objc_description_registers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            commands: list[list[str]] = []

            def fake_runner(command, cwd, timeout):
                commands.append(list(command))
                out_arg = next(arg for arg in command if arg.startswith("output="))
                Path(out_arg.split("=", 1)[1]).write_text(
                    json.dumps({"ok": True, "hit_count": 0, "hits": [], "breakpoints": [{"hits": 0, "locs": 1}]}),
                    encoding="utf-8",
                )
                return ProcessResult(0, "ok", "")

            result = validate_lldb_trace(
                project="proj",
                program="Program",
                attach_pid="123",
                symbols="-[Demo run:]",
                output_dir=report_dir,
                objc_description_registers="x2, x2,x3",
                runner=fake_runner,
            )
            markdown = Path(result["markdown_report"]).read_text(encoding="utf-8")

        self.assertIn("capture_objc_args=true", commands[0])
        self.assertIn("objc_description_registers=x2,x3", commands[0])
        self.assertEqual(result["objc_description_registers"], ["x2", "x3"])
        self.assertIn("Objective-C descriptions: `x2,x3`", markdown)

    def test_validate_lldb_trace_surfaces_interior_boundary_recovery_seed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)

            def fake_runner(command, cwd, timeout):
                out_arg = next(arg for arg in command if arg.startswith("output="))
                Path(out_arg.split("=", 1)[1]).write_text(
                    json.dumps({"ok": True, "hit_count": 1, "hits": [{"pc": "0x1234", "symbol": "-[RemoteValue init:]"}], "breakpoints": [{"hits": 1}]}),
                    encoding="utf-8",
                )
                return ProcessResult(0, "ok", "")

            with patch(
                "cerberus_re_skill.modules.lldb_validation.enrich_lldb_trace",
                return_value={
                    "ok": True,
                    "output": str(report_dir / "enriched.json"),
                    "matched_function_count": 0,
                    "symbol_mismatch_count": 1,
                    "symbol_resolved_mismatch_count": 1,
                    "interior_boundary_mismatch_count": 1,
                },
            ):
                result = validate_lldb_trace(
                    project="proj",
                    program="Program",
                    attach_pid="123",
                    symbols="-[RemoteValue init:]",
                    output_dir=report_dir,
                    runner=fake_runner,
                )
            markdown = Path(result["markdown_report"]).read_text(encoding="utf-8")

        self.assertEqual(result["interior_boundary_mismatch_count"], 1)
        self.assertEqual(result["symbol_resolved_mismatch_count"], 1)
        self.assertIn("Symbol-resolved mismatches: 1", markdown)
        self.assertIn("Interior boundary mismatches: 1", markdown)
        self.assertIn(
            "Use symbol-resolved identity as a cross-check when address mapping lands in a neighboring function",
            result["next_work_items"],
        )
        self.assertIn(
            "Recover static function boundaries where runtime symbols land inside conflicting function bodies",
            result["next_work_items"],
        )

    def test_validate_lldb_trace_renders_slide_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)

            def fake_runner(command, cwd, timeout):
                out_arg = next(arg for arg in command if arg.startswith("output="))
                Path(out_arg.split("=", 1)[1]).write_text(
                    json.dumps(
                        {
                            "ok": True,
                            "hit_count": 1,
                            "hits": [{"pc": "0x5000", "symbol": "FirstBoundary"}],
                            "breakpoints": [{"hits": 1, "locs": 1}],
                        }
                    ),
                    encoding="utf-8",
                )
                return ProcessResult(0, "ok", "")

            with patch(
                "cerberus_re_skill.modules.lldb_validation.enrich_lldb_trace",
                return_value={
                    "ok": True,
                    "output": str(report_dir / "enriched.json"),
                    "matched_function_count": 1,
                    "slide_confidence": "conflicting",
                    "slide_conflict": True,
                    "slide_candidates": [
                        {
                            "slide": "0x4000",
                            "mapped_hit_count": 2,
                            "evidence_count": 2,
                            "runtime_hit_count": 1,
                            "symbols": ["FirstBoundary"],
                        }
                    ],
                },
            ):
                result = validate_lldb_trace(
                    project="proj",
                    program="Program",
                    attach_pid="123",
                    symbols="FirstBoundary",
                    output_dir=report_dir,
                    runner=fake_runner,
                )
            markdown = Path(result["markdown_report"]).read_text(encoding="utf-8")

        self.assertTrue(result["slide_conflict"])
        self.assertEqual(result["slide_candidates"][0]["slide"], "0x4000")
        self.assertIn("## Slide Candidates", markdown)
        self.assertIn("slide=`0x4000`", markdown)
        self.assertIn("symbols=FirstBoundary", markdown)

    def test_validate_lldb_trace_rejects_unknown_objc_description_register(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "x0 through x7"):
            validate_lldb_trace(
                project="proj",
                program="Program",
                attach_pid="123",
                symbols="-[Demo run:]",
                objc_description_registers="x8",
            )

    def test_validate_lldb_trace_classifies_attach_blocker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            def fake_runner(command, cwd, timeout):
                return ProcessResult(1, "", "error: attach failed: Operation not permitted")

            result = validate_lldb_trace(
                project="proj",
                program="Program",
                attach_name="ExampleApp",
                symbols="-[Demo run:]",
                output_dir=Path(tmp),
                runner=fake_runner,
            )

        self.assertTrue(result["ok"])
        self.assertEqual(result["trace_status"], "attach_blocked")
        self.assertIn("LLDB attach policy", result["next_work_items"][0])

    def test_validate_lldb_trace_classifies_breakpoints_no_hits(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)

            def fake_runner(command, cwd, timeout):
                out_arg = next(arg for arg in command if arg.startswith("output="))
                Path(out_arg.split("=", 1)[1]).write_text(
                    json.dumps({"ok": True, "hit_count": 0, "hits": [], "breakpoints": [{"hits": 0, "locs": 1}]}),
                    encoding="utf-8",
                )
                return ProcessResult(0, "ok", "")

            result = validate_lldb_trace(
                project="proj",
                program="Program",
                launch_cmd="/tmp/probe",
                symbols="-[Missing run:]",
                output_dir=report_dir,
                runner=fake_runner,
            )

        self.assertTrue(result["ok"])
        self.assertEqual(result["trace_status"], "breakpoints_no_hits")
        self.assertEqual(result["trace"]["resolved_breakpoint_locations"], 1)
        self.assertIn("trigger guidance", result["next_work_items"][0])

    def test_validate_lldb_trace_classifies_no_breakpoints(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)

            def fake_runner(command, cwd, timeout):
                out_arg = next(arg for arg in command if arg.startswith("output="))
                Path(out_arg.split("=", 1)[1]).write_text(
                    json.dumps({"ok": True, "hit_count": 0, "hits": [], "breakpoints": [{"hits": 0, "locs": 0}]}),
                    encoding="utf-8",
                )
                return ProcessResult(0, "ok", "zsh: terminated: 15 ( sleep 1 && kill -TERM 123 )")

            result = validate_lldb_trace(
                project="proj",
                program="Program",
                launch_cmd="/tmp/probe",
                symbols="-[Missing run:]",
                output_dir=report_dir,
                runner=fake_runner,
            )

        self.assertTrue(result["ok"])
        self.assertEqual(result["trace_status"], "no_breakpoints")
        self.assertEqual(result["trace"]["resolved_breakpoint_locations"], 0)
        self.assertIn("no breakpoint locations", result["next_work_items"][0])
        self.assertEqual(result["steps"][0]["stderr_tail"], "")

    def test_validate_lldb_trace_suggests_macho_c_export_aliases(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)

            def fake_runner(command, cwd, timeout):
                out_arg = next(arg for arg in command if arg.startswith("output="))
                Path(out_arg.split("=", 1)[1]).write_text(
                    json.dumps({"ok": True, "hit_count": 0, "hits": [], "breakpoints": [{"hits": 0, "locs": 0}]}),
                    encoding="utf-8",
                )
                return ProcessResult(0, "ok", "")

            result = validate_lldb_trace(
                project="proj",
                program="Program",
                launch_cmd="/tmp/probe",
                symbols="_AFGetGlobalState,_AFClientConnection",
                output_dir=report_dir,
                runner=fake_runner,
            )

        self.assertEqual(result["trace_status"], "no_breakpoints")
        self.assertTrue(any("without the leading underscore" in item for item in result["trigger_guidance"]))
        self.assertTrue(any("AFGetGlobalState" in item for item in result["trigger_guidance"]))

    def test_validate_lldb_trace_classifies_missing_marker_as_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)

            def fake_runner(command, cwd, timeout):
                out_arg = next(arg for arg in command if arg.startswith("output="))
                Path(out_arg.split("=", 1)[1]).write_text(
                    json.dumps(
                        {
                            "ok": True,
                            "warning": "GHIDRA_TRACE_BEGIN marker not found in LLDB output",
                            "hit_count": 0,
                            "hits": [],
                            "breakpoints": [],
                        }
                    ),
                    encoding="utf-8",
                )
                return ProcessResult(0, "LLDB trace complete", "")

            result = validate_lldb_trace(
                project="proj",
                program="Program",
                attach_name="BackgroundTaskRunner",
                symbols="-[ExampleIsolatedTaskRunner runToolWithInvocation:]",
                output_dir=report_dir,
                runner=fake_runner,
            )

        self.assertFalse(result["ok"])
        self.assertEqual(result["trace_status"], "trace_incomplete")
        self.assertIn("incomplete wait/trace lifecycle", result["trigger_guidance"][0])
        self.assertIn("wait/trace lifecycle failures", result["next_work_items"][0])

    def test_validate_lldb_trace_recovers_raw_timeout_breakpoint_preflight(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)

            def fake_runner(command, cwd, timeout):
                out_arg = next(arg for arg in command if arg.startswith("output="))
                Path(out_arg.split("=", 1)[1]).write_text(
                    json.dumps(
                        {
                            "ok": True,
                            "warning": "GHIDRA_TRACE_BEGIN marker not found in LLDB output",
                            "hit_count": 0,
                            "hits": [],
                            "breakpoints": [],
                            "raw_tail": (
                                "(lldb) breakpoint set --name \"-[Demo run:]\"\n"
                                "Breakpoint 1: where = Demo`-[Demo run:], address = 0x0000000100001234\n"
                                "(lldb) continue\n"
                            ),
                        }
                    ),
                    encoding="utf-8",
                )
                return ProcessResult(0, "LLDB trace complete", "")

            result = validate_lldb_trace(
                project="proj",
                program="Program",
                attach_pid="123",
                symbols="-[Demo run:]",
                output_dir=report_dir,
                runner=fake_runner,
            )
            persisted_trace = json.loads(Path(result["trace_json"]).read_text(encoding="utf-8"))
            markdown = Path(result["markdown_report"]).read_text(encoding="utf-8")

        self.assertTrue(result["ok"])
        self.assertEqual(result["trace_status"], "breakpoints_no_hits")
        self.assertEqual(result["trace"]["breakpoint_count"], 1)
        self.assertEqual(result["trace"]["resolved_breakpoint_locations"], 1)
        self.assertTrue(result["trace"]["breakpoint_preflight"]["breakpoints"][0]["summary"].startswith("where ="))
        self.assertTrue(result["trigger_guidance"])
        self.assertTrue(persisted_trace["breakpoint_preflight_recovered"])
        self.assertIn("Breakpoint Preflight", markdown)
        self.assertIn("Trigger Guidance", markdown)

    def test_validate_lldb_trace_recovers_partial_preflight_from_timeout_hits(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)

            def fake_runner(command, cwd, timeout):
                out_arg = next(arg for arg in command if arg.startswith("output="))
                Path(out_arg.split("=", 1)[1]).write_text(
                    json.dumps(
                        {
                            "ok": True,
                            "warning": "timeout: GHIDRA_TRACE_BEGIN not found but recovered 3 hits from sidecar",
                            "hit_count": 3,
                            "hits": [
                                {"pc": "0x1000", "symbol": "-[TriggerQueue enqueue:]"},
                                {"pc": "0x1000", "symbol": "-[TriggerQueue enqueue:]"},
                                {"pc": "0x2000", "symbol": "-[TriggerRunner run:]"},
                            ],
                            "breakpoints": [],
                        }
                    ),
                    encoding="utf-8",
                )
                return ProcessResult(0, "LLDB trace complete", "")

            with patch(
                "cerberus_re_skill.modules.lldb_validation.enrich_lldb_trace",
                return_value={"ok": True, "output": str(report_dir / "enriched.json"), "matched_function_count": 3},
            ):
                result = validate_lldb_trace(
                    project="proj",
                    program="Program",
                    attach_pid="123",
                    symbols="-[TriggerQueue enqueue:],-[TriggerRunner run:]",
                    output_dir=report_dir,
                    runner=fake_runner,
                )
            persisted_trace = json.loads(Path(result["trace_json"]).read_text(encoding="utf-8"))
            markdown = Path(result["markdown_report"]).read_text(encoding="utf-8")

        self.assertTrue(result["ok"])
        self.assertEqual(result["trace_status"], "ok")
        self.assertEqual(result["trace"]["breakpoint_count"], 2)
        self.assertEqual(result["trace"]["resolved_breakpoint_locations"], 2)
        self.assertEqual(result["trace"]["breakpoints_hit"], 2)
        self.assertTrue(result["trace"]["breakpoint_preflight_recovered"])
        self.assertTrue(result["trace"]["breakpoint_preflight_partial"])
        self.assertEqual(result["trace"]["breakpoint_preflight"]["breakpoints"][0]["hits"], 2)
        self.assertTrue(persisted_trace["breakpoint_preflight_partial"])
        self.assertIn("Partial recovery", markdown)

    def test_validate_lldb_trace_enriches_hit_preserving_timeout_as_partial(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)

            def fake_runner(command, cwd, timeout):
                out_arg = next(arg for arg in command if arg.startswith("output="))
                Path(out_arg.split("=", 1)[1]).write_text(
                    json.dumps(
                        {
                            "ok": True,
                            "hit_count": 2,
                            "hits": [
                                {"pc": "0x1000", "symbol": "-[Runner evaluate:]"},
                                {"pc": "0x2000", "symbol": "-[Runner finish:]"},
                            ],
                            "breakpoints": [{"hits": 2, "locs": 2}],
                        }
                    ),
                    encoding="utf-8",
                )
                return ProcessResult(124, "LLDB trace complete\n  Total hits: 2\n", "")

            with patch(
                "cerberus_re_skill.modules.lldb_validation.enrich_lldb_trace",
                return_value={
                    "ok": True,
                    "output": str(report_dir / "enriched.json"),
                    "matched_function_count": 1,
                    "address_mapped_function_count": 2,
                    "slide_confidence": "conflicting",
                    "slide_conflict": True,
                },
            ) as enrich:
                result = validate_lldb_trace(
                    project="proj",
                    program="Program",
                    attach_pid="123",
                    symbols="-[Runner evaluate:],-[Runner finish:]",
                    output_dir=report_dir,
                    runner=fake_runner,
                )
            markdown = Path(result["markdown_report"]).read_text(encoding="utf-8")

        self.assertFalse(result["ok"])
        self.assertEqual(result["trace_status"], "partial_timeout")
        self.assertEqual(result["hit_count"], 2)
        self.assertEqual(result["matched_function_count"], 1)
        self.assertEqual(result["address_mapped_function_count"], 2)
        self.assertTrue(result["slide_conflict"])
        self.assertIn("clean success", result["next_work_items"][0])
        self.assertIn("preserved runtime hits", result["trigger_guidance"][0])
        self.assertIn("Status: `partial_timeout`", markdown)
        enrich.assert_called_once()

    def test_validate_lldb_trace_preserves_durable_zero_hit_preflight_sentinels(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)

            def fake_runner(command, cwd, timeout):
                out_arg = next(arg for arg in command if arg.startswith("output="))
                Path(out_arg.split("=", 1)[1]).write_text(
                    json.dumps(
                        {
                            "ok": True,
                            "warning": "timeout: GHIDRA_TRACE_BEGIN not found but recovered 2 hits and full breakpoint preflight from sidecar",
                            "hit_count": 2,
                            "hits": [
                                {"pc": "0x1000", "symbol": "-[Runner evaluate:]"},
                                {"pc": "0x2000", "symbol": "-[Store record:]"},
                            ],
                            "breakpoints": [
                                {"id": 1, "locs": 1, "hits": 1, "source": "durable_preflight_sidecar", "requested": {"kind": "symbol", "value": "-[Runner evaluate:]"}},
                                {"id": 2, "locs": 1, "hits": 0, "source": "durable_preflight_sidecar", "requested": {"kind": "symbol", "value": "-[Evaluator deny:]"}},
                                {"id": 3, "locs": 1, "hits": 1, "source": "durable_preflight_sidecar", "requested": {"kind": "symbol", "value": "-[Store record:]"}},
                            ],
                            "breakpoint_preflight_recovered": True,
                            "breakpoint_preflight_source": "durable_preflight_sidecar",
                        }
                    ),
                    encoding="utf-8",
                )
                return ProcessResult(0, "LLDB trace complete", "")

            with patch(
                "cerberus_re_skill.modules.lldb_validation.enrich_lldb_trace",
                return_value={"ok": True, "output": str(report_dir / "enriched.json"), "matched_function_count": 2},
            ):
                result = validate_lldb_trace(
                    project="proj",
                    program="Program",
                    attach_pid="123",
                    symbols="-[Runner evaluate:],-[Evaluator deny:],-[Store record:]",
                    output_dir=report_dir,
                    runner=fake_runner,
                )
            markdown = Path(result["markdown_report"]).read_text(encoding="utf-8")

        self.assertTrue(result["ok"])
        self.assertEqual(result["trace_status"], "ok")
        self.assertEqual(result["trace"]["breakpoint_count"], 3)
        self.assertEqual(result["trace"]["resolved_breakpoint_locations"], 3)
        self.assertEqual(result["trace"]["breakpoints_hit"], 2)
        self.assertTrue(result["trace"]["breakpoint_preflight_recovered"])
        self.assertFalse(result["trace"]["breakpoint_preflight_partial"])
        self.assertEqual(result["trace"]["breakpoint_preflight_source"], "durable_preflight_sidecar")
        self.assertIn("complete breakpoint preflight", markdown)
        self.assertIn("-[Evaluator deny:]", markdown)

    def test_validate_lldb_trace_serializes_bytes_from_runner(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)

            def fake_runner(command, cwd, timeout):
                out_arg = next(arg for arg in command if arg.startswith("output="))
                Path(out_arg.split("=", 1)[1]).write_text(
                    json.dumps(
                        {
                            "ok": True,
                            "warning": "GHIDRA_TRACE_BEGIN marker not found in LLDB output",
                            "hit_count": 0,
                            "hits": [],
                            "breakpoints": [],
                        }
                    ),
                    encoding="utf-8",
                )
                return ProcessResult(0, b"LLDB trace complete", b"")

            result = validate_lldb_trace(
                project="proj",
                program="Program",
                attach_name="BackgroundTaskRunner",
                symbols="-[ExampleIsolatedTaskRunner runToolWithInvocation:]",
                output_dir=report_dir,
                runner=fake_runner,
            )
            persisted = json.loads(Path(result["json_report"]).read_text(encoding="utf-8"))

        self.assertFalse(result["ok"])
        self.assertEqual(result["trace_status"], "trace_incomplete")
        self.assertEqual(result["steps"][0]["stdout_tail"], "LLDB trace complete")
        self.assertEqual(persisted["steps"][0]["stdout_tail"], "LLDB trace complete")

    def test_validate_lldb_trace_marker_missing_with_raw_output_is_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)

            def fake_runner(command, cwd, timeout):
                out_arg = next(arg for arg in command if arg.startswith("output="))
                Path(out_arg.split("=", 1)[1]).write_text(
                    json.dumps(
                        {
                            "ok": True,
                            "warning": "GHIDRA_TRACE_BEGIN marker not found in LLDB output",
                            "raw_tail": "(lldb) breakpoint set --address 0x1000\nerror: invalid address",
                            "hit_count": 0,
                            "hits": [],
                            "breakpoints": [],
                        }
                    ),
                    encoding="utf-8",
                )
                return ProcessResult(0, "LLDB trace complete", "")

            result = validate_lldb_trace(
                project="proj",
                program="Program",
                attach_name="BackgroundTaskRunner",
                addresses="0x1000",
                output_dir=report_dir,
                runner=fake_runner,
            )
            markdown = Path(result["markdown_report"]).read_text(encoding="utf-8")

        self.assertFalse(result["ok"])
        self.assertEqual(result["trace_status"], "trace_incomplete")
        self.assertIn("LLDB Raw Tail", markdown)
        self.assertIn("error: invalid address", markdown)

    def test_validate_lldb_trace_tolerates_symbol_export_failure_when_addresses_resolve(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)

            def fake_runner(command, cwd, timeout):
                if "ghidra_lldb_symbols" in command[0]:
                    return ProcessResult(1, "", "binary not found")
                out_arg = next(arg for arg in command if arg.startswith("output="))
                Path(out_arg.split("=", 1)[1]).write_text(
                    json.dumps({"ok": True, "hit_count": 0, "hits": [], "breakpoints": [{"hits": 0, "locs": 1}]}),
                    encoding="utf-8",
                )
                return ProcessResult(0, "LLDB trace complete", "")

            result = validate_lldb_trace(
                project="proj",
                program="Program",
                attach_pid="123",
                addresses="1000",
                binary="/missing/binary",
                output_dir=report_dir,
                runner=fake_runner,
            )

        self.assertTrue(result["ok"])
        self.assertEqual(result["trace_status"], "breakpoints_no_hits")
        self.assertFalse(result["steps"][0]["ok"])
        self.assertEqual(result["steps"][0]["label"], "lldb symbols")
        self.assertEqual(result["trace"]["resolved_breakpoint_locations"], 1)

    def test_validate_lldb_trace_tolerates_symbol_export_failure_when_hits_exist(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)

            def fake_runner(command, cwd, timeout):
                if "ghidra_lldb_symbols" in command[0]:
                    return ProcessResult(1, "", "binary not found")
                out_arg = next(arg for arg in command if arg.startswith("output="))
                Path(out_arg.split("=", 1)[1]).write_text(
                    json.dumps(
                        {
                            "ok": True,
                            "hit_count": 1,
                            "hits": [{"pc": "0x1000", "symbol": "-[VCXPCServer listener:shouldAcceptNewConnection:]"}],
                            "breakpoints": [],
                        }
                    ),
                    encoding="utf-8",
                )
                return ProcessResult(0, "LLDB trace complete", "")

            with patch(
                "cerberus_re_skill.modules.lldb_validation.enrich_lldb_trace",
                return_value={"ok": True, "output": str(report_dir / "enriched.json"), "matched_function_count": 1},
            ):
                result = validate_lldb_trace(
                    project="proj",
                    program="Program",
                    attach_pid="123",
                    symbols="-[VCXPCServer listener:shouldAcceptNewConnection:]",
                    binary="/missing/ExampleClient",
                    output_dir=report_dir,
                    runner=fake_runner,
                )

        self.assertTrue(result["ok"])
        self.assertEqual(result["trace_status"], "ok")
        self.assertEqual(result["hit_count"], 1)
        self.assertFalse(result["steps"][0]["ok"])

    def test_validate_lldb_trace_guides_system_framework_stub_binary_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)

            def fake_runner(command, cwd, timeout):
                if "ghidra_lldb_symbols" in command[0]:
                    return ProcessResult(1, "", "binary not found")
                out_arg = next(arg for arg in command if arg.startswith("output="))
                Path(out_arg.split("=", 1)[1]).write_text(
                    json.dumps(
                        {
                            "ok": True,
                            "hit_count": 1,
                            "hits": [{"pc": "0x1000", "symbol": "+[Demo run]"}],
                            "breakpoints": [{"hits": 1}],
                        }
                    ),
                    encoding="utf-8",
                )
                return ProcessResult(0, "LLDB trace complete", "")

            with patch(
                "cerberus_re_skill.modules.lldb_validation.enrich_lldb_trace",
                return_value={"ok": True, "output": str(report_dir / "enriched.json"), "matched_function_count": 1},
            ):
                result = validate_lldb_trace(
                    project="proj",
                    program="Program",
                    launch_cmd="/tmp/probe",
                    symbols="+[Demo run]",
                    binary="/System/Library/PrivateFrameworks/Demo.framework/Demo",
                    output_dir=report_dir,
                    runner=fake_runner,
                )
            markdown = Path(result["markdown_report"]).read_text(encoding="utf-8")

        self.assertTrue(result["ok"])
        self.assertTrue(any("dyld-cache stubs" in item for item in result["trigger_guidance"]))
        self.assertIn("extracted dyld-cache binary", markdown)


if __name__ == "__main__":
    unittest.main()
