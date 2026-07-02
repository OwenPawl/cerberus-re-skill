import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cerberus_re_skill.modules.frida_validation import (
    recheck_runtime_attach,
    summarize_frida_console_events,
    validate_no_attach_scripts,
    write_frida_diagnostic_artifact,
)


class FridaValidationTests(unittest.TestCase):
    def test_diagnostic_artifact_marks_amfi_policy_blocker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with patch("cerberus_re_skill.modules.frida_validation.collect_frida_diagnostics") as diagnostics:
                from cerberus_re_skill.modules.frida_diagnostics import FridaDiagnostic

                diagnostics.return_value = [
                    FridaDiagnostic("WARN", "Frida helper policy", "amfi_get_out_of_my_way=1 is set"),
                ]
                report = write_frida_diagnostic_artifact(output_dir=tmp, runner=lambda _cmd, _timeout: {"returncode": 0})

            self.assertEqual(report["status"], "blocked-by-host-policy")
            self.assertTrue(report["runtime_attach_blocked"])
            self.assertTrue(Path(report["json_report"]).exists())

    def test_validate_no_attach_scripts_writes_syntax_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with patch("cerberus_re_skill.modules.frida_validation.shutil.which", return_value="/usr/bin/node"):
                report = validate_no_attach_scripts(
                    output_dir=tmp,
                    runner=lambda command, _timeout: {
                        "returncode": 0,
                        "stdout": "",
                        "stderr": "",
                        "command": [str(part) for part in command],
                    },
                )

            self.assertTrue(report["ok"])
            self.assertTrue((Path(tmp) / "frida_trace.js").exists())
            self.assertTrue((Path(tmp) / "frida_heap.js").exists())
            self.assertEqual(len(report["checks"]), 2)

    def test_runtime_recheck_is_skipped_without_explicit_allow(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = recheck_runtime_attach(target="/bin/echo", output_dir=tmp)

        self.assertTrue(report["ok"])
        self.assertEqual(report["status"], "skipped")

    def test_runtime_recheck_can_force_sudo_for_stable_frida_venv(self) -> None:
        commands = []

        def runner(command, _timeout):
            commands.append([str(part) for part in command])
            return {
                "returncode": 0,
                "stdout": (
                    'GHIDRA_FRIDA_HIT {"symbol":"-[CodexProbe runWithInput:]","pc":"0x1000"}\n'
                    'GHIDRA_FRIDA_RETURN {"symbol":"-[CodexProbe runWithInput:]","return_value":"0x2000"}\n'
                ),
                "stderr": "",
                "command": [str(part) for part in command],
            }

        with tempfile.TemporaryDirectory() as tmp:
            frida = "/opt/cerberus-re/frida-venv/bin/frida"
            with (
                patch("cerberus_re_skill.modules.frida_validation.known_frida_tool", return_value=frida),
                patch("cerberus_re_skill.modules.frida_validation.find_tool", return_value=None),
                patch.dict("os.environ", {"GHIDRA_RE_FRIDA_SUDO": "1"}),
            ):
                report = recheck_runtime_attach(
                    target="/bin/echo",
                    output_dir=tmp,
                    allow_runtime=True,
                    symbol="-[CodexProbe runWithInput:]",
                    capture_returns=True,
                    runner=runner,
                )
                runtime_payload = json.loads(Path(report["runtime_hits_json"]).read_text(encoding="utf-8"))

        self.assertTrue(report["ok"])
        self.assertEqual(commands[0][:3], ["sudo", "-n", "/opt/cerberus-re/frida-venv/bin/frida"])
        self.assertNotIn("--no-pause", commands[0])
        self.assertIn("-t", commands[0])
        self.assertEqual(report["symbol"], "-[CodexProbe runWithInput:]")
        self.assertTrue(report["capture_returns"])
        self.assertEqual(report["runtime_hit_count"], 2)
        self.assertEqual(runtime_payload["hit_count"], 2)
        self.assertEqual(runtime_payload["hits"][1]["event_type"], "objc-return")

    def test_runtime_recheck_accepts_multiple_objc_symbols(self) -> None:
        def runner(command, _timeout):
            return {
                "returncode": 0,
                "stdout": (
                    'GHIDRA_FRIDA_INSTALLED -[CodexProbe first]\n'
                    'GHIDRA_FRIDA_INSTALLED -[CodexProbe second]\n'
                    'GHIDRA_FRIDA_HIT {"symbol":"-[CodexProbe first]","pc":"0x1000"}\n'
                    'GHIDRA_FRIDA_HIT {"symbol":"-[CodexProbe second]","pc":"0x2000"}\n'
                ),
                "stderr": "",
                "command": [str(part) for part in command],
            }

        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch("cerberus_re_skill.modules.frida_validation.known_frida_tool", return_value="/usr/bin/frida"),
                patch("cerberus_re_skill.modules.frida_validation.find_tool", return_value=None),
            ):
                report = recheck_runtime_attach(
                    target="/bin/echo",
                    output_dir=tmp,
                    allow_runtime=True,
                    symbol=["-[CodexProbe first]", "-[CodexProbe second]"],
                    runner=runner,
                )
            script = (Path(tmp) / "frida_runtime_probe.js").read_text(encoding="utf-8")

        self.assertTrue(report["ok"])
        self.assertEqual(report["symbols"], ["-[CodexProbe first]", "-[CodexProbe second]"])
        self.assertEqual(report["frida_event_summary"]["installed_symbols"], ["-[CodexProbe first]", "-[CodexProbe second]"])
        self.assertIn('"symbol": "-[CodexProbe first]"', script)
        self.assertIn('"symbol": "-[CodexProbe second]"', script)

    def test_runtime_recheck_rejects_mixed_objc_symbol_and_native_hooks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(RuntimeError, r"--symbol cannot be combined with native hooks"):
                recheck_runtime_attach(
                    target="/bin/echo",
                    output_dir=tmp,
                    symbol=["+[DASession networkingAllowedWithUUID:error:]"],
                    native_symbols=["DeviceAccess!DAExtensionTypeToEntitlement"],
                )

    def test_runtime_recheck_rejects_mixed_objc_symbol_and_selector_hooks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(RuntimeError, r"--symbol cannot be combined with --selector"):
                recheck_runtime_attach(
                    target="/bin/echo",
                    output_dir=tmp,
                    symbol=["+[DASession networkingAllowedWithUUID:error:]"],
                    selectors=["networkingAllowedWithUUID:error:"],
                )

    def test_runtime_recheck_passes_target_args_and_records_readiness(self) -> None:
        commands = []

        def runner(command, _timeout):
            commands.append([str(part) for part in command])
            return {
                "returncode": 0,
                "stdout": (
                    "HARNESS_READY\n"
                    "GHIDRA_FRIDA_WAITING_CLASS CodexProbe\n"
                    "GHIDRA_FRIDA_INSTALLED -[CodexProbe runWithInput:]\n"
                    'GHIDRA_FRIDA_HIT {"symbol":"-[CodexProbe runWithInput:]","pc":"0x1000"}\n'
                ),
                "stderr": "",
                "command": [str(part) for part in command],
            }

        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch("cerberus_re_skill.modules.frida_validation.known_frida_tool", return_value="/usr/bin/frida"),
                patch("cerberus_re_skill.modules.frida_validation.find_tool", return_value=None),
            ):
                report = recheck_runtime_attach(
                    target="/bin/echo",
                    output_dir=tmp,
                    allow_runtime=True,
                    symbol="-[CodexProbe runWithInput:]",
                    target_args=["is.workflow.actions.nothing", "ghidra"],
                    readiness_marker="HARNESS_READY",
                    require_readiness_marker=True,
                    runner=runner,
                )

        self.assertTrue(report["ok"])
        self.assertEqual(report["target_args"], ["is.workflow.actions.nothing", "ghidra"])
        self.assertTrue(report["readiness_observed"])
        self.assertEqual(commands[0][-3:], ["--", "is.workflow.actions.nothing", "ghidra"])
        self.assertEqual(report["frida_event_summary"]["waiting_class_count"], 1)
        self.assertEqual(report["frida_event_summary"]["waiting_classes"], ["CodexProbe"])
        self.assertEqual(report["frida_event_summary"]["installed_symbols"], ["-[CodexProbe runWithInput:]"])

    def test_runtime_recheck_can_attach_pid_with_native_symbol(self) -> None:
        commands = []

        def runner(command, _timeout):
            commands.append([str(part) for part in command])
            return {
                "returncode": 124,
                "stdout": (
                    "GHIDRA_FRIDA_NATIVE_INSTALLED ExampleClient!_Demo 0x1000\n"
                    'GHIDRA_FRIDA_HIT {"event_type":"native-call","symbol":"_Demo","pc":"0x1000",'
                    '"args":{"x0":"0x1000"},'
                    '"native_arg_preview_mode":"best_effort_registers",'
                    '"native_arg_previews":{"x0":{"value":"0x1000","kind":"code_or_module_pointer"}}}\n'
                ),
                "stderr": "timed out",
                "command": [str(part) for part in command],
            }

        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch("cerberus_re_skill.modules.frida_validation.known_frida_tool", return_value="/usr/bin/frida"),
                patch("cerberus_re_skill.modules.frida_validation.find_tool", return_value=None),
            ):
                report = recheck_runtime_attach(
                    attach_pid=1234,
                    output_dir=tmp,
                    allow_runtime=True,
                    native_symbols=["ExampleClient!_Demo"],
                    capture_returns=True,
                    native_arg_preview=True,
                    runner=runner,
                )
                script = (Path(tmp) / "frida_runtime_probe.js").read_text(encoding="utf-8")
                runtime_payload = json.loads(Path(report["runtime_hits_json"]).read_text(encoding="utf-8"))

        self.assertTrue(report["ok"])
        self.assertEqual(report["attach_pid"], 1234)
        self.assertEqual(report["hook_mode"], "native")
        self.assertTrue(report["native_arg_preview"])
        self.assertTrue(report["trace"]["native_arg_preview"])
        self.assertEqual(commands[0][:3], ["/usr/bin/frida", "-p", "1234"])
        self.assertNotIn("-f", commands[0])
        self.assertIn("findExport", script)
        self.assertIn("symbolCandidates", script)
        self.assertIn("const nativeArgPreview = true;", script)
        self.assertIn("GHIDRA_FRIDA_NATIVE_INSTALLED", script)
        self.assertEqual(runtime_payload["hits"][0]["args"]["x0"], "0x1000")
        self.assertEqual(runtime_payload["hits"][0]["native_arg_preview_mode"], "best_effort_registers")
        self.assertEqual(runtime_payload["hits"][0]["native_arg_previews"]["x0"]["kind"], "code_or_module_pointer")
        self.assertEqual(report["runtime_hit_count"], 1)
        self.assertEqual(report["frida_event_summary"]["native_installed_count"], 1)
        self.assertEqual(report["frida_event_summary"]["native_installed"], ["ExampleClient!_Demo 0x1000"])

    def test_runtime_recheck_guides_short_lived_late_dlopen_native_hooks(self) -> None:
        def runner(command, _timeout):
            return {
                "returncode": 0,
                "stdout": (
                    'GHIDRA_FRIDA_ENV {"pid":123,"arch":"arm64","platform":"darwin","moduleCount":300}\n'
                    "loaded_path=/System/Library/PrivateFrameworks/ApplicationFirewall.framework/ApplicationFirewall\n"
                    "AFGetGlobalState.value=0\n"
                    "Process terminated\n"
                ),
                "stderr": "",
                "command": [str(part) for part in command],
            }

        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch("cerberus_re_skill.modules.frida_validation.known_frida_tool", return_value="/usr/bin/frida"),
                patch("cerberus_re_skill.modules.frida_validation.find_tool", return_value=None),
            ):
                report = recheck_runtime_attach(
                    target="/tmp/af_owned_probe",
                    output_dir=tmp,
                    allow_runtime=True,
                    native_symbols=["ApplicationFirewall!AFGetGlobalState"],
                    native_wait_seconds=5,
                    require_runtime_hit=True,
                    runner=runner,
                )
                markdown = Path(report["markdown_report"]).read_text(encoding="utf-8")

        self.assertFalse(report["ok"])
        self.assertEqual(report["status"], "blocked")
        self.assertEqual(report["frida_event_summary"]["native_installed_count"], 0)
        self.assertEqual(report["frida_event_summary"]["native_missing_count"], 0)
        self.assertTrue(any("post-dlopen readiness marker" in item for item in report["runtime_guidance"]))
        self.assertIn("Runtime Guidance", markdown)
        self.assertIn("not proof that the native export is absent", markdown)

    def test_runtime_recheck_guides_objc_waiting_classes_after_readiness(self) -> None:
        def runner(command, _timeout):
            return {
                "returncode": 0,
                "stdout": "ready_after_dlopen\nGHIDRA_FRIDA_WAITING_CLASS XProtectScan\n",
                "stderr": "",
                "command": [str(part) for part in command],
            }

        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch("cerberus_re_skill.modules.frida_validation.known_frida_tool", return_value="/usr/bin/frida"),
                patch("cerberus_re_skill.modules.frida_validation.find_tool", return_value=None),
            ):
                report = recheck_runtime_attach(
                    target="/bin/echo",
                    output_dir=tmp,
                    allow_runtime=True,
                    symbol="-[XProtectScan initWithURL:]",
                    readiness_marker="ready_after_dlopen",
                    require_readiness_marker=True,
                    require_runtime_hit=True,
                    runner=runner,
                )
                markdown = Path(report["markdown_report"]).read_text(encoding="utf-8")

        self.assertFalse(report["ok"])
        self.assertEqual(report["status"], "blocked")
        self.assertTrue(report["readiness_observed"])
        self.assertEqual(report["frida_event_summary"]["waiting_classes"], ["XProtectScan"])
        self.assertTrue(any("ObjC classes were still waiting" in item for item in report["runtime_guidance"]))
        self.assertIn("class-ready marker", markdown)
        self.assertIn("keep the target alive briefly", markdown)

    def test_runtime_recheck_records_native_zero_hit_targets(self) -> None:
        def runner(command, _timeout):
            return {
                "returncode": 0,
                "stdout": (
                    "GHIDRA_FRIDA_NATIVE_INSTALLED XPCDistributed!makeXPCSession 0x1000\n"
                    "GHIDRA_FRIDA_NATIVE_INSTALLED libswiftXPC.dylib!activate 0x2000\n"
                    'GHIDRA_FRIDA_HIT {"event_type":"native-call","symbol":"makeXPCSession",'
                    '"target":{"label":"XPCDistributed!makeXPCSession","symbol":"makeXPCSession"},'
                    '"pc":"0x1000"}\n'
                    'GHIDRA_FRIDA_RETURN {"event_type":"native-return","symbol":"makeXPCSession",'
                    '"target":{"label":"XPCDistributed!makeXPCSession","symbol":"makeXPCSession"},'
                    '"return_value":"0x3000"}\n'
                ),
                "stderr": "",
                "command": [str(part) for part in command],
            }

        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch("cerberus_re_skill.modules.frida_validation.known_frida_tool", return_value="/usr/bin/frida"),
                patch("cerberus_re_skill.modules.frida_validation.find_tool", return_value=None),
            ):
                report = recheck_runtime_attach(
                    attach_pid=1234,
                    output_dir=tmp,
                    allow_runtime=True,
                    native_symbols=["XPCDistributed!makeXPCSession", "libswiftXPC.dylib!activate"],
                    capture_returns=True,
                    runner=runner,
                )
                markdown = Path(report["markdown_report"]).read_text(encoding="utf-8")

        self.assertTrue(report["ok"])
        self.assertEqual(report["runtime_hit_count"], 2)
        self.assertEqual(
            report["native_target_hits"],
            [
                {
                    "label": "XPCDistributed!makeXPCSession",
                    "installed": True,
                    "address": "0x1000",
                    "call_count": 1,
                    "return_count": 1,
                    "hit_count": 2,
                },
                {
                    "label": "libswiftXPC.dylib!activate",
                    "installed": True,
                    "address": "0x2000",
                    "call_count": 0,
                    "return_count": 0,
                    "hit_count": 0,
                },
            ],
        )
        self.assertEqual(report["native_zero_hit_targets"], ["libswiftXPC.dylib!activate"])
        self.assertEqual(report["native_unqualified_zero_hit_targets"], [])
        self.assertFalse(any("Module!symbol" in item for item in report["runtime_guidance"]))
        self.assertIn("### Native Target Hits", markdown)
        self.assertIn("Installed zero-hit targets", markdown)

    def test_runtime_recheck_guides_unqualified_native_zero_hit_targets(self) -> None:
        def runner(command, _timeout):
            return {
                "returncode": 0,
                "stdout": "GHIDRA_FRIDA_NATIVE_INSTALLED amfi_restricted_execution_mode_status 0x183cd9054\n",
                "stderr": "",
                "command": [str(part) for part in command],
            }

        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch("cerberus_re_skill.modules.frida_validation.known_frida_tool", return_value="/usr/bin/frida"),
                patch("cerberus_re_skill.modules.frida_validation.find_tool", return_value=None),
            ):
                report = recheck_runtime_attach(
                    target="/bin/echo",
                    output_dir=tmp,
                    allow_runtime=True,
                    native_symbols=["amfi_restricted_execution_mode_status"],
                    capture_returns=True,
                    runner=runner,
                )
                markdown = Path(report["markdown_report"]).read_text(encoding="utf-8")

        self.assertTrue(report["ok"])
        self.assertEqual(report["native_zero_hit_targets"], ["amfi_restricted_execution_mode_status"])
        self.assertEqual(report["native_unqualified_zero_hit_targets"], ["amfi_restricted_execution_mode_status"])
        self.assertTrue(any("Module!symbol" in item for item in report["runtime_guidance"]))
        self.assertIn("Module!symbol", markdown)

    def test_runtime_recheck_records_native_missing_targets(self) -> None:
        def runner(command, _timeout):
            return {
                "returncode": 0,
                "stdout": (
                    "GHIDRA_FRIDA_NATIVE_MISSING XPCDistributed!Receiver.init\n"
                    "GHIDRA_FRIDA_NATIVE_INSTALLED XPCDistributed!makeXPCSession 0x1000\n"
                ),
                "stderr": "",
                "command": [str(part) for part in command],
            }

        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch("cerberus_re_skill.modules.frida_validation.known_frida_tool", return_value="/usr/bin/frida"),
                patch("cerberus_re_skill.modules.frida_validation.find_tool", return_value=None),
            ):
                report = recheck_runtime_attach(
                    attach_pid=1234,
                    output_dir=tmp,
                    allow_runtime=True,
                    native_symbols=["XPCDistributed!Receiver.init", "XPCDistributed!makeXPCSession"],
                    capture_returns=True,
                    runner=runner,
                )
                markdown = Path(report["markdown_report"]).read_text(encoding="utf-8")

        self.assertTrue(report["ok"])
        self.assertEqual(report["frida_event_summary"]["native_missing_count"], 1)
        self.assertEqual(report["native_missing_targets"], ["XPCDistributed!Receiver.init"])
        self.assertEqual(report["native_zero_hit_targets"], ["XPCDistributed!makeXPCSession"])
        self.assertIn("Missing native targets", markdown)
        self.assertIn("Installed zero-hit targets", markdown)

    def test_runtime_recheck_records_native_wait_seconds(self) -> None:
        def runner(command, _timeout):
            return {
                "returncode": 0,
                "stdout": (
                    "GHIDRA_FRIDA_NATIVE_INSTALLED _LateLoaded 0x1000\n"
                    'GHIDRA_FRIDA_HIT {"event_type":"native-call","symbol":"_LateLoaded","pc":"0x1000"}\n'
                ),
                "stderr": "",
                "command": [str(part) for part in command],
            }

        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch("cerberus_re_skill.modules.frida_validation.known_frida_tool", return_value="/usr/bin/frida"),
                patch("cerberus_re_skill.modules.frida_validation.find_tool", return_value=None),
            ):
                report = recheck_runtime_attach(
                    target="/bin/echo",
                    output_dir=tmp,
                    allow_runtime=True,
                    native_symbols=["_LateLoaded"],
                    native_wait_seconds=3.0,
                    require_runtime_hit=True,
                    runner=runner,
                )
                script = (Path(tmp) / "frida_runtime_probe.js").read_text(encoding="utf-8")

        self.assertTrue(report["ok"])
        self.assertEqual(report["native_wait_seconds"], 3.0)
        self.assertEqual(report["trace"]["native_wait_seconds"], 3.0)
        self.assertIn("const nativeWaitMs = 3000;", script)
        self.assertEqual(report["frida_event_summary"]["native_installed_count"], 1)

    def test_runtime_recheck_can_attach_pid_with_selector_wide_hooks(self) -> None:
        commands = []

        def runner(command, _timeout):
            commands.append([str(part) for part in command])
            return {
                "returncode": 124,
                "stdout": (
                    "GHIDRA_FRIDA_SELECTOR_INSTALLED -[ExampleProbe runDescriptorForSurface:]\n"
                    "GHIDRA_FRIDA_SELECTOR_ENUM_ERROR Error: undecodable class name\n"
                    'GHIDRA_FRIDA_HIT {"event_type":"objc-call","symbol":"-[ExampleProbe runDescriptorForSurface:]","selector":"runDescriptorForSurface:","pc":"0x1000"}\n'
                ),
                "stderr": "timed out",
                "command": [str(part) for part in command],
            }

        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch("cerberus_re_skill.modules.frida_validation.known_frida_tool", return_value="/usr/bin/frida"),
                patch("cerberus_re_skill.modules.frida_validation.find_tool", return_value=None),
            ):
                report = recheck_runtime_attach(
                    attach_pid=1234,
                    output_dir=tmp,
                    allow_runtime=True,
                    selectors=["runDescriptorForSurface:"],
                    class_filters=["WF"],
                    max_selector_hooks=8,
                    runner=runner,
                )
                script = (Path(tmp) / "frida_runtime_probe.js").read_text(encoding="utf-8")
                markdown = Path(report["markdown_report"]).read_text(encoding="utf-8")

        self.assertTrue(report["ok"])
        self.assertEqual(report["hook_mode"], "objc-selector")
        self.assertEqual(report["selectors"], ["runDescriptorForSurface:"])
        self.assertEqual(report["class_filters"], ["WF"])
        self.assertEqual(report["max_selector_hooks"], 8)
        self.assertEqual(commands[0][:3], ["/usr/bin/frida", "-p", "1234"])
        self.assertIn("GHIDRA_FRIDA_SELECTOR_INSTALLED", script)
        self.assertEqual(report["runtime_hit_count"], 1)
        self.assertEqual(report["frida_event_summary"]["selector_installed_count"], 1)
        self.assertEqual(
            report["frida_event_summary"]["selector_installed"],
            ["-[ExampleProbe runDescriptorForSurface:]"],
        )
        self.assertEqual(report["frida_event_summary"]["selector_enumeration_error_count"], 1)
        self.assertIn("- Installed hooks: `1`", markdown)

    def test_runtime_recheck_records_selector_no_match_alongside_installed_hooks(self) -> None:
        def runner(command, _timeout):
            return {
                "returncode": 0,
                "stdout": (
                    "GHIDRA_FRIDA_SELECTOR_INSTALLED -[ExampleProbe runDescriptorForSurface:]\n"
                    "GHIDRA_FRIDA_SELECTOR_NO_MATCH fireTriggerWithIdentifier:force:completion:\n"
                    'GHIDRA_FRIDA_HIT {"event_type":"objc-call","symbol":"-[ExampleProbe runDescriptorForSurface:]","selector":"runDescriptorForSurface:","pc":"0x1000"}\n'
                ),
                "stderr": "",
                "command": [str(part) for part in command],
            }

        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch("cerberus_re_skill.modules.frida_validation.known_frida_tool", return_value="/usr/bin/frida"),
                patch("cerberus_re_skill.modules.frida_validation.find_tool", return_value=None),
            ):
                report = recheck_runtime_attach(
                    target="/bin/echo",
                    output_dir=tmp,
                    allow_runtime=True,
                    selectors=["runDescriptorForSurface:", "fireTriggerWithIdentifier:force:completion:"],
                    class_filters=["WF"],
                    runner=runner,
                )

        self.assertTrue(report["ok"])
        self.assertEqual(report["runtime_hit_count"], 1)
        self.assertEqual(report["frida_event_summary"]["selector_installed_count"], 1)
        self.assertEqual(report["frida_event_summary"]["selector_no_match_count"], 1)
        self.assertEqual(
            report["frida_event_summary"]["selector_no_match"],
            ["fireTriggerWithIdentifier:force:completion:"],
        )

    def test_runtime_recheck_exact_classes_avoid_global_selector_enumeration(self) -> None:
        def runner(command, _timeout):
            return {
                "returncode": 0,
                "stdout": (
                    "GHIDRA_FRIDA_SELECTOR_INSTALLED -[ExampleProbe runDescriptorForSurface:]\n"
                    'GHIDRA_FRIDA_HIT {"event_type":"objc-call","symbol":"-[ExampleProbe runDescriptorForSurface:]","selector":"runDescriptorForSurface:","pc":"0x1000"}\n'
                ),
                "stderr": "",
                "command": [str(part) for part in command],
            }

        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch("cerberus_re_skill.modules.frida_validation.known_frida_tool", return_value="/usr/bin/frida"),
                patch("cerberus_re_skill.modules.frida_validation.find_tool", return_value=None),
            ):
                report = recheck_runtime_attach(
                    attach_pid=1234,
                    output_dir=tmp,
                    allow_runtime=True,
                    selectors=["runDescriptorForSurface:"],
                    exact_classes=["ExampleProbe"],
                    require_runtime_hit=True,
                    runner=runner,
                )
                script = (Path(tmp) / "frida_runtime_probe.js").read_text(encoding="utf-8")

        self.assertTrue(report["ok"])
        self.assertEqual(report["exact_classes"], ["ExampleProbe"])
        self.assertEqual(report["class_filters"], [])
        self.assertEqual(report["frida_event_summary"]["selector_enumeration_error_count"], 0)
        self.assertIn('const exactClasses = [\n  "ExampleProbe"\n];', script)
        self.assertIn("classFilters.length > 0 || exactClasses.length === 0", script)

    def test_runtime_recheck_can_await_spawn_with_selector_wide_hooks(self) -> None:
        commands = []

        def runner(command, _timeout):
            commands.append([str(part) for part in command])
            return {
                "returncode": 124,
                "stdout": (
                    "Handling: Spawn(pid=42, identifier=\"/System/Thing\")\n"
                    "GHIDRA_FRIDA_SELECTOR_INSTALLED -[ExampleProbe runToolWithInvocation:]\n"
                ),
                "stderr": "timed out",
                "command": [str(part) for part in command],
            }

        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch("cerberus_re_skill.modules.frida_validation.known_frida_tool", return_value="/usr/bin/frida"),
                patch("cerberus_re_skill.modules.frida_validation.find_tool", return_value=None),
            ):
                report = recheck_runtime_attach(
                    await_regex=".*BackgroundTaskRunner.*",
                    output_dir=tmp,
                    allow_runtime=True,
                    selectors=["runToolWithInvocation:"],
                    class_filters=["WF"],
                    runner=runner,
                )

        self.assertTrue(report["ok"])
        self.assertEqual(report["await_regex"], ".*BackgroundTaskRunner.*")
        self.assertEqual(commands[0][:3], ["/usr/bin/frida", "-W", ".*BackgroundTaskRunner.*"])
        self.assertNotIn("-p", commands[0])
        self.assertNotIn("-f", commands[0])
        self.assertEqual(report["frida_event_summary"]["selector_installed_count"], 1)

    def test_runtime_recheck_can_require_runtime_hit(self) -> None:
        def runner(command, _timeout):
            return {
                "returncode": 124,
                "stdout": "GHIDRA_FRIDA_SELECTOR_INSTALLED -[ExampleProbe runToolWithInvocation:]\n",
                "stderr": "timed out",
                "command": [str(part) for part in command],
            }

        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch("cerberus_re_skill.modules.frida_validation.known_frida_tool", return_value="/usr/bin/frida"),
                patch("cerberus_re_skill.modules.frida_validation.find_tool", return_value=None),
            ):
                report = recheck_runtime_attach(
                    attach_pid=1234,
                    output_dir=tmp,
                    allow_runtime=True,
                    selectors=["runToolWithInvocation:"],
                    class_filters=["WF"],
                    require_runtime_hit=True,
                    runner=runner,
                )

        self.assertFalse(report["ok"])
        self.assertEqual(report["status"], "no-runtime-hits")
        self.assertTrue(report["require_runtime_hit"])
        self.assertEqual(report["runtime_hit_count"], 0)
        self.assertEqual(report["frida_event_summary"]["selector_installed_count"], 1)
        self.assertTrue(report["hook_installation_observed"])

    def test_runtime_recheck_guides_installed_objc_zero_hits_on_short_lived_target(self) -> None:
        def runner(command, _timeout):
            return {
                "returncode": 0,
                "stdout": (
                    "Spawned `/tmp/btm_dump_owned`. Resuming main thread!\n"
                    "GHIDRA_FRIDA_SELECTOR_INSTALLED -[BTMManager dumpDatabaseWithAuthorization:error:]\n"
                    "Process terminated\n"
                ),
                "stderr": "",
                "command": [str(part) for part in command],
            }

        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch("cerberus_re_skill.modules.frida_validation.known_frida_tool", return_value="/usr/bin/frida"),
                patch("cerberus_re_skill.modules.frida_validation.find_tool", return_value=None),
            ):
                report = recheck_runtime_attach(
                    target="/tmp/btm_dump_owned",
                    output_dir=tmp,
                    allow_runtime=True,
                    selectors=["dumpDatabaseWithAuthorization:error:"],
                    exact_classes=["BTMManager"],
                    require_runtime_hit=True,
                    runner=runner,
                )
                markdown = Path(report["markdown_report"]).read_text(encoding="utf-8")

        self.assertFalse(report["ok"])
        self.assertEqual(report["status"], "no-runtime-hits")
        self.assertEqual(report["frida_event_summary"]["selector_installed_count"], 1)
        self.assertTrue(any("readiness marker" in item for item in report["runtime_guidance"]))
        self.assertTrue(any("delay briefly" in item for item in report["runtime_guidance"]))
        self.assertIn("Runtime Guidance", markdown)
        self.assertIn("short-lived owned probes", markdown)

    def test_runtime_recheck_preserves_hit_then_target_fatal_as_failure(self) -> None:
        def runner(command, _timeout):
            return {
                "returncode": 0,
                "stdout": (
                    "READINESS\n"
                    "target-output-without-newline GHIDRA_FRIDA_INSTALLED -[RemoteValue init:]\n"
                    'GHIDRA_FRIDA_HIT {"event_type":"objc-call","symbol":"-[RemoteValue init:]","pc":"0x1000"}\n'
                ),
                "stderr": "Fatal error: Use of unimplemented initializer for class RemoteValue\n",
                "command": [str(part) for part in command],
            }

        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch("cerberus_re_skill.modules.frida_validation.known_frida_tool", return_value="/usr/bin/frida"),
                patch("cerberus_re_skill.modules.frida_validation.find_tool", return_value=None),
            ):
                report = recheck_runtime_attach(
                    target="/bin/echo",
                    output_dir=tmp,
                    allow_runtime=True,
                    symbol="-[RemoteValue init:]",
                    readiness_marker="READINESS",
                    require_readiness_marker=True,
                    require_runtime_hit=True,
                    runner=runner,
                )
                markdown = Path(report["markdown_report"]).read_text(encoding="utf-8")

        self.assertFalse(report["ok"])
        self.assertEqual(report["status"], "target-failed-after-runtime-hit")
        self.assertTrue(report["hook_installation_observed"])
        self.assertTrue(report["hook_installation_inferred_from_hits"])
        self.assertTrue(report["target_failure_observed"])
        self.assertEqual(report["runtime_hit_count"], 1)
        self.assertIn("Target failure observed: `True`", markdown)

    def test_runtime_recheck_preserves_prehook_attach_failure_as_blocked(self) -> None:
        def runner(command, _timeout):
            return {
                "returncode": 1,
                "stdout": "Failed to enable spawn gating: spawn gating requires additional privileges\n",
                "stderr": "",
                "command": [str(part) for part in command],
            }

        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch("cerberus_re_skill.modules.frida_validation.known_frida_tool", return_value="/usr/bin/frida"),
                patch("cerberus_re_skill.modules.frida_validation.find_tool", return_value=None),
            ):
                report = recheck_runtime_attach(
                    await_regex="BackgroundTaskRunner",
                    output_dir=tmp,
                    allow_runtime=True,
                    selectors=["workflowControllerWillRun:"],
                    class_filters=["ExampleBackgroundTaskRunner"],
                    require_runtime_hit=True,
                    runner=runner,
                )
                markdown = Path(report["markdown_report"]).read_text(encoding="utf-8")

        self.assertFalse(report["ok"])
        self.assertEqual(report["status"], "blocked")
        self.assertFalse(report["hook_installation_observed"])
        self.assertEqual(report["runtime_hit_count"], 0)
        self.assertIn("### Frida stdout tail", markdown)
        self.assertIn("spawn gating requires additional privileges", markdown)

    def test_runtime_recheck_can_wait_for_attach_name(self) -> None:
        commands = []

        def runner(command, _timeout):
            command = [str(part) for part in command]
            commands.append(command)
            if command[:3] == ["ps", "-axo", "pid=,command="]:
                return {
                    "returncode": 0,
                    "stdout": "1234 /System/XPCServices/BackgroundTaskRunner\n",
                    "stderr": "",
                    "command": command,
                }
            return {
                "returncode": 124,
                "stdout": (
                    "GHIDRA_FRIDA_SELECTOR_INSTALLED -[ExampleBackgroundTaskRunner listener:shouldAcceptNewConnection:]\n"
                    'GHIDRA_FRIDA_HIT {"event_type":"objc-call","symbol":"-[ExampleBackgroundTaskRunner listener:shouldAcceptNewConnection:]","pc":"0x1000"}\n'
                ),
                "stderr": "timed out",
                "command": command,
            }

        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch("cerberus_re_skill.modules.frida_validation.known_frida_tool", return_value="/usr/bin/frida"),
                patch("cerberus_re_skill.modules.frida_validation.find_tool", return_value=None),
            ):
                report = recheck_runtime_attach(
                    attach_name="BackgroundTaskRunner",
                    output_dir=tmp,
                    allow_runtime=True,
                    selectors=["listener:shouldAcceptNewConnection:"],
                    class_filters=["ExampleBackgroundTaskRunner"],
                    runner=runner,
                )

        self.assertTrue(report["ok"])
        self.assertEqual(report["attach_name"], "BackgroundTaskRunner")
        self.assertEqual(report["attach_pid"], 1234)
        self.assertEqual(report["resolved_attach_pid"], 1234)
        self.assertEqual(commands[0][:3], ["ps", "-axo", "pid=,command="])
        self.assertEqual(commands[1][:3], ["/usr/bin/frida", "-p", "1234"])
        self.assertEqual(report["runtime_hit_count"], 1)

    def test_runtime_recheck_attach_name_timeout_records_blocker(self) -> None:
        commands = []

        def runner(command, _timeout):
            command = [str(part) for part in command]
            commands.append(command)
            return {"returncode": 0, "stdout": "", "stderr": "", "command": command}

        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch("cerberus_re_skill.modules.frida_validation.known_frida_tool", return_value="/usr/bin/frida"),
                patch("cerberus_re_skill.modules.frida_validation.find_tool", return_value=None),
            ):
                report = recheck_runtime_attach(
                    attach_name="BackgroundTaskRunner",
                    output_dir=tmp,
                    allow_runtime=True,
                    selectors=["listener:shouldAcceptNewConnection:"],
                    timeout_seconds=0.1,
                    runner=runner,
                )

        self.assertFalse(report["ok"])
        self.assertEqual(report["status"], "blocked")
        self.assertIsNone(report["resolved_attach_pid"])
        self.assertIn("timed out waiting for process", report["result"]["stderr"])
        self.assertEqual(commands[0][:3], ["ps", "-axo", "pid=,command="])

    def test_runtime_recheck_await_spawn_records_blocker(self) -> None:
        def runner(command, _timeout):
            return {
                "returncode": 1,
                "stdout": 'Handling: Spawn(pid=42, identifier="/System/Thing")\n',
                "stderr": 'Failed to handle spawn: module not found at "/usr/lib/libSystem.B.dylib"',
                "command": [str(part) for part in command],
            }

        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch("cerberus_re_skill.modules.frida_validation.known_frida_tool", return_value="/usr/bin/frida"),
                patch("cerberus_re_skill.modules.frida_validation.find_tool", return_value=None),
            ):
                report = recheck_runtime_attach(
                    await_regex=".*BackgroundTaskRunner.*",
                    output_dir=tmp,
                    allow_runtime=True,
                    selectors=["runToolWithInvocation:"],
                    class_filters=["WF"],
                    runner=runner,
                )

        self.assertFalse(report["ok"])
        self.assertEqual(report["status"], "blocked")
        self.assertIn("module not found", report["result"]["stderr"])

    def test_required_readiness_marker_can_block_recheck(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch("cerberus_re_skill.modules.frida_validation.known_frida_tool", return_value="/usr/bin/frida"),
                patch("cerberus_re_skill.modules.frida_validation.find_tool", return_value=None),
            ):
                report = recheck_runtime_attach(
                    target="/bin/echo",
                    output_dir=tmp,
                    allow_runtime=True,
                    readiness_marker="READY",
                    require_readiness_marker=True,
                    runner=lambda command, _timeout: {
                        "returncode": 0,
                        "stdout": "",
                        "stderr": "",
                        "command": [str(part) for part in command],
                    },
                )

        self.assertFalse(report["ok"])
        self.assertEqual(report["status"], "blocked")
        self.assertFalse(report["readiness_observed"])

    def test_frida_console_event_summary_dedupes_values(self) -> None:
        summary = summarize_frida_console_events(
            "\n".join(
                [
                    "GHIDRA_FRIDA_WAITING_CLASS ExampleNoopAction",
                    "GHIDRA_FRIDA_WAITING_CLASS ExampleNoopAction",
                    "GHIDRA_FRIDA_INSTALLED -[ExampleNoopAction runWithInput:error:]",
                    "GHIDRA_FRIDA_SELECTOR_INSTALLED -[ExampleProbe runDescriptorForSurface:]",
                    'GHIDRA_FRIDA_SELECTOR_ALIAS {"symbol":"+[ExampleProbe runDescriptorForSurface:]","primary_symbol":"-[ExampleProbe runDescriptorForSurface:]"}',
                    "GHIDRA_FRIDA_SELECTOR_ENUM_ERROR Error: undecodable class name",
                    "GHIDRA_FRIDA_MISSING_METHOD -[Missing nope]",
                    "GHIDRA_FRIDA_MISSING_CLASS MissingClass",
                ]
            )
        )

        self.assertEqual(summary["waiting_class_count"], 2)
        self.assertEqual(summary["waiting_classes"], ["ExampleNoopAction"])
        self.assertEqual(summary["installed_count"], 1)
        self.assertEqual(summary["selector_installed_count"], 1)
        self.assertEqual(summary["selector_installed"], ["-[ExampleProbe runDescriptorForSurface:]"])
        self.assertEqual(summary["selector_alias_count"], 1)
        self.assertEqual(
            summary["selector_aliases"],
            ['{"symbol":"+[ExampleProbe runDescriptorForSurface:]","primary_symbol":"-[ExampleProbe runDescriptorForSurface:]"}'],
        )
        self.assertEqual(summary["selector_enumeration_error_count"], 1)
        self.assertEqual(summary["selector_enumeration_errors"], ["Error: undecodable class name"])
        self.assertEqual(summary["missing_method_count"], 1)
        self.assertEqual(summary["missing_classes"], ["MissingClass"])


if __name__ == "__main__":
    unittest.main()
