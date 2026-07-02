import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cerberus_re_skill.modules.frida_diagnostics import ProbeResult, collect_frida_diagnostics


class FridaDiagnosticsTests(unittest.TestCase):
    def test_warns_when_frida_tools_are_missing(self) -> None:
        entries = collect_frida_diagnostics(
            tool_finder=lambda _name: None,
            runner=lambda _cmd: ProbeResult(1, "", "No module named frida"),
            known_tool_finder=lambda _name: None,
            platform_name="darwin",
            machine="arm64",
            amfi_enabled=lambda: False,
        )

        by_label = {entry.label: entry for entry in entries}
        self.assertEqual(by_label["Frida CLI"].level, "WARN")
        self.assertIn("not found", by_label["Frida CLI"].value)
        self.assertEqual(by_label["Frida Python module"].level, "WARN")
        self.assertEqual(by_label["frida-ps local probe"].level, "WARN")
        self.assertEqual(by_label["DevToolsSecurity"].level, "WARN")

    def test_reports_devtools_target_signing_and_amfi_policy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "Probe"
            target.write_text("fixture", encoding="utf-8")

            def tool_finder(name: str) -> str | None:
                return {
                    "frida": "/opt/frida/bin/frida",
                    "frida-ps": "/opt/frida/bin/frida-ps",
                    "python3": "/usr/bin/python3",
                    "DevToolsSecurity": "/usr/sbin/DevToolsSecurity",
                    "codesign": "/usr/bin/codesign",
                }.get(name)

            def runner(cmd: list[str] | tuple[str, ...]) -> ProbeResult:
                if cmd[:2] == ["/opt/frida/bin/frida", "--version"]:
                    return ProbeResult(0, "17.9.1\n", "")
                if cmd[:3] == ["/usr/bin/python3", "-c", "import frida; print(getattr(frida, '__version__', 'unknown'))"]:
                    return ProbeResult(0, "17.9.1\n", "")
                if cmd == ["/opt/frida/bin/frida-ps"]:
                    return ProbeResult(0, "PID  Name\n", "")
                if cmd == ["/usr/sbin/DevToolsSecurity", "-status"]:
                    return ProbeResult(0, "Developer mode is currently disabled.\n", "")
                if cmd[:2] == ["/usr/bin/codesign", "-dv"]:
                    return ProbeResult(1, "", "code object is not signed at all")
                raise AssertionError(f"unexpected command: {cmd!r}")

            missing_venv = Path(tmp) / "missing-frida-venv"
            missing_sudoers = Path(tmp) / "missing-sudoers"
            with (
                patch("cerberus_re_skill.modules.frida_diagnostics.DEFAULT_FRIDA_VENV", missing_venv),
                patch("cerberus_re_skill.modules.frida_diagnostics.SUDOERS_FILE", missing_sudoers),
            ):
                entries = collect_frida_diagnostics(
                    target,
                    tool_finder=tool_finder,
                    runner=runner,
                    known_tool_finder=lambda _name: None,
                    platform_name="darwin",
                    machine="arm64",
                    amfi_enabled=lambda: True,
                )

        by_label = {entry.label: entry for entry in entries}
        self.assertEqual(by_label["Frida CLI"].level, "OK")
        self.assertEqual(by_label["frida-ps local probe"].level, "OK")
        self.assertIn("developer mode disabled", by_label["DevToolsSecurity"].value)
        self.assertIn("AMFI workaround incomplete", by_label["Frida helper policy"].value)
        self.assertIn("unsigned", by_label["Frida target signing"].value)

    def test_reports_ok_when_amfi_workaround_is_active(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            venv = Path(tmp) / "frida-venv"
            bin_dir = venv / "bin"
            bin_dir.mkdir(parents=True)
            frida_ps = bin_dir / "frida-ps"
            frida_ps.write_text("#!/bin/sh\n", encoding="utf-8")
            sudoers = Path(tmp) / "cerberus-re-frida"
            sudoers.write_text("fixture", encoding="utf-8")

            def runner(cmd: list[str] | tuple[str, ...]) -> ProbeResult:
                if cmd == ["sudo", "-n", str(frida_ps)]:
                    return ProbeResult(0, "PID  Name\n", "")
                if cmd == ["/usr/sbin/DevToolsSecurity", "-status"]:
                    return ProbeResult(0, "Developer mode is currently enabled.\n", "")
                return ProbeResult(0, "ok\n", "")

            with (
                patch("cerberus_re_skill.modules.frida_diagnostics.DEFAULT_FRIDA_VENV", venv),
                patch("cerberus_re_skill.modules.frida_diagnostics.SUDOERS_FILE", sudoers),
            ):
                entries = collect_frida_diagnostics(
                    tool_finder=lambda name: {
                        "python3": "/usr/bin/python3",
                        "DevToolsSecurity": "/usr/sbin/DevToolsSecurity",
                    }.get(name),
                    runner=runner,
                    known_tool_finder=lambda _name: None,
                    platform_name="darwin",
                    machine="arm64",
                    amfi_enabled=lambda: True,
                )

        by_label = {entry.label: entry for entry in entries}
        self.assertEqual(by_label["Frida helper policy"].level, "OK")
        self.assertIn("AMFI workaround active", by_label["Frida helper policy"].value)

    def test_reports_ok_for_non_hardened_adhoc_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "Probe"
            target.write_text("fixture", encoding="utf-8")

            def runner(cmd: list[str] | tuple[str, ...]) -> ProbeResult:
                if cmd[:2] == ["/usr/bin/codesign", "-dv"]:
                    return ProbeResult(0, "", "CodeDirectory flags=0x2(adhoc)\n")
                if cmd[:3] == ["/usr/bin/codesign", "-d", "--entitlements"]:
                    return ProbeResult(1, "", "no entitlements\n")
                return ProbeResult(0, "ok\n", "")

            entries = collect_frida_diagnostics(
                target,
                tool_finder=lambda name: {
                    "python3": "/usr/bin/python3",
                    "DevToolsSecurity": "/usr/sbin/DevToolsSecurity",
                    "codesign": "/usr/bin/codesign",
                }.get(name),
                runner=runner,
                known_tool_finder=lambda _name: None,
                platform_name="darwin",
                machine="arm64",
                amfi_enabled=lambda: False,
            )

        by_label = {entry.label: entry for entry in entries}
        self.assertEqual(by_label["Frida target signing"].level, "OK")
        self.assertIn("without hardened runtime", by_label["Frida target signing"].value)


if __name__ == "__main__":
    unittest.main()
