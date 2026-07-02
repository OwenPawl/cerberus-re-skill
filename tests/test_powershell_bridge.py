import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "powershell" / "GhidraRe.psm1"
MANIFEST = ROOT / "powershell" / "GhidraRe.psd1"


class PowerShellBridgeParityTests(unittest.TestCase):
    def test_raw_bridge_call_is_exported_and_uses_python_cli(self) -> None:
        module = MODULE.read_text(encoding="utf-8")
        manifest = MANIFEST.read_text(encoding="utf-8")

        self.assertIn("'Invoke-GhidraReBridgeCall'", manifest)
        bridge_call = _function_body(module, "Invoke-GhidraReBridgeCall")
        self.assertIn("Invoke-GhidraReCli", bridge_call)
        self.assertIn('"bridge"', bridge_call)
        self.assertIn('"call"', bridge_call)
        self.assertIn('"BodyJson"', bridge_call)
        self.assertIn('"BodyPath"', bridge_call)

    def test_bootstrap_and_doctor_use_python_cli(self) -> None:
        module = MODULE.read_text(encoding="utf-8")

        initialize = _function_body(module, "Initialize-GhidraRe")
        doctor = _function_body(module, "Invoke-GhidraReDoctor")
        self.assertIn('Invoke-GhidraReCli -Arguments (@("bootstrap") + $args)', initialize)
        self.assertNotIn('Invoke-GhidraReScript -ScriptName "bootstrap"', initialize)
        self.assertIn('"doctor"', doctor)
        self.assertIn('"--frida-target"', doctor)
        self.assertNotIn('Invoke-GhidraReScript -ScriptName "doctor"', doctor)

    def test_no_power_shell_bridge_function_calls_removed_shell_wrappers(self) -> None:
        module = MODULE.read_text(encoding="utf-8")
        for name in [
            "Get-GhidraReBridgeSessions",
            "Select-GhidraReBridgeSession",
            "Open-GhidraReBridge",
            "Close-GhidraReBridge",
            "Get-GhidraReCurrentContext",
            "Get-GhidraReBridgeSnapshot",
            "Search-GhidraReFunctions",
            "Invoke-GhidraReAnalyzeTarget",
            "Trace-GhidraReSelector",
        ]:
            body = _function_body(module, name)
            self.assertNotIn("ghidra_bridge_", body, name)
            self.assertIn("Invoke-GhidraReCli", body + _function_body(module, "Invoke-GhidraReBridgeCall"))


def _function_body(module: str, name: str) -> str:
    marker = f"function {name}"
    start = module.find(marker)
    if start < 0:
        raise AssertionError(f"function not found: {name}")
    brace = module.find("{", start)
    if brace < 0:
        raise AssertionError(f"function body not found: {name}")
    depth = 0
    for index in range(brace, len(module)):
        if module[index] == "{":
            depth += 1
        elif module[index] == "}":
            depth -= 1
            if depth == 0:
                return module[brace + 1:index]
    raise AssertionError(f"function body did not terminate: {name}")


if __name__ == "__main__":
    unittest.main()
