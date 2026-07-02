import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from cerberus_re_skill.modules.frida_scripts import (
    generate_frida_heap_scan_script,
    generate_frida_native_trace_script,
    generate_frida_selector_trace_script,
    generate_frida_trace_script,
)


class FridaScriptValidationTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("node"), "node is required for JavaScript syntax validation")
    def test_generated_frida_scripts_are_javascript_syntax_valid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            trace = root / "trace.js"
            heap = root / "heap.js"

            result = generate_frida_trace_script(
                symbols="-[CodexProbe runWithInput:]",
                output=trace,
                capture_returns=True,
            )
            generate_frida_heap_scan_script("CodexProbe", heap)

            trace_js = trace.read_text(encoding="utf-8")
            self.assertEqual(result["targets"][0]["selector_arg_count"], 1)
            self.assertIn("objcArgIndexes.push(i + 2)", trace_js)
            self.assertIn("for (const i of objcArgIndexes)", trace_js)
            self.assertIn("function isLikelyObjCPointer(value)", trace_js)
            self.assertIn('value.compare(ptr("0x10000")) < 0', trace_js)
            self.assertIn("GHIDRA_FRIDA_WAITING_CLASS", trace_js)
            self.assertIn("retryPendingTargets", trace_js)
            self.assertIn("installedTargets.has(target.symbol)", trace_js)
            self.assertIn("function moduleInfoForAddress(address)", trace_js)
            self.assertIn("Process.findModuleByAddress(ptrValue)", trace_js)
            self.assertIn("module_base", trace_js)
            self.assertIn("module_offset", trace_js)
            self.assertIn("ghidra-re.runtime-hit.v1", trace.read_text(encoding="utf-8"))
            self.assertIn("ghidra-re.runtime-hit.v1", heap.read_text(encoding="utf-8"))

            for script in [trace, heap]:
                result = subprocess.run(
                    ["node", "--check", str(script)],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_trace_script_normalizes_objc_category_symbols_to_runtime_class(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            trace = Path(tmp) / "trace.js"

            result = generate_frida_trace_script(
                symbols="-[ExampleContextualAction(SpotlightResultRunnable) runDescriptorForSurface:]",
                output=trace,
            )

            target = result["targets"][0]
            self.assertEqual(
                target["symbol"],
                "-[ExampleContextualAction(SpotlightResultRunnable) runDescriptorForSurface:]",
            )
            self.assertEqual(target["class_name"], "ExampleContextualAction")
            self.assertEqual(target["category_name"], "SpotlightResultRunnable")
            self.assertEqual(target["runtime_symbol"], "-[ExampleContextualAction runDescriptorForSurface:]")
            self.assertIn('"class_name": "ExampleContextualAction"', trace.read_text(encoding="utf-8"))

    def test_trace_script_normalizes_underscore_category_symbols_to_runtime_class(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            trace = Path(tmp) / "trace.js"

            result = generate_frida_trace_script(
                symbols="-[ExampleTask(Compatibility)_initWithName:description:associatedAppBundleIdentifier:actions:]",
                output=trace,
            )

            target = result["targets"][0]
            self.assertEqual(target["class_name"], "ExampleTask")
            self.assertEqual(target["category_name"], "Compatibility")
            self.assertEqual(target["method_name"], "- initWithName:description:associatedAppBundleIdentifier:actions:")

    @unittest.skipUnless(shutil.which("node"), "node is required for JavaScript syntax validation")
    def test_selector_trace_script_hooks_runtime_selector_with_filters(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            trace = Path(tmp) / "selector_trace.js"

            result = generate_frida_selector_trace_script(
                selectors=["runDescriptorForSurface:"],
                output=trace,
                class_filters=["Example"],
                exact_classes=["ExampleProbe"],
                max_hooks=8,
                capture_returns=True,
            )
            script = trace.read_text(encoding="utf-8")

            self.assertEqual(result["selectors"], ["runDescriptorForSurface:"])
            self.assertEqual(result["class_filters"], ["Example"])
            self.assertEqual(result["exact_classes"], ["ExampleProbe"])
            self.assertIn("GHIDRA_FRIDA_SELECTOR_INSTALLED", script)
            self.assertIn("installedImplementations", script)
            self.assertIn("GHIDRA_FRIDA_SELECTOR_ALIAS", script)
            self.assertIn("selector_aliases", script)
            self.assertIn("selector_alias_count", script)
            self.assertIn("selectorHookCounts", script)
            self.assertIn("GHIDRA_FRIDA_SELECTOR_NO_MATCH", script)
            self.assertIn("installClassSelectors(className)", script)
            self.assertIn("GHIDRA_FRIDA_SELECTOR_ENUM_ERROR", script)
            self.assertIn("const exactClasses = [", script)
            self.assertIn('"ExampleProbe"', script)
            self.assertIn("classFilters.length > 0 || exactClasses.length === 0", script)
            self.assertIn("selector_wide: true", script)
            self.assertIn("function isLikelyObjCPointer(value)", script)
            self.assertIn("function moduleInfoForAddress(address)", script)
            self.assertIn("module_offset", script)
            self.assertIn('value.compare(ptr("0x10000")) < 0', script)
            syntax = subprocess.run(
                ["node", "--check", str(trace)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(syntax.returncode, 0, syntax.stderr)

    @unittest.skipUnless(shutil.which("node"), "node is required for JavaScript syntax validation")
    def test_native_trace_script_can_wait_for_late_loaded_exports(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            trace = Path(tmp) / "native_trace.js"

            result = generate_frida_native_trace_script(
                symbols=["ExampleClient!ExampleSystemActionsDataFromContextualAction"],
                output=trace,
                capture_returns=True,
                native_wait_seconds=2.5,
                native_arg_preview=True,
            )
            script = trace.read_text(encoding="utf-8")

            self.assertEqual(result["native_wait_seconds"], 2.5)
            self.assertTrue(result["native_arg_preview"])
            self.assertIn("const nativeWaitMs = 2500;", script)
            self.assertIn("const nativeArgPreview = true;", script)
            self.assertIn("function nativeArgPreviewForValue(value)", script)
            self.assertIn("function readUtf8Preview(address)", script)
            self.assertIn("function printableStringPrefix(value)", script)
            self.assertIn("address.readCString", script)
            self.assertIn("address.readUtf8String", script)
            self.assertIn("native_arg_previews", script)
            self.assertIn('native_arg_preview_mode = "best_effort_registers"', script)
            self.assertIn("setInterval(function()", script)
            self.assertIn("emitMissingTargets", script)
            syntax = subprocess.run(
                ["node", "--check", str(trace)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(syntax.returncode, 0, syntax.stderr)

    def test_native_trace_script_records_macho_underscore_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            trace = Path(tmp) / "native_trace.js"

            result = generate_frida_native_trace_script(
                symbols=["XPCDistributed!_$sDemoSymbol"],
                output=trace,
            )
            script = trace.read_text(encoding="utf-8")

            self.assertEqual(result["targets"][0]["symbol"], "_$sDemoSymbol")
            self.assertEqual(
                result["targets"][0]["symbol_candidates"],
                ["_$sDemoSymbol", "$sDemoSymbol"],
            )
            self.assertIn('"symbol_candidates": [', script)
            self.assertIn('"_$sDemoSymbol"', script)
            self.assertIn('"$sDemoSymbol"', script)
            self.assertIn("target.symbol_candidates || symbolCandidates(target.symbol)", script)


if __name__ == "__main__":
    unittest.main()
