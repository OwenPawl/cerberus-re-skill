from pathlib import Path
import unittest


class LldbTraceScriptTests(unittest.TestCase):
    def test_launch_arguments_are_separated_from_lldb_options(self) -> None:
        script = Path("scripts/ghidra_lldb_trace").read_text(encoding="utf-8")

        self.assertIn("settings set -- target.run-args%s", script)
        self.assertNotIn("settings set target.run-args --%s", script)
        self.assertNotIn("settings set target.run-args%s", script)

    def test_launch_binary_paths_may_contain_spaces(self) -> None:
        script = Path("scripts/ghidra_lldb_trace").read_text(encoding="utf-8")

        self.assertIn("shlex.split(sys.argv[1])", script)
        self.assertIn("shlex.quote(sys.argv[1])", script)
        self.assertIn('launch_bin="${launch_parts[0]}"', script)
        self.assertIn('quoted_part="$(lldb_quote_arg "$launch_part")"', script)
        self.assertIn('launch_args+=" $quoted_part"', script)
        self.assertIn('while [[ "$launch_candidate" == *" "* ]]', script)
        self.assertIn('if [[ -x "$launch_candidate" ]]', script)
        self.assertIn('launch_args="${launch_cmd#"$launch_candidate"}"', script)

    def test_objc_description_register_capture_is_explicit_and_limited(self) -> None:
        script = Path("scripts/ghidra_lldb_trace").read_text(encoding="utf-8")

        self.assertIn("objc_description_registers=x2[,x3]", script)
        self.assertIn("objc_description_registers must be a comma-separated subset of x0 through x7", script)
        self.assertIn("def _describe_objc_pointer", script)
        self.assertIn('rec["objc_descriptions"]', script)

    def test_selector_capture_is_limited_to_objc_method_symbols(self) -> None:
        script = Path("scripts/ghidra_lldb_trace").read_text(encoding="utf-8")

        self.assertIn('_symbol_name.startswith("+[") or _symbol_name.startswith("-[")', script)
        self.assertIn('rec["objc_selector_skipped"] = "non_objc_symbol"', script)
        self.assertIn('rec["selector"] = _selector', script)

    def test_timeout_sidecars_preserve_full_breakpoint_preflight(self) -> None:
        script = Path("scripts/ghidra_lldb_trace").read_text(encoding="utf-8")

        self.assertIn("_preflight_file =", script)
        self.assertIn("def _flush_preflight(target):", script)
        self.assertIn("_flush_preflight(frame.GetThread().GetProcess().GetTarget())", script)
        self.assertIn("_flush_preflight(lldb.debugger.GetSelectedTarget())", script)
        self.assertIn("preflight_sidecar = raw_file + \".preflight.json\"", script)
        self.assertIn('"breakpoint_preflight_source": preflight_source', script)

    def test_runtime_module_identity_is_preserved_for_drift_audits(self) -> None:
        script = Path("scripts/ghidra_lldb_trace").read_text(encoding="utf-8")

        self.assertIn("_runtime_modules = []", script)
        self.assertIn("def _capture_runtime_modules(target):", script)
        self.assertIn("_module.GetUUIDString()", script)
        self.assertIn("modules_sidecar = raw_file + \".modules.json\"", script)
        self.assertIn('"runtime_modules": _m._runtime_modules', script)


if __name__ == "__main__":
    unittest.main()
