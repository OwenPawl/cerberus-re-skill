# Local Validation Matrix

Use this matrix before milestone closeout, release polish, or bridge-facing changes.

## Fast Checks

```bash
python3 -m compileall cerberus_re_skill tests
python3 -m unittest discover -s tests
python3 -m cerberus_re_skill doctor
python3 -m cerberus_re_skill doctor --frida-target /tmp/cerberus-re-validation/CodexObjCProbe
python3 -m cerberus_re_skill validate local
python3 -m cerberus_re_skill polish release --mode quick --strict-command-surface
python3 -m cerberus_re_skill frida diagnose --target /tmp/cerberus-re-validation/CodexObjCProbe
python3 -m cerberus_re_skill frida validate-scripts
git diff --check
```

## Java / Headless Smoke

```bash
./scripts/ghidra_import_analyze /usr/bin/true codex_true_smoke
./scripts/ghidra_export_apple_bundle codex_true_smoke true
./scripts/ghidra_run_script codex_true_smoke true DecompileFunction.java output=/tmp/codex_true_decompile.c
./scripts/ghidra_classify_small_functions codex_true_smoke true include_named=true max_bytes=128 dry_run=true output=/tmp/codex_true_small.json
./scripts/ghidra_run_script codex_true_smoke true ExportXPCSurface.java output=/tmp/codex_true_xpc_java.json
```

## Larger Headless Target

```bash
./scripts/ghidra_export_apple_bundle sample_service_smoke SampleXPCService
./scripts/ghidra_classify_small_functions sample_service_smoke SampleXPCService max_bytes=64 dry_run=true output=/tmp/sample_service_small_functions.json
./scripts/ghidra_run_script sample_service_smoke SampleXPCService ExportXPCSurface.java output=/tmp/sample_service_xpc_java.json
python3 -m cerberus_re_skill export xpc-surface sample_service_smoke SampleXPCService --output /tmp/sample_service_xpc_surface.json --markdown-output /tmp/sample_service_xpc_surface.md
```

## Raw CLI Live Bridge

```bash
python3 -m cerberus_re_skill bridge install
python3 -m cerberus_re_skill bridge arm codex_true_smoke true
python3 -m cerberus_re_skill bridge health --project codex_true_smoke --program true
python3 -m cerberus_re_skill bridge call /functions/search '{"project":"codex_true_smoke","program":"true","query":"entry","limit":5}'
python3 -m cerberus_re_skill bridge call /decompile '{"project":"codex_true_smoke","program":"true","function":"entry"}'
python3 -m cerberus_re_skill bridge call /edit/comment '{"project":"codex_true_smoke","program":"true","address":"100000388","comment":"bridge validation","comment_type":"plate","write":true}'
python3 -m cerberus_re_skill bridge call /program/save '{"project":"codex_true_smoke","program":"true","write":true,"description":"bridge validation"}'
python3 -m cerberus_re_skill bridge audit
python3 -m cerberus_re_skill bridge close --project codex_true_smoke --program true
```

When validating multiple targets, prefer selector JSON in every raw call:

```bash
python3 -m cerberus_re_skill bridge arm sample_service_smoke SampleXPCService
python3 -m cerberus_re_skill bridge call /strings/search '{"project":"sample_service_smoke","program":"SampleXPCService","query":"xpc","limit":8}'
python3 -m cerberus_re_skill bridge call /symbols/xrefs '{"project":"sample_service_smoke","program":"SampleXPCService","query":"_OBJC_CLASS_$_NSXPCListener","limit":10}'
```

To compare headless and live function identity fields, save a live function/search response and build a report:

```bash
python3 -m cerberus_re_skill bridge call /functions/search '{"project":"codex_true_smoke","program":"true","query":"entry","limit":5}' > /tmp/codex_true_live_functions.json
python3 -m cerberus_re_skill export function-identity-report codex_true_smoke true ~/ghidra-projects/exports/codex_true_smoke/true/function_inventory.json /tmp/codex_true_live_functions.json --output /tmp/codex_true_identity_report.json
```

## LLDB ObjC Fixture

```bash
mkdir -p /tmp/cerberus-re-validation
clang -fobjc-arc -framework Foundation tests/fixtures/CodexObjCProbe.m -o /tmp/cerberus-re-validation/CodexObjCProbe
./scripts/ghidra_import_analyze /tmp/cerberus-re-validation/CodexObjCProbe codex_objc_probe
./scripts/ghidra_export_apple_bundle codex_objc_probe CodexObjCProbe
./scripts/ghidra_build_isa_map codex_objc_probe CodexObjCProbe
./scripts/ghidra_lldb_symbols /tmp/cerberus-re-validation/CodexObjCProbe codex_objc_probe CodexObjCProbe
./scripts/ghidra_lldb_trace codex_objc_probe CodexObjCProbe launch_cmd=/tmp/cerberus-re-validation/CodexObjCProbe 'symbols=-[CodexProbe runWithInput:]' capture_objc_args=true capture_backtrace=true max_hits=3 timeout=15 output=/tmp/cerberus-re-validation/objc_probe_lldb_trace.json
./scripts/ghidra_lldb_enrich codex_objc_probe CodexObjCProbe /tmp/cerberus-re-validation/objc_probe_lldb_trace.json include_decompile=true output=/tmp/cerberus-re-validation/objc_probe_lldb_trace_enriched.json
python3 -m cerberus_re_skill generate-harness /tmp/cerberus-re-validation/objc_probe_lldb_trace_enriched.json --output /tmp/cerberus-re-validation/CodexObjCProbeHarness.m --compile --compile-output /tmp/cerberus-re-validation/CodexObjCProbeHarness
```

## Frida Diagnostics

```bash
FRIDA_BIN="${GHIDRA_RE_FRIDA_BIN:-$(command -v frida || printf /opt/cerberus-re/frida-venv/bin/frida)}"
"$FRIDA_BIN" --version
"$(dirname "$FRIDA_BIN")/frida-ps" | head
scripts/strip_hardened_runtime /tmp/cerberus-re-validation/CodexObjCProbe /tmp/cerberus-re-validation/CodexObjCProbe.frida
python3 -m cerberus_re_skill doctor --frida-target /tmp/cerberus-re-validation/CodexObjCProbe.frida
./scripts/ghidra_frida_trace codex_objc_probe CodexObjCProbe 'symbols=-[CodexProbe runWithInput:]' capture_returns=true dry_run=true script_output=/tmp/cerberus-re-validation/frida_probe_trace.js
./scripts/ghidra_frida_heap_scan CodexProbe dry_run=true script_output=/tmp/cerberus-re-validation/frida_probe_heap.js
node --check /tmp/cerberus-re-validation/frida_probe_trace.js
node --check /tmp/cerberus-re-validation/frida_probe_heap.js
DevToolsSecurity -status
```

If runtime attach fails, capture the exact failure. Runtime Frida validation
should try the normal native Frida path first when host policy allows it. The
old `/opt/cerberus-re/frida-venv` plus `sudo -n` workaround is fallback-only for
AMFI-off hosts.

## Analyst Automation Checks

```bash
python3 -m cerberus_re_skill export xpc-graph codex_true_smoke:true --output /tmp/codex_true_xpc_graph.json --markdown-output /tmp/codex_true_xpc_graph.md
python3 -m cerberus_re_skill diff codex_true_smoke true codex_true_smoke true --output /tmp/codex_true_self_diff.json
python3 -m unittest tests.test_command_surface tests.test_workflow_automation
```
