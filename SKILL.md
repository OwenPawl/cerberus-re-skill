---
name: cerberus-re
description: Cerberus RE is a local Apple-focused reverse-engineering workbench for building a repeatable three-headed static/dynamic/instrumentation loop around Ghidra, LLDB, and Frida. Trigger when the user wants static Ghidra analysis, LLDB dynamic/live analysis, Frida instrumentation, decompilation, runtime traces, or structured reversing artifacts such as functions, strings, symbols, Objective-C metadata, Swift metadata, xrefs, and runtime hits.
---

# Cerberus RE

Use this skill for local Apple-focused reverse engineering with a repeatable
three-headed static/dynamic/instrumentation loop around Ghidra, LLDB, and
Frida. The public CLI is `cerberus-re`.

`long-run-agent` is a strongly encouraged companion dependency for substantial
work. Use it to preserve mission state, claims, artifacts, failures, friction,
and next actions while Cerberus RE handles static, dynamic, and instrumentation
evidence. Cerberus RE can still run alone for bounded one-off tasks.

## Operating Contract

- Resolve the repo or installed skill root first. If working from this checkout,
  run commands from the repo root.
- Prefer the Python CLI: `cerberus-re` or `python3 -m cerberus_re_skill`.
- Keep generated evidence as JSON or Markdown artifacts, not terminal-only output.
- Use durable workspace paths under `~/ghidra-projects`.
- Preserve dirty worktree changes you did not make.
- Capture runtime validation before treating runtime behavior as understood.
- Keep ranking and prioritization framed as safe reverse-engineering workflow.
- Runtime attach is guarded. Frida rechecks stay artifact-only unless
  `--allow-runtime` is explicit.
- Mutating bridge calls require `write=true`; destructive bridge calls also
  require `destructive=true`.

## First Commands

```bash
git status --short --branch
python3 scripts/install_dependencies.py
cerberus-re doctor
cerberus-re bootstrap
cerberus-re bridge audit
```

Run `python3 scripts/install_dependencies.py --execute` from a fresh checkout
when the host needs a local virtual environment or macOS Homebrew-managed
dependencies.

## Static Workflow

```bash
cerberus-re import analyze <binary-or-source-ref> <project_name>
cerberus-re export apple-bundle <project_name> <program_name>
cerberus-re export xpc-surface <project_name> <program_name>
```

If a standalone Mach-O target fails while Ghidra resolves reexported
dependencies, retry with:

```bash
cerberus-re import analyze <binary-or-source-ref> <project_name> --skip-macho-reexports
```

Record that the resulting static view excludes reexport behavior.

For universal Mach-O targets, choose the intended runtime slice explicitly:

```bash
cerberus-re import analyze <binary-or-source-ref> <project_name> --macho-arch arm64e
```

This stages a thin copy under the Cerberus RE workspace before import.

If a specific Ghidra analyzer reproducibly blocks import, disable only that
named analyzer and record the exception in the evidence report:

```bash
cerberus-re import analyze <binary-or-source-ref> <project_name> \
  --disable-analysis-option "Objective-C Selector Trampoline Analysis"
```

## Runtime Workflow

Use LLDB when you can launch or safely attach to a process:

```bash
cerberus-re validate lldb-trace <project> <program> \
  --launch-cmd <binary> \
  --symbols '<symbol-or-selector>' \
  --binary <binary>
```

Pass multiple LLDB trace symbols either by repeating `--symbols` or with a
comma-separated value; both forms are normalized before tracing.

For dyld-cache-backed Apple frameworks, the live `/System/Library/...framework`
path may be a stub without an on-disk Mach-O. Use the extracted dyld-cache
binary for `--binary`, while the launch or attach target remains the live
process under test.

If the static export under test is saved outside the default export tree, add:

```bash
--function-inventory /path/to/function_inventory.json
```

Use Frida for guarded instrumentation:

```bash
cerberus-re frida diagnose --target <binary>
cerberus-re frida validate-scripts --symbol '<ObjC method>' --class-name <Class>
cerberus-re frida recheck-attach \
  --target <owned-binary> \
  --symbol '<ObjC method>' \
  --capture-returns \
  --allow-runtime
cerberus-re frida recheck-attach \
  --attach-pid <pid> \
  --selector '<ObjC selector>' \
  --class-filter '<ClassSubstring>' \
  --require-runtime-hit \
  --allow-runtime
cerberus-re frida recheck-attach \
  --attach-pid <pid> \
  --selector '<ObjC selector>' \
  --exact-class '<KnownClass>' \
  --require-runtime-hit \
  --allow-runtime
cerberus-re frida recheck-attach \
  --target <owned-binary> \
  --native-symbol 'ExampleFramework!late_loaded_export' \
  --native-wait-seconds 3 \
  --native-arg-preview \
  --require-runtime-hit \
  --allow-runtime
```

Prefer `Module!symbol` for native exports when the intended framework or dylib
is known. Unqualified native symbols remain supported, but an installed
zero-hit unqualified hook is ambiguous evidence and should usually be retried
with module qualification. Exact ObjC method hooks (`--symbol`), selector-wide
ObjC hooks (`--selector`), and native hooks (`--native-symbol` or `--address`)
are separate Frida recheck modes; run separate commands when you need coverage
from more than one mode. Native hooks always preserve raw register strings under
`args`; `--native-arg-preview` adds bounded best-effort string/module previews
for those registers without making signature-correctness claims.

After LLDB or Frida emits `runtime_hits.json`, correlate it back to static
context:

```bash
cerberus-re export runtime-enrich <project> <program> <runtime_hits.json>
```

## Bridge Workflow

Use the live bridge when an interactive loop is faster than repeated exports:

```bash
cerberus-re bridge arm <project_name> [program_name]
cerberus-re bridge sessions
cerberus-re bridge call /functions/search '{"query":"SomeFunction"}'
cerberus-re bridge call /decompile '{"function":"SomeFunction"}'
cerberus-re bridge close --project <project_name>
```

## XPC Workflow

- Export XPC surfaces with `cerberus-re export xpc-surface`.
- If an XPC report shows zero counts, check `warnings` and `missing_input_count`
  before treating it as real absence evidence; pass `--bundle-dir` or explicit
  export JSON paths when using an Apple bundle saved outside the default export
  directory.
- Merge surfaces with `cerberus-re export xpc-graph`.
- Use owner hints only until imported owner evidence confirms or disproves them.
- Generate harness skeletons only after service, protocol, and endpoint evidence
  are concrete enough to rank.
- Recover `NSXPCInterface` factory/configuration evidence before planning a
  bounded remote method probe.

## Validation

Before a milestone push or release closeout, run:

```bash
python3 -m unittest discover -s tests
python3 -m compileall cerberus_re_skill scripts tests
python3 -m cerberus_re_skill polish release --mode quick --strict-command-surface
git diff --check
python3 -m cerberus_re_skill bridge audit
```

Add targeted live/static validation when changing Ghidra, LLDB, or Frida behavior.

## References

Read only the file needed for the current task:

- `references/operating-workflows.md`: detailed workflows and fallback rules.
- `references/command-surface.md`: public CLI catalog.
- `references/output-files.md`: artifact paths, schemas, and report meanings.
- `references/raw-bridge-recipes.md`: bridge endpoint payloads and examples.
- `references/frida-diagnostics.md`: Frida policy and validation guidance.
- `references/apple-macho-notes.md`: Apple Mach-O and dyld target notes.
- `references/builtins.md`: built-in Ghidra script caveats.
- `references/triage-outputs.md`: triage output details.
- `references/triage-patterns.json`: triage heuristic categories.
