# Cerberus RE Operating Workflows

This file holds the workflow detail that should not live in `SKILL.md`.

## Bootstrap And Environment

- Install with `pip install -e .` from the repo root.
- Run `cerberus-re bootstrap` once per host.
- Bootstrap installs the Cerberus bridge extension unless explicitly skipped.
- Use `cerberus-re doctor` when Ghidra, Java, Frida, or bridge state looks wrong.
- On macOS, detached bridge launches use a hidden keeper session so Ghidra can
  survive after the launcher command exits.

## Workspace Layout

- Projects: `~/ghidra-projects/projects/<project_name>/`
- Exports: `~/ghidra-projects/exports/<project_name>/<program_name>/`
- Logs: `~/ghidra-projects/logs/<project_name>/`
- Registered source roots: `~/.config/cerberus-re/sources.json`
- Bridge sessions: `~/.config/cerberus-re/bridge-sessions/`
- Bridge requests: `~/.config/cerberus-re/bridge-requests/`

## Import And Export

- Prefer explicit project names.
- Use `cerberus-re import analyze <binary> <project>` for normal binaries.
- Use `cerberus-re import analyze <binary> <project> --skip-macho-reexports` when a standalone Mach-O import fails while Ghidra recursively resolves reexported libraries; preserve that the resulting static view excludes reexport behavior.
- Use `cerberus-re import analyze <binary> <project> --macho-arch <arch>` for
  universal Mach-O targets when runtime validation will use a specific slice
  such as `arm64e`; the command stages a thin copy before import and reports
  the staged path.
- Use `--disable-analysis-option <name>` only when a specific Ghidra analyzer is
  blocking import with a reproducible headless failure. Record the disabled
  analyzer in the evidence report; the default import path should remain full
  auto-analysis.
- Use `cerberus-re import macos-framework <path> --project <project>` for live or
  extracted macOS framework paths.
- On Windows or Linux, register mounted/extracted Apple roots with
  `cerberus-re source add`, then import `source:name:/path/in/source`.
- Export the Apple bundle after import unless the task only needs a narrow
  script run.
- Set `GHIDRA_EXPORT_DEMANGLE=0` for a faster or quieter export pass.

## Direct Headless Fallback

If wrapper-based headless export stalls at `LaunchSupport -jdk_home -save`, use
the direct Java 21 AnalyzeHeadless path:

- Java executable: prefer `GHIDRA_RE_DIRECT_JAVA`, then configured Java 21, then
  common Homebrew or Temurin Java 21 paths.
- Main class path: Ghidra `Utility.jar`.
- Required property: `-Djava.system.class.loader=ghidra.GhidraClassLoader`.
- Main class: `ghidra.Ghidra`.
- Headless class: `ghidra.app.util.headless.AnalyzeHeadless`.
- Keep the same project location, script path, post script, program, logs, and
  script logs as the wrapper path.

`validate local --headless-smoke` records the wrapper failure and direct
fallback success as recovered evidence when the fallback completes.

## Swift-Heavy Targets

Run `cerberus-re export swift-outlined <project> <program>` when Ghidra still
shows many `_OUTLINED_FUNCTION_*`, anonymous `FUN_*`, or `outlined$misc$`
helpers.

Use `--dry-run` for counts only. Use `--build-authstub-map` when a dyld-extracted
binary exposes auth stubs without useful names.

The resolver classifies small helpers into categories such as `argshuffle`,
`pactail`, `loadglobal`, `loadmov`, `compare`, `pacsign`, `authstub`, `helper`,
`callwrap`, and `misc`. Re-export the Apple bundle after renaming.

## Live Bridge

Prefer the bridge for repeated search, navigation, decompile, refs, and careful
project edits. Prefer headless exports for wide scans and cold project setup.

`cerberus-re bridge arm` installs the extension when absent and repairs the
persistent Code Browser and front-end plugin configuration when it is disabled.
If Ghidra was already running when a repair was needed, restart Ghidra so the
process loads the newly enabled plugin. An arm timeout distinguishes disabled
configuration from an enabled installation that failed to create a live
session.

Useful endpoints include:

- `/session`
- `/context`
- `/functions/search`
- `/analyze/target`
- `/decompile`
- `/references`
- `/symbols/get`
- `/objc/selector-trace`
- `/edit/comment`
- `/patch/bytes`

Use `bridge inventory` to discover stable application, tool, and open-program
handles. When a tool has multiple programs open, program-scoped calls require
an explicit `target.program_id` or full `program_path`; Cerberus does not infer
the selected tab. Application- and tool-targeted arm requests are consumed only
by their owners, and disarming a bridge does not terminate its Ghidra JVM.

Read-only script exports detect project ownership from both armed sessions and
the application heartbeat inventory. A clean GUI-owned project is copied to a
content-verified temporary snapshot and emits a `*.routing.json` manifest under
the project log directory. A dirty target is rejected until it is explicitly
saved or read through the live bridge; an unowned project continues to use
direct headless access.

## LLDB

Use LLDB for launchable or attachable targets. The trace path can capture
argument registers, backtraces, ObjC self/selector context, isa values, and
static enrichment. For event-driven targets, start tracing first, trigger the
action immediately, and use a generous timeout.

For system framework behavior, compile a small harness that exercises the path
instead of trying to attach broadly to privileged system processes.

## Frida

Run `cerberus-re frida diagnose` first. Runtime attach is skipped unless
`--allow-runtime` is explicit.

Generated scripts can validate syntax without attachment. Runtime rechecks write
`frida-runtime-recheck.json` and, on hits, `runtime_hits.json`.

Console lines beginning `GHIDRA_FRIDA_HIT`, `GHIDRA_FRIDA_RETURN`, and
`GHIDRA_FRIDA_HEAP_OBJECT` normalize into the shared runtime-hit schema.
Selector-wide hooks deduplicate inherited or aliased Objective-C methods by
implementation pointer. The emitted runtime hit keeps the primary symbol plus
`selector_aliases` so one implementation call does not inflate into several
duplicate proof records.

Use `cerberus-re frida objc-archive` when the evidence is a host-owned
secure-coded object that must be decoded inside an attachable target. It embeds
the bytes, validates one expected root class, and restricts observation to
no-argument getters rather than opening an arbitrary invocation surface.

Use `cerberus-re frida objc-probe --call-string
'Class.sharedProvider.defaultValueForType:=TypeName'` when a statically
recovered read boundary requires one `NSString` argument. The option supports
only one argument on the final selector after zero-argument navigation. It
does not prove a selector is read-only; do not select save, update, or execution
methods for bounded observation. Test argument-bearing calls in a disposable
spawned or owned process first when possible; attached use requires
`--allow-attached-call` because an Objective-C exception can terminate the
target.

## XPC Analysis

Build XPC surface reports from exported `objc_metadata.json`, `strings.json`,
and `symbols.json`. Merge them with `xpc-graph` to reveal owner/client edges and
remaining gaps.

Use owner hints as temporary scaffolding. Replace hints with imported owner
surfaces when paths can be verified.

For domain-specific work, keep reusable tool improvements separate from
target-specific evidence. Keep target notes, failed paths, and exploratory
project plans outside the public skill repository when preparing a public skill
surface.
