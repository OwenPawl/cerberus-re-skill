---
name: ghidra-re
description: Use for Ghidra-based reverse engineering on this machine, especially Apple Mach-O and dyld-extracted binaries. Trigger when the user wants headless Ghidra import/analysis, to run Ghidra scripts, inspect decompilation, or export structured reversing artifacts such as functions, strings, symbols, Objective-C metadata, or xrefs. Prefer this skill over ad hoc shell commands when the task should create or reuse a Ghidra project under ~/ghidra-projects. Works identically whether loaded by OpenAI Codex or Anthropic Claude Code.
---

# Ghidra RE

Use this skill for repeatable, headless-first Ghidra work on macOS or Windows. It assumes:

- Ghidra install:
  - macOS: `/Applications/Ghidra`
  - Windows: `%LOCALAPPDATA%\Programs\Ghidra` for a user-scoped install; `C:\Program Files\Ghidra` is also detected when already installed
- JDK:
  - macOS: `/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home`
  - Windows: `/c/Program Files/Eclipse Adoptium/jdk-21`
- Workspace root: `~/ghidra-projects`
- Skill root — **resolve this first** before running any script (see below)

The skill is host-agnostic and runs on Windows, macOS, and Linux with **zero Bash dependency**. All orchestration is implemented in Python 3.11+ under the `ghidra_re_skill/` package. Install with `pip install -e .` from the skill root, then use `python -m ghidra_re_skill` (or the `ghidra-re` console script) for all operations.

## Resolving the Skill Root

The Python package is installed via `pip install -e .` from the skill root. After installation, use `ghidra-re` (console script) or `python -m ghidra_re_skill` from anywhere. No `SKILL_ROOT` variable or path prefix is needed.

To install: `pip install -e /path/to/ghidra-re-skill`

## Quick Start

> All commands use the `ghidra-re` CLI (installed via `pip install -e .`). Equivalent: `python -m ghidra_re_skill`.

1. On a fresh machine, run `ghidra-re bootstrap` once.
   - This installs the bridge extension **and** the GhidraApple community plugin automatically.
   - On Windows, bootstrap should auto-detect Ghidra. Use `GHIDRA_INSTALL_DIR` or `GHIDRA_HOME` only as an override when detection is wrong.
   - After bootstrap, restart Ghidra and enable GhidraApple analyzers: **Analysis > Analyze All Open Files** (check the GhidraApple entries). This must be done once per project for the ObjC/msgSend/block enrichment to take effect.
   - To skip plugin install: `ghidra-re bootstrap --skip-plugins-install`
   - To install/reinstall the plugin separately: `ghidra-re plugins install ghidraapple`
   - To check plugin status: `ghidra-re plugins status`
2. If bootstrap cannot find Ghidra or Java 21, run `ghidra-re doctor`.
3. On Windows, if the targets live in a mounted or extracted macOS image, register that source first:
   - `python -m ghidra_re_skill bridge call /source/add mac-image root=/d/macos-root platform=macos-image copy=cache`
4. Start a multi-target mission when the task spans more than one framework, daemon, or helper:
   - `ghidra-re mission start <mission_name> --goal "..." --target <binary_or_project:program>`
5. Extend the mission with a seed-driven trace:
   - `ghidra-re mission trace <mission_name> <seed>`
6. For a more autonomous pass, let the mission keep driving its own next hops:
   - `ghidra-re mission autopilot <mission_name>`
7. Read the mission report:
   - `ghidra-re mission report <mission_name>`
8. Finish the mission:
   - `ghidra-re mission finish <mission_name>`
9. For a single target, import and analyze into a dedicated project:
   - `ghidra-re import analyze <binary|source:name:/path/in/image> [project_name]`
10. Export the default Apple-focused bundle:
   - `ghidra-re bridge call /export/apple-bundle --project <project_name> --program <program_name>`
10a. Export Mach-O structural metadata (load commands, segments, dylib table, UUID, versions, entitlements):
   - `ghidra-re export macho-structure <project_name> <program_name>`
   - Output: `~/ghidra-projects/exports/<project>/<program>/macho_structure.json`
   - Pass `--output /path/to/file.json` to override the destination.
10b. Export per-class ObjC ivar and method layout (superclass chains, protocol conformances, ivar offsets, method selectors/imp addresses, categories):
   - `ghidra-re export objc-layout <project_name> <program_name>`
   - Output: `~/ghidra-projects/exports/<project>/<program>/objc_layout.json`
10c. Export Swift type layout (structs/classes/enums, fields with types, enum cases, protocol conformances + witness table addresses):
   - `ghidra-re export swift-layout <project_name> <program_name>`
   - Output: `~/ghidra-projects/exports/<project>/<program>/swift_layout.json`
   - Requires `swift demangle` on PATH for human-readable type names.
11. Export the bug-hunt bundle only when the task is explicitly bug hunting or boundary triage:
   - `ghidra-re bridge call /export/bug-hunt-bundle`
12. Generate a function dossier for a top candidate:
   - `ghidra-re bridge call /function/dossier`
13. Apply a finding back into the project when you confirm something interesting:
   - `ghidra-re bridge call /apply-finding`
14. Run an extra script when needed:
   - `ghidra-re import run-script <script_name> <project_name> [program_name]`
15. Record any friction or missing-feature notes through the shared notes flow before you wrap up the session:
   - `ghidra-re notes add --title "..." --body "..." --category workflow`
   - `ghidra-re notes status`
   - `ghidra-re notes open-shared`
16. Arm or reuse the live bridge when you want an interactive RE loop:
   - `ghidra-re bridge arm <project_name> [program_name]`
17. Use the live bridge for inspection or edits:
   - `ghidra-re bridge call /session`
   - `ghidra-re bridge call /bridge/snapshot`
   - `ghidra-re bridge call /bridge/analyze-target`
   - `ghidra-re bridge call /decompile/current`
   - `ghidra-re bridge call /functions/search <query>`
   - `ghidra-re bridge call /symbols/get`
   - `ghidra-re bridge call /bridge/rename`
   - `ghidra-re bridge call /bridge/comment`
   - `ghidra-re bridge call /bridge/patch-bytes`
   - `ghidra-re bridge call /bridge/patch-instruction`
18. Use the dyld-aware macOS import helper when a framework path comes from a live system image or extracted source root:
   - `ghidra-re import macos-framework </System/.../Framework.framework/Framework> [--project <name>]`
19. Build a one-file macOS share bundle when you want to hand the skill and Ghidra to another desktop:
   - `ghidra-re publish mac-desktop [output_zip]`
22. Build a one-file Windows share bundle when you want easy installation on a Windows machine:
   - `ghidra-re publish windows-desktop [output_zip] [--ghidra-zip /path/to/ghidra.zip]`
23. On Windows, optionally import the native module after install:
   - `Import-Module GhidraRe`
   - `Get-GhidraReBridgeSessions`
   - `Start-GhidraReMission -Name win_trace -Goal 'Trace a subsystem' -Target 'source:mac-image:/System/.../WorkflowKit'`
24. Run the explicit polish pass before serious testing or publishing:
   - `scripts/ghidra_polish_release [mode=quick|release]`

## Default Workflow

### 1) Import into the dedicated workspace
- First-use bootstrap writes machine-local config to `~/.config/ghidra-re/config.env` on macOS/Linux and `%APPDATA%\ghidra-re\config.env` on Windows.
- Projects live under `~/ghidra-projects/projects/<project_name>/`.
- Exports live under `~/ghidra-projects/exports/<project_name>/<program_name>/`.
- Logs live under `~/ghidra-projects/logs/<project_name>/`.
- Multi-target investigation workspaces live under `~/ghidra-projects/investigations/<mission_name>/`.
- Source-backed imports are cached under `~/ghidra-projects/sources/<source_name>/` by default when you use `source:name:/path`.
- Prefer explicit project names for reusable work. If omitted, the import wrapper derives one from the binary basename.
- On Windows, the PowerShell module resolves the installed skill root automatically from `CODEX_HOME`, `CLAUDE_HOME`, `~/.codex/skills/ghidra-re`, or `~/.claude/skills/ghidra-re`, then forwards to the same script surface regardless of which host loaded the skill.

### 2) Use missions for cross-target work
- Prefer `scripts/ghidra_mission_start` whenever the question spans multiple frameworks, daemons, or XPC helpers.
- Mission workspaces keep:
  - `mission.json`
  - `graph.sqlite`
  - `exports/`
  - `reports/latest.md`
  - `reports/latest.json`
- Mission runs are notes-only by default. They do not rename symbols, comment programs, or patch bytes unless you explicitly call the existing write wrappers outside the mission flow.
- `scripts/ghidra_mission_trace` uses the investigation graph first, then live bridge helpers like `functions/search`, `analyze/target`, and `selector-trace`.
- `scripts/ghidra_mission_autopilot` extends that loop by choosing the next seed from configured seeds, graph-derived suggestions, and recent analysis notes, then capturing a live bridge snapshot back into the mission artifacts.
- Autopilot seed ranking now prefers higher-signal graph functions, configured seeds, current-hypothesis targets, and preferred targets that have not been explored yet.
- `scripts/ghidra_mission_finish` is the default closeout path. It renders the report, records the closeout in the mission metadata, and closes the mission's bridge-managed Ghidra sessions unless `keep_sessions_open=true`.
- `scripts/ghidra_mission_finish` can also forward a discovered workflow-friction note into the shared GitHub-backed notes backlog with `shared_note_title=...` and `shared_note_body=...`.
- Finished missions now also emit `reports/casefile.md` and `reports/casefile.json` as a cleaner analyst closeout bundle.

### 3) Resolve Swift outlined functions (Swift-heavy binaries only)
- For any dyld-extracted or Swift-heavy binary, run `scripts/ghidra_resolve_swift_outlined` **before** exporting or decompiling. This renames 3,000–4,000 anonymous `_OUTLINED_FUNCTION_*` stubs to descriptive names (`outlined$argshuffle$`, `outlined$pactail$swift_retain$`, `outlined$loadglobal$`, `outlined$authstub$`, etc.) and marks pure ARC helpers as inline. Without this, the decompiler output for any Swift method that calls retain/release is dominated by opaque `_OUTLINED_FUNCTION_0()` calls that hide the real control flow.
- Re-run `scripts/ghidra_export_apple_bundle` afterwards to regenerate the function inventory with updated names.
- The script runs in two passes by default (`second_pass=true`): the main pass renames `_OUTLINED_FUNCTION_*`, anonymous `FUN_*` auth stubs (`scan_fun_stubs=true`), and existing `outlined$misc$` stubs ≤32 bytes that the expanded classifier can now better categorize. The second pass re-resolves pactail branch-target names using the now-renamed callees. This is important for dyld-extracted binaries where the `__stubs` region is named `FUN_*` instead of `_OUTLINED_FUNCTION_*` by Ghidra.
- Categories: `argshuffle`, `pactail` (PAC-guarded tail call — callee name embedded when resolved), `loadglobal`, `loadmov`, `compare`, `pacsign`, `authstub` (named by GOT slot address in dyld extracts, or by actual symbol name when `authstub_map.json` is present — e.g. `outlined$authstub$swift_retain`), `helper` (small 1–16 instruction ret/b helper, ≤64 bytes; marked inline), `callwrap` (single-bl wrapper with callee name embedded, e.g. `callwrap$swift_getEnumTagSinglePayload`; marked inline), and `misc` (>64 bytes or unusual terminal — genuinely complex, left as-is). Only ~12 misc remain in WorkflowKit after a full pass.
- `authstub_map.json` is built by `scripts/ghidra_build_authstub_map` (also invoked automatically when `build_authstub_map=true` is passed to `ghidra_resolve_swift_outlined`). It parses the live dyld shared cache — including all split sub-cache `.dylddata` files — decodes PAC-tagged GOT slot pointers, looks up target symbols via `dyld_info -exports`, and batch-demangling with `xcrun swift-demangle`. Achieves ~99% resolution on WorkflowKit (1899/1920 stubs). The resulting file is auto-discovered by `ResolveSwiftOutlined.java` on subsequent headless runs.

### 4) Use the Apple export bundle
- Run `scripts/ghidra_export_apple_bundle` after import unless the user only wants a narrow script run.
- The bundle runs `DemangleAllScript.java` and then exports:
  - `program_summary.json`
  - `objc_metadata.json`
  - `swift_metadata.json`
  - `function_inventory.json`
  - `symbols.json`
  - `strings.json`
- `objc_metadata.json` now includes interface-quality class buckets, categories, class refs, selector refs, protocol refs, selector strings, and recovered protocol names so ObjC-heavy Apple frameworks can be followed without reopening Ghidra immediately.
- `swift_metadata.json` now includes:
  - demangled/raw Swift symbol pairs
  - a stable alias map
  - metadata-section summaries for `__swift5_*` blocks
  - async-like entries, metadata accessors, protocol conformance hints, and dispatch-thunk tagging
- Set `GHIDRA_EXPORT_DEMANGLE=0` when you want a faster or quieter export pass without the blanket demangle step.
- For Swift-heavy frameworks, prefer `scripts/ghidra_swift_surface_report` before ad hoc `functions/search` calls so you start from grouped types/methods instead of raw mangled names.

### 5) Use targeted scripts for follow-up
- Run `scripts/ghidra_export_bug_hunt_bundle` when the task is bug hunting, boundary analysis, or userland trust-boundary triage.
- Use `scripts/ghidra_function_dossier` on the top-ranked candidate paths before decompiling functions ad hoc.
- For ObjC-heavy frameworks, start with `scripts/ghidra_objc_surface_report`, then drill into `scripts/ghidra_describe_objc_class`, `scripts/ghidra_describe_objc_protocol`, `scripts/ghidra_describe_selector`, `scripts/ghidra_trace_classref`, and `scripts/ghidra_objc_message_flow` when you need a more useful selector-level flow view.
- Use `scripts/ghidra_apply_finding` only when you want to write comments, bookmarks, or renames back into the project.
- Use `scripts/ghidra_notes_add` whenever the workflow exposes missing features, confusing outputs, or repetitive manual steps. The GitHub-backed shared issue is now the canonical community backlog; `references/use-case-driven-notes.md` is legacy/reference-only.
- `DecompileFunction.java` for on-demand decompilation
- `ExportXrefs.java` for targeted xref tracing
- `ExportAppleBundle.java` when you want the full structured export outside the convenience wrapper

### 6) Use the live bridge for iterative GUI sessions
- Prefer the live bridge whenever the target is already open or the task will involve repeated `search -> navigate -> decompile -> refs` loops.
- Prefer headless exports for wide scans, batch bundles, or cold-start project setup; switch to the bridge once you want a tighter interactive loop.
- `ghidra-re bootstrap` installs the bridge extension into the user's Ghidra settings when possible. The installer uses `xml.etree.ElementTree` to safely patch Ghidra tool config files (`.tcd`), removing any old "Codex Bridge" package and adding the plugin to the "Ghidra Core" package — it never mangles XML with regex and skips malformed files gracefully.
- If Ghidra was already running before the install, restart it once or run `EnableCodexBridge.java` from the GUI Script Manager.
- The bridge now keeps a real multi-session registry under `~/.config/ghidra-re/bridge-sessions/` and a compatibility pointer at `~/.config/ghidra-re/bridge-current.json`. The lock used when updating `bridge-current.json` auto-expires stale locks (older than 30 s) to prevent permanent hangs after a crash.
- On Windows, `check_pid_alive()` uses `PROCESS_QUERY_LIMITED_INFORMATION` + `GetExitCodeProcess` with proper handle cleanup instead of a bare `OpenProcess` flag, reducing false-positive "alive" results after a process exits.
- `ghidra-re bridge arm` and `ghidra-re bridge call` write per-request files under `~/.config/ghidra-re/bridge-requests/`, first give an already-running Ghidra session a chance to consume them, and only then launch a detached GUI session if needed.
- Use `scripts/ghidra_bridge_sessions` to list live sessions and `scripts/ghidra_bridge_select` to change the default target.
- On macOS, detached launches use a hidden `screen` keeper session so Ghidra survives after the launcher command exits and the bridge remains usable across the rest of the Codex session.
- Cross-project arms are supported: a running `bsr_smoke` session can ignore a `workflowkit_bug_smoke` request while a newly launched WorkflowKit instance consumes the same request file and becomes another live session.
- `scripts/ghidra_bridge_call` is the raw HTTP wrapper; prefer the convenience wrappers for common tasks.
- `scripts/ghidra_bridge_open` now waits until both `/health` and `/session` succeed before it returns, so a reported armed bridge is immediately queryable.
- `scripts/ghidra_bridge_snapshot` captures the current live session, function, decompile, references, and variables in one machine-readable artifact for later ingestion or notes.
- Bridge snapshots now try to resolve the containing function from the current address, so mid-function cursor positions still produce a useful decompile/references bundle.
- Most live bridge wrappers accept optional `session=<id>`, `project=<name>`, or `program=<name>` selectors.
- Prefer `project=` or `session=` when duplicate live targets share the same `program_name`.
- `scripts/ghidra_bridge_swift_search` combines the live bridge session with the latest export bundle so type or method queries can resolve through stable aliases and thunk/canonical addresses.
- `scripts/ghidra_bridge_swift_type` aggregates grouped Swift type context, related strings, ObjC bridge names, metadata accessors, and the best live-analysis target when one is available.
- Mutating bridge calls require `write=true`; destructive bridge calls also require `destructive=true`.
- The PowerShell module mirrors the most common source, mission, and bridge commands with `Verb-GhidraRe*` functions for Windows-first usage.

## Command Surface

Run these wrappers from the skill directory:

- `scripts/ghidra_import_analyze <binary> [project_name]`
- `scripts/ghidra_import_macos_framework </System/.../Framework.framework[/Framework]> [project_name] [copy=cache|direct] [source=<name>]`
- `scripts/ghidra_run_script <project_name> <program_name> <script_name> [script args...]`
- `scripts/ghidra_export_apple_bundle <project_name> <program_name>`
- `scripts/ghidra_resolve_swift_outlined <project_name> <program_name> [dry_run=true] [inline=false] [skip_stubs=true] [scan_fun_stubs=true] [second_pass=true] [verbose=true] [build_authstub_map=true] [cache_path=<path>]`
- `scripts/ghidra_build_authstub_map <project_name> <program_name>`  — build/refresh `authstub_map.json` from the live dyld shared cache
- `scripts/ghidra_build_isa_map <project_name> <program_name>`  — build/refresh `isa_map.json` for ObjC runtime isa resolution during LLDB tracing
- `scripts/ghidra_lldb_symbols <binary_path> [<project_name> <program_name>]`  — static symbol inventory via LLDB (ObjC methods, trampolines, etc.)
- `scripts/ghidra_lldb_trace <project_name> <program_name> launch_cmd=<bin> symbols=<syms> [max_hits=100] [timeout=30] [capture_args=true] [capture_backtrace=false] [capture_objc_args=true]`  — runtime breakpoint trace, captures arg registers and optional ObjC self/selector context
- `scripts/ghidra_lldb_enrich <project_name> <program_name> <lldb_trace.json> [output=<path>]`  — enrich runtime hits with Ghidra addresses, function metadata, and xref context
- `scripts/ghidra_diff <project_a> <program_a> <project_b> <program_b> [output=<path>]`  — compare exported `function_inventory.json` files and rank structurally interesting changes
- `scripts/ghidra_generate_harness <enriched_trace.json> [target=<symbol|address>] [language=auto|objc|swift] [output=<path>]`  — generate a safe Swift/Objective-C harness skeleton from an enriched runtime hit
- `scripts/ghidra_xpc_surface <project_name> <program_name> [output=<path>] [markdown_output=<path>]`  — recover XPC service, protocol, listener, and connection hints from existing export JSON
- `scripts/ghidra_xpc_graph <project:program> [project:program ...] [output=<path>] [markdown_output=<path>]`  — merge per-binary XPC surface reports into a coarse IPC graph
- `scripts/ghidra_xpc_trace <project_name> <program_name> attach_name=<process> [timeout=<s>] [max_hits=<n>] [dry_run=true]`  — trace common NSXPC setup calls through the LLDB trace backend
- `scripts/ghidra_frida_trace <project_name> <program_name> symbols=<objc_methods> [process=<name>] [capture_returns=true] [dry_run=true]`  — generate or run a Frida ObjC method trace script
- `scripts/ghidra_frida_heap_scan <class_name> [process=<name>] [dry_run=true]`  — generate or run a Frida ObjC heap enumeration script
- `scripts/ghidra_generate_xpc_harness <project_name> <program_name> [service=<mach-service>] [protocol=<ProtocolName>] [output=<path>]`  — generate a safe Objective-C NSXPCConnection harness skeleton
11b. For runtime analysis of binaries you can launch or attach to, use the LLDB integration tools:
   - `scripts/ghidra_lldb_symbols <binary_path> [<project_name> <program_name>]` — extract the full symbol table (ObjC methods, trampolines, data symbols) from a Mach-O binary in 0.7 s using LLDB's static module loading. No process needed. Outputs `lldb_symbols.json`.
   - `scripts/ghidra_build_isa_map <project_name> <program_name>` — extract concrete `_OBJC_CLASS_$_...` and `_OBJC_METACLASS_$_...` addresses from `symbols.json` and save `isa_map.json` beside the export bundle. Use this before isa-aware LLDB traces so captured `objc_isa` values can be resolved offline.
   - `scripts/ghidra_lldb_trace <project_name> <program_name> launch_cmd=<binary> symbols=<sym1,sym2> [max_hits=100] [timeout=30] [capture_args=true] [capture_backtrace=false] [capture_objc_args=true]` — run a binary under LLDB with breakpoints, capturing argument registers (x0-x7), optional backtraces, and when enabled, `self_ptr`, `objc_isa`, resolved `self_class`, and selector cstrings from `x1`. Outputs `lldb_trace_<timestamp>.json`.
   - `scripts/ghidra_lldb_enrich <project_name> <program_name> <lldb_trace.json>` — map runtime PCs back to Ghidra addresses, attach function summaries and sampled xref context, and write `*_enriched.json`. The Python CLI equivalent is `ghidra-re export lldb-enrich <project> <program> <trace_json>`.
   - `capture_objc_args=true` auto-enables isa capture and tries to build/load `isa_map.json` from the export bundle. If the export bundle is unavailable, tracing still runs and records raw `objc_isa` / selector pointers when possible.
   - For `attach_name=<process>`, LLDB's `--waitfor` attaches only after the process appears, but the wrapper's timeout countdown starts immediately. Use a generous timeout for event-driven targets, start the trace first, then trigger the shortcut or app action right away.
   - LLDB trace works on any binary you compile or own. For system framework analysis, compile a Swift/ObjC test harness that exercises the code path of interest.
- Python post-processing commands:
  - `ghidra-re export class-hierarchy <project_name> <program_name>` — build `class_hierarchy.json` and `class_hierarchy.mmd` from ObjC and Swift layout exports.
  - `ghidra-re export framework-graph <project_name> <program_name>` — build per-program and project-level framework dependency graphs.
  - `ghidra-re export subsystem-clusters <project_name> <program_name>` — group functions by ObjC class, name prefix, and optional xref communities.
  - `ghidra-re export xpc-surface <project_name> <program_name>` — recover probable XPC services, protocols, listeners, and connection methods from existing export JSON.
  - `ghidra-re export xpc-graph <project:program> [project:program ...]` — merge per-binary XPC surface reports and infer service ownership edges.
  - `ghidra-re diff <project_a> <program_a> <project_b> <program_b>` — compare function inventories by name, disambiguate duplicate labels by entry or structure, and emit added/removed/modified summaries.
  - `ghidra-re generate-harness <enriched_trace.json> [target]` — generate a compilable harness skeleton from an enriched trace hit; calls stay commented until valid objects are supplied.
- `scripts/ghidra_swift_surface_report <project_name> <program_name> [query] [format=json|markdown]`
- `scripts/ghidra_describe_swift_type <project_name> <program_name> <type_query>`
- `scripts/ghidra_objc_surface_report <project_name> <program_name> [format=json|markdown]`
- `scripts/ghidra_describe_objc_class <project_name> <program_name> <class_name>`
- `scripts/ghidra_describe_objc_protocol <project_name> <program_name> <protocol_name>`
- `scripts/ghidra_describe_selector <project_name> <program_name> <selector>`
- `scripts/ghidra_trace_classref <project_name> <program_name> <class_name>`
- `scripts/ghidra_objc_message_flow <project_name> <program_name> <selector> [class=<ClassName>]`
- `scripts/ghidra_export_bug_hunt_bundle <project_name> <program_name>`
- `scripts/ghidra_function_dossier <project_name> <program_name> <function_or_address>`
- `scripts/ghidra_apply_finding <project_name> <program_name> <key=value args...>`
- `scripts/ghidra_open_gui <project_name> [program_name]`
- `scripts/ghidra_bridge_build`
- `scripts/ghidra_bridge_install`
- `scripts/ghidra_bridge_arm <project_name> [program_name]`
- `scripts/ghidra_bridge_open <project_name> [program_name]`
- `scripts/ghidra_bridge_close [session=<id>|project=<name>|program=<name>]`
- `scripts/ghidra_bridge_close_all [mission=<name>] [all=true]`
- `scripts/ghidra_bridge_disarm`
- `scripts/ghidra_bridge_sessions`
- `scripts/ghidra_bridge_select session=<id>|project=<name>|program=<name>`
- `scripts/ghidra_bridge_status`
- `scripts/ghidra_bridge_call <endpoint> [json_body]`
- `scripts/ghidra_bridge_current_context`
- `scripts/ghidra_bridge_snapshot [key=value ...]`
- `scripts/ghidra_bridge_analyze_target <query> [key=value ...]`
- `scripts/ghidra_bridge_decompile_current [key=value ...]`
- `scripts/ghidra_bridge_functions_search <query> [key=value ...]`
- `scripts/ghidra_bridge_swift_search <type_or_method> [key=value ...]`
- `scripts/ghidra_bridge_swift_type <TypeName> [key=value ...]`
- `scripts/ghidra_bridge_selector_trace <selector> [key=value ...]`
- `scripts/ghidra_bridge_xrefs [key=value ...]`
- `scripts/ghidra_bridge_rename key=value ...`
- `scripts/ghidra_bridge_comment key=value ...`
- `scripts/ghidra_bridge_apply_signature key=value ...`
- `scripts/ghidra_bridge_apply_type key=value ...`
- `scripts/ghidra_bridge_patch_bytes <address> <hex_bytes>`
- `scripts/ghidra_bridge_patch_instruction <address> <assembly>`
- `scripts/ghidra_bridge_clear_listing <start> [end] [mode]`
- `scripts/ghidra_bridge_disassemble <start> [end]`
- `scripts/ghidra_bridge_create_function <entry> [name] [end]`
- `scripts/ghidra_bridge_delete_function <function_or_address>`
- `scripts/ghidra_bridge_create_data <address> <datatype>`
- `scripts/ghidra_bridge_delete_data <address> [end]`
- `scripts/ghidra_source_add <name> root=<path> [platform=macos-image] [copy=cache|direct]`
- `scripts/ghidra_source_list`
- `scripts/ghidra_source_resolve <name> </path/in/image> [copy=cache|direct]`
- `scripts/ghidra_mission_start <mission_name> goal=... target=... [target=...] [seed=...]`
- `scripts/ghidra_mission_status <mission_name>`
- `scripts/ghidra_mission_trace <mission_name> seed=<kind:value> [target=project:program]`
- `scripts/ghidra_mission_report <mission_name> [format=markdown|json|path]`
- `scripts/ghidra_mission_report <mission_name> [format=markdown|json|path|casefile|casefile-path]`
- `scripts/ghidra_mission_autopilot <mission_name> [rounds=3] [seed=<kind:value>] [target=project:program]`
- `scripts/ghidra_mission_finish <mission_name> [all=true] [keep_sessions_open=true]`
- `scripts/ghidra_notes_add title=... body=... [category=workflow] [target=...]`
- `scripts/ghidra_notes_sync`
- `scripts/ghidra_notes_pull`
- `scripts/ghidra_notes_status`
- `scripts/ghidra_notes_remediate fingerprint=... [summary=...]`
- `scripts/ghidra_notes_open_shared [browse=true]`
- `scripts/bootstrap [--skip-smoke-test]`
- `scripts/doctor`
- `scripts/ghidra_polish_release [mode=quick|release]`
- `scripts/build_share_package [output_zip]`
- `scripts/build_mac_desktop_share_package [output_zip] [--without-ghidra-payload]`
- `scripts/build_windows_desktop_share_package [output_zip] [--ghidra-zip /path/to/ghidra.zip]`
- `powershell/GhidraRe.psd1` and `powershell/GhidraRe.psm1` for native Windows PowerShell wrappers
- `scripts/ghidra_polish_release` for the explicit pre-test release/polish pass

### Script argument style
- Prefer `key=value` arguments because they are robust under `analyzeHeadless`.
- The wrapper also accepts `--key value` and rewrites it to `key=value`.
- Set `GHIDRA_IMPORT_DEMANGLE=0` to skip the default import-time demangle pass.
- Examples:
  - `scripts/ghidra_run_script bsr_smoke BackgroundShortcutRunner DecompileFunction.java function=-[WFBackgroundShortcutRunner runWorkflowWithDescriptor:request:inEnvironment:runningContext:completion:] output=/tmp/wf_runner.c`
  - `scripts/ghidra_run_script bsr_smoke BackgroundShortcutRunner ExportXrefs.java --symbol _objc_msgSend --output /tmp/objc_msgsend_xrefs.json`

## Built-ins Vs Custom Scripts

- Prefer the custom scripts in `scripts/ghidra_scripts/` for structured exports and repeatable output.
- The main custom scripts are:
  - `ExportAppleBundle.java`
  - `ExportEntrypoints.java`
  - `ExportSinks.java`
  - `TriageBugPaths.java`
  - `ExportFunctionDossier.java`
  - `ApplyFinding.java`
  - `DecompileFunction.java`
  - `ExportXrefs.java`
- Prefer built-in scripts only when they already solve the job cleanly.
- Safe default built-in:
  - `DemangleAllScript.java`
- Built-ins that are often useful but context-sensitive:
  - `SwiftDemanglerScript.java`
  - `MachO_Script.java`
- Built-ins that are less suited to headless automation because they prompt or assume a GUI cursor:
  - `ExportFunctionInfoScript.java`

Use `scripts/ghidra_run_script` for both built-ins and custom scripts. It adds the custom script directory and the common built-in Ghidra script directories to `-scriptPath`.

## References

Read only what you need:

- Apple Mach-O notes and common targets: `references/apple-macho-notes.md`
- Output files and schemas: `references/output-files.md`
- Bridge session and operation-log notes: `references/output-files.md`
- Bug-hunt output bundle details: `references/bug-hunt-outputs.md`
- Bug-hunt heuristics and categories: `references/bug-hunt-patterns.json`
- Built-in script caveats: `references/builtins.md`
- Use-case-driven skill improvement notes: shared via the GitHub-backed notes commands above; `references/use-case-driven-notes.md` is legacy/reference history inside the repo
