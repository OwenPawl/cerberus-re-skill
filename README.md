# ghidra-re

> **Works with both [OpenAI Codex](https://openai.com/codex) and [Anthropic Claude Code](https://claude.ai/code) — install once, use with either.**

![Claude Code](https://img.shields.io/badge/Claude%20Code-skill-orange?logo=anthropic)
![OpenAI Codex](https://img.shields.io/badge/OpenAI%20Codex-skill-412991?logo=openai)
![macOS](https://img.shields.io/badge/macOS-arm64-black?logo=apple)
![Windows](https://img.shields.io/badge/Windows-x86__64-blue?logo=windows)

`ghidra-re` is a local skill for Ghidra-based reverse engineering on macOS and Windows, with a workflow tuned for Apple Mach-O binaries, dyld-extracted frameworks, multi-target investigation missions, and a live Ghidra bridge for iterative RE sessions.

**Dual-host by design.** The same checkout installs as either an **OpenAI Codex** skill (`~/.codex/skills/ghidra-re`) or an **Anthropic Claude Code** skill (`~/.claude/skills/ghidra-re`), or both simultaneously. A single unified backend in `scripts/` and `powershell/` is shared across hosts — there is no host-specific fork of any script. See [`scripts/lib/skill_host.sh`](./scripts/lib/skill_host.sh) for the unified host-resolution layer.

| Host | Install path | Reads |
|------|-------------|-------|
| **Claude Code** (Anthropic) | `~/.claude/skills/ghidra-re` | `SKILL.md` frontmatter |
| **Codex** (OpenAI) | `~/.codex/skills/ghidra-re` | `SKILL.md` + `agents/openai.yaml` |

## What it includes

- Headless import and analysis helpers
- Structured exports for functions, strings, symbols, Objective-C metadata, and xrefs
- Richer Swift exports with demangled alias maps, metadata-section recovery, and surface-level type reports
- LLDB runtime trace capture and static enrichment back into Ghidra function context
- Structural function-inventory diffs for comparing exported binaries across builds or OS versions
- Trace-driven Swift/Objective-C harness skeleton generation from enriched runtime hits
- XPC surface reports from existing ObjC/string/symbol export bundles
- A multi-session live Ghidra bridge registry for several open targets at once
- Bridge snapshots, mission finish/cleanup, and an autonomous multi-round mission driver
- Mission workspaces with a persistent SQLite investigation graph, notes, and reports
- Smarter autopilot seed ranking, richer live snapshots, and mission case files for closeout
- Function dossiers, write-back helpers, and optional bug-hunt overlays
- A live Ghidra bridge extension for navigation, decompilation, comments, renames, and controlled program surgery
- Dyld-aware import helpers for macOS frameworks and cache-backed Apple binaries
- Share-package builders for handing the skill to another Mac

## Layout

- [SKILL.md](./SKILL.md): skill entrypoint and workflow instructions, loaded by both Codex and Claude Code
- [scripts](./scripts): shell wrappers, builders, and the host-agnostic `install_skill`
- [scripts/lib/skill_host.sh](./scripts/lib/skill_host.sh): unified "which skill host am I running under" resolution layer
- [powershell](./powershell): native PowerShell module for Windows-first usage (probes both `CODEX_HOME` and `CLAUDE_HOME`)
- [bridge-extension](./bridge-extension): Ghidra bridge source and prebuilt extension zips
- [references](./references): notes, schemas, and heuristics
- [agents/openai.yaml](./agents/openai.yaml): optional Codex discovery metadata; Claude Code reads `SKILL.md` frontmatter directly

## Shared notes

`ghidra-re` now has a GitHub-backed global use-case notes system.

- Canonical public backlog: one GitHub issue in `OwenPawl/ghidra-re-skill`
- Local resilience layer: `~/.config/ghidra-re/shared-notes/`
- Write path: structured local queue first, then sync to GitHub when `gh` is authenticated

The main commands are:

```bash
ghidra-re notes status
ghidra-re notes add --title 'Missing live-export ingest' --body 'Baseline export still requires close/reopen for an already-open target.' --category workflow --target workflowkit_bug_smoke:WorkflowKit
ghidra-re notes sync
ghidra-re notes pull
ghidra-re notes open-shared
```

The old [use-case-driven-notes.md](./references/use-case-driven-notes.md) file is now legacy/reference-only and no longer the canonical live backlog.

## Quick install

The recommended install path for either host is the Python CLI installer. It copies the checkout into the right place, runs `bootstrap`, and installs the Ghidra live-bridge extension:

```bash
pip install -e .                                          # install the Python package first
ghidra-re install                                         # auto-detect host(s): Codex, Claude Code, or both
ghidra-re install --host codex                            # force Codex only
ghidra-re install --host claude                           # force Claude Code only
ghidra-re install --host both                             # install into every known host
```

Or install manually:

```bash
# Codex
mkdir -p ~/.codex/skills
cp -R . ~/.codex/skills/ghidra-re
pip install -e ~/.codex/skills/ghidra-re
ghidra-re bootstrap

# Claude Code
mkdir -p ~/.claude/skills
cp -R . ~/.claude/skills/ghidra-re
pip install -e ~/.claude/skills/ghidra-re
ghidra-re bootstrap
```

Both hosts load the same `SKILL.md` (YAML frontmatter with `name` + `description`) and the same Python CLI surface; nothing in the skill needs to know which host launched it.

If you want a one-file share bundle:

```bash
ghidra-re publish share                        # cross-platform zip
ghidra-re publish mac-desktop                  # macOS zip with optional Ghidra payload
ghidra-re publish windows-desktop              # Windows zip with PowerShell installer
```

The macOS bundle can install the skill, Ghidra, the launcher app, and Java 21 on another Mac.
The Windows bundle includes a PowerShell installer that can:
- install the skill into `%USERPROFILE%\.codex\skills\ghidra-re`
- install a user-scoped `GhidraRe` PowerShell module
- reuse an existing Ghidra install or unpack `payload\Ghidra.zip`, `Ghidra.zip`, or a `ghidra_*.zip` placed next to the installer into `%LOCALAPPDATA%\Programs\Ghidra`
- run bootstrap using an existing Java 21 JDK

## Publish to GitHub

If `gh` is installed and authenticated, publish the repository directly:

```bash
gh repo create ghidra-re-skill --public --source=. --push
```

## Requirements

- macOS or Windows
- Ghidra 12.0.4
- Java 21
- A supported skill host (any of: OpenAI Codex with local skill support, Anthropic Claude Code with local skill support)

On Windows, you can now use either Git Bash or the native `GhidraRe` PowerShell module.

The default local assumptions are:

- Ghidra install:
  - macOS: `/Applications/Ghidra`
  - Windows: `%LOCALAPPDATA%\Programs\Ghidra` for a user-scoped install; `C:\Program Files\Ghidra` is also detected when already installed
- Launcher app:
  - macOS: `/Applications/Ghidra.app`
  - Windows: `ghidraRun.bat`
- JDK:
  - macOS: `/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home`
  - Windows: `/c/Program Files/Eclipse Adoptium/jdk-21`
- Workspace: `~/ghidra-projects`

On Windows, `GHIDRA_INSTALL_DIR` and `GHIDRA_HOME` are treated as explicit overrides, not required setup. `ghidra-re bootstrap` should auto-detect normal install locations and then persist the resolved path in `%APPDATA%\ghidra-re\config.env`.

Shared-notes defaults:

- Repo: `OwenPawl/ghidra-re-skill`
- Auto-sync: on when `gh` is authenticated
- Local queue/cache: `~/.config/ghidra-re/shared-notes/`

## Windows Apple-target flow

The Windows installer installs a PowerShell module named `GhidraRe`. After install:

```powershell
Import-Module GhidraRe
Get-GhidraReBridgeSessions
Start-GhidraReMission -Name win_trace -Goal 'Trace a subsystem' -Target 'source:mac-image:/System/Library/PrivateFrameworks/WorkflowKit.framework/Versions/A/WorkflowKit'
```

The module is a native PowerShell-facing layer over the same `ghidra-re` Python CLI.

The shared-notes flow is also available from PowerShell:

```powershell
Get-GhidraReNotesStatus
Add-GhidraReNote -Title 'Missing feature' -Body 'Describe the friction here.'
Sync-GhidraReNotes
Receive-GhidraReNotes
Open-GhidraReSharedNotes
```

When a Windows machine needs Apple binaries, register a mounted or extracted macOS root as a source:

```bash
ghidra-re bridge call /source/add mac-image root=/d/macos-root platform=macos-image copy=cache
ghidra-re import analyze source:mac-image:/System/Library/PrivateFrameworks/VoiceShortcuts.framework/Versions/A/VoiceShortcuts
```

Mission targets can use the same source form:

```bash
ghidra-re mission start win_trace \
  --goal 'Trace a subsystem across Apple userland targets' \
  --target 'source:mac-image:/System/Library/PrivateFrameworks/WorkflowKit.framework/Versions/A/WorkflowKit'
```

If you are preparing a Windows share package on another machine and already have a Windows Ghidra zip, you can embed it:

```bash
ghidra-re publish windows-desktop out.zip --ghidra-zip /path/to/ghidra_*.zip
```

## Recent Robustness Improvements

The following low-level improvements were applied to the Python package after the initial cross-platform refactor, based on a thorough code review:

| Area | Improvement |
|------|-------------|
| **Bridge XML patching** | `_patch_tool_xml` / `_patch_frontend_xml` now use `xml.etree.ElementTree` instead of fragile regex substitutions. The parser safely removes the old "Codex Bridge" `PACKAGE`, removes stray `INCLUDE` elements, inserts `CodexBridgePlugin` inside the `"Ghidra Core"` `PACKAGE`, and skips malformed files with a warning rather than corrupting them. |
| **Stale-lock detection** | The directory-based `bridge-current.lock` now checks `lock.stat().st_mtime` on each retry. If the lock is older than 30 seconds (configurable) it is removed automatically, preventing permanent hangs after a crash or SIGKILL. |
| **Windows process check** | `check_pid_alive()` on Windows now opens the process with `PROCESS_QUERY_LIMITED_INFORMATION` (0x1000), calls `GetExitCodeProcess`, and confirms the exit code equals 259 (`STILL_ACTIVE`). The handle is always closed in a `finally` block. |
| **Safe publisher backups** | `install_skill` uses `datetime`-based timestamps and calls `shutil.rmtree(backup)` before `shutil.move` when the backup path already exists, preventing unintended nesting (e.g. `ghidra-re.backup-TS/ghidra-re`). |
| **`shutil.copytree` tree copy** | The manual recursive `_copy_tree` was replaced with `shutil.copytree(..., ignore=ignore_func, dirs_exist_ok=True)`, which is faster, handles symlinks correctly, and uses the stdlib's battle-tested copy engine. |

These changes improve reliability during long-running headless analysis, on Windows with rapid lock-acquire / lock-release cycles, and whenever the bridge extension is installed or reinstalled multiple times in the same Ghidra settings directory.



```bash
./scripts/bootstrap
./scripts/ghidra_mission_start my_mission \
  goal='Trace a subsystem across related targets' \
  target=/absolute/path/to/binary \
  target=existing_project:FrameworkName
./scripts/ghidra_mission_trace my_mission seed=selector:initWithCoder:
./scripts/ghidra_mission_autopilot my_mission rounds=2
./scripts/ghidra_mission_report my_mission
./scripts/ghidra_mission_report my_mission format=casefile
./scripts/ghidra_mission_finish my_mission shared_note_title='Autopilot friction' shared_note_body='Need a better ObjC sender ranking view in live snapshots.'
```

For a focused single-target session, the fastest interactive loop is usually:

```bash
./scripts/ghidra_import_analyze /path/to/binary my_project
./scripts/ghidra_export_apple_bundle my_project BinaryName
./scripts/ghidra_bridge_open my_project BinaryName
./scripts/ghidra_bridge_functions_search 'SomeFunctionName'
./scripts/ghidra_bridge_analyze_target 'SomeFunctionName'
./scripts/ghidra_bridge_selector_trace 'someSelector:'
./scripts/ghidra_bridge_snapshot
```

`ghidra_bridge_snapshot` now resolves the containing function from the current address when possible, so bridge snapshots stay useful even when the UI is parked mid-function instead of at a clean entry point.

For a live multi-target session, start with the registry:

```bash
./scripts/ghidra_bridge_sessions
./scripts/ghidra_bridge_select project=workflowkit_bug_smoke
```

Prefer `project=` or `session=` when two live targets share the same program name.

The optional bug-hunt layer is still there when you want it:

```bash
./scripts/ghidra_export_bug_hunt_bundle my_project BinaryName
./scripts/ghidra_function_dossier my_project BinaryName 100012340
```

For Swift-heavy Apple frameworks, the higher-signal flow is now:

```bash
./scripts/ghidra_import_macos_framework /System/Library/PrivateFrameworks/VoiceShortcuts.framework/VoiceShortcuts
./scripts/ghidra_export_apple_bundle VoiceShortcuts_<hash> VoiceShortcuts
./scripts/ghidra_swift_surface_report VoiceShortcuts_<hash> VoiceShortcuts query=VoiceShortcuts. format=markdown
./scripts/ghidra_describe_swift_type VoiceShortcuts_<hash> VoiceShortcuts VoiceShortcuts.SpotlightIndexingCoordinator
./scripts/ghidra_bridge_open VoiceShortcuts_<hash> VoiceShortcuts
./scripts/ghidra_bridge_swift_search 'VoiceShortcuts.EventNode'
./scripts/ghidra_bridge_swift_type VoiceShortcuts.SpotlightIndexingCoordinator
```

`ghidra_bridge_open` now waits until both `/health` and `/session` succeed before it returns, so “bridge armed” also means “bridge is queryable.”

For ObjC-heavy Apple frameworks or mixed Swift/ObjC subsystems, prefer:

```bash
./scripts/ghidra_export_apple_bundle workflowkit_full_dyld_extract WorkflowKit
./scripts/ghidra_objc_surface_report workflowkit_full_dyld_extract WorkflowKit markdown
./scripts/ghidra_describe_objc_class workflowkit_full_dyld_extract WorkflowKit WFRemoteExecutionCoordinator
./scripts/ghidra_describe_objc_protocol workflowkit_full_dyld_extract WorkflowKit IndexedEntity
./scripts/ghidra_describe_selector workflowkit_full_dyld_extract WorkflowKit 'handleRunRequest:service:account:fromID:context:'
./scripts/ghidra_trace_classref workflowkit_full_dyld_extract WorkflowKit WFRemoteExecutionCoordinator
./scripts/ghidra_objc_message_flow workflowkit_full_dyld_extract WorkflowKit 'handleRunRequest:service:account:fromID:context:' class=WFRemoteExecutionCoordinator
```

Those helpers merge the richer `symbols.json` ObjC method surface with `objc_metadata.json`, so imported-style methods like `-[WFRemoteExecutionCoordinator_handleRunRequest:...]` still show up even when the flatter metadata method bucket is incomplete. `ghidra_objc_message_flow` builds on top of that by grouping receiver classes, sibling selectors, and live sender hints when a bridge session is available.

For runtime traces, capture symbols with LLDB and enrich the resulting PCs back into the static model:

```bash
./scripts/ghidra_lldb_symbols /path/to/WorkflowKit workflowkit_full_dyld_extract WorkflowKit
./scripts/ghidra_lldb_trace workflowkit_full_dyld_extract WorkflowKit attach_name=BackgroundShortcutRunner symbols='-[WFAction runWithInput:userInterface:runningDelegate:variableSource:workQueue:completionHandler:]' capture_objc_args=true timeout=90
./scripts/ghidra_lldb_enrich workflowkit_full_dyld_extract WorkflowKit ~/ghidra-projects/exports/workflowkit_full_dyld_extract/WorkflowKit/lldb_trace_<timestamp>.json
```

The Python CLI equivalent for the last step is `ghidra-re export lldb-enrich <project> <program> <trace_json>`.

To compare two exported binaries without reopening Ghidra, diff their latest `function_inventory.json` files:

```bash
./scripts/ghidra_diff workflowkit_full_dyld_extract WorkflowKit workflowkit_dyld_arm64e_macos WorkflowKit output=/tmp/workflowkit_diff.json
ghidra-re diff workflowkit_full_dyld_extract WorkflowKit workflowkit_dyld_arm64e_macos WorkflowKit --output /tmp/workflowkit_diff.json
```

The current diff aligns by function name and disambiguates duplicate names by entry or structural metadata. It reports added, removed, modified, and unchanged functions plus a lightweight patch-relevance score. Instruction-mnemonic fingerprints and decompile comparisons are planned once headless Ghidra/JDK validation is available.

To turn an enriched runtime hit into a starting harness:

```bash
./scripts/ghidra_generate_harness ~/ghidra-projects/exports/workflowkit_full_dyld_extract/WorkflowKit/lldb_trace_<timestamp>_enriched.json output=/tmp/workflowkit_harness.m
ghidra-re generate-harness ~/ghidra-projects/exports/workflowkit_full_dyld_extract/WorkflowKit/lldb_trace_<timestamp>_enriched.json --language swift --output /tmp/workflowkit_harness.swift
```

The generated harness loads the target framework, records the observed function/symbol/address context, preserves argument-register pointers as comments/logs, and emits safe fuzzable placeholders. Calls are commented out until the placeholders are replaced with valid target-specific objects.

To recover XPC topology hints from an existing export bundle:

```bash
./scripts/ghidra_xpc_surface workflowkit_full_dyld_extract WorkflowKit output=/tmp/workflowkit_xpc_surface.json markdown_output=/tmp/workflowkit_xpc_surface.md
ghidra-re export xpc-surface workflowkit_full_dyld_extract WorkflowKit --output /tmp/workflowkit_xpc_surface.json --markdown-output /tmp/workflowkit_xpc_surface.md
```

This Python-first pass does not require reopening Ghidra. It extracts probable mach services, XPC-related classes/protocols/selectors, listener methods, and connection methods from the existing Apple export bundle.

To merge multiple XPC surface reports into a coarse IPC graph:

```bash
./scripts/ghidra_xpc_graph workflowkit_full_dyld_extract:WorkflowKit bsr_smoke:BackgroundShortcutRunner output=/tmp/shortcuts_xpc_graph.json markdown_output=/tmp/shortcuts_xpc_graph.md
ghidra-re export xpc-graph workflowkit_full_dyld_extract:WorkflowKit bsr_smoke:BackgroundShortcutRunner --output /tmp/shortcuts_xpc_graph.json --markdown-output /tmp/shortcuts_xpc_graph.md
```

The graph pass auto-builds missing `xpc_surface.json` reports, then infers ownership edges by matching service names to target program names. For example, WorkflowKit references BackgroundShortcutRunner through `com.apple.shortcuts.background-shortcut-runner`.

For live XPC setup tracing, use the LLDB-backed wrapper:

```bash
./scripts/ghidra_xpc_trace workflowkit_full_dyld_extract WorkflowKit attach_name=BackgroundShortcutRunner timeout=60 max_hits=25
./scripts/ghidra_xpc_trace workflowkit_full_dyld_extract WorkflowKit dry_run=true
```

The wrapper delegates to `ghidra_lldb_trace` with default NSXPC connection/listener symbols, ObjC argument capture, and backtraces enabled. Use `dry_run=true` to inspect the exact delegated LLDB command before attaching to a process.

For Frida-based tracing on systems where Frida is installed:

```bash
./scripts/ghidra_frida_trace workflowkit_full_dyld_extract WorkflowKit symbols='-[WFAction runWithInput:userInterface:runningDelegate:variableSource:workQueue:completionHandler:]' process=BackgroundShortcutRunner capture_returns=true
./scripts/ghidra_frida_heap_scan WFAction process=BackgroundShortcutRunner
```

Both wrappers support `dry_run=true`, which generates Frida JavaScript without requiring the local Frida CLI. Generated events are emitted with `GHIDRA_FRIDA_*` prefixes for downstream parsing.

To generate a safe XPC client harness from an XPC surface report:

```bash
./scripts/ghidra_generate_xpc_harness workflowkit_full_dyld_extract WorkflowKit service=com.apple.shortcuts.background-shortcut-runner protocol=WFMacHelperXPCProtocol output=/tmp/background_runner_xpc_harness.m
ghidra-re generate-xpc-harness workflowkit_full_dyld_extract WorkflowKit --service com.apple.shortcuts.background-shortcut-runner --protocol WFMacHelperXPCProtocol --output /tmp/background_runner_xpc_harness.m
```

The generated Objective-C harness creates an `NSXPCConnection`, configures `remoteObjectInterface` when a protocol is supplied, and leaves remote method invocation as an explicit TODO.

## Notes

- Real workflow friction and wishlist items now live in the shared GitHub-backed notes flow. Use `./scripts/ghidra_notes_add` for new items and `./scripts/ghidra_notes_open_shared` for the canonical public backlog.
- [use-case-driven-notes.md](./references/use-case-driven-notes.md) remains in the repo as legacy/reference history, not the canonical day-to-day write target.
- Mission workspaces live under `~/ghidra-projects/investigations/<mission_name>/`.
- Finished missions now also emit `reports/casefile.md` and `reports/casefile.json` for analyst-friendly closeout.
- The live bridge keeps one compatibility pointer in `bridge-current.json`, but the real session registry lives under `~/.config/ghidra-re/bridge-sessions/`.
- The skill prefers the live bridge when an iterative GUI session is more useful than another headless export pass, and now supports selecting among multiple live targets.
- `ExportAppleBundle.java` now emits richer `swift_metadata.json` content, including demangled/raw names, stable aliases, metadata-section summaries, async-like entries, protocol witness hints, and dispatch-thunk tagging.
- The Windows desktop installer also installs a user PowerShell module so day-to-day Windows use does not have to start in Git Bash.
- `ghidra_mission_finish` closes the mission's live Ghidra sessions by default, and `ghidra_bridge_close_all all=true` is the emergency cleanup button when you want every bridge-managed Ghidra window gone.
- `ghidra_polish_release` is the explicit pre-testing pass for syntax, builders, bridge buildability, and packaging.
