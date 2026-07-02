# Cerberus RE

`cerberus-re` is a local Apple-focused reverse-engineering workbench for
building a repeatable three-headed static/dynamic/instrumentation loop around
Ghidra, LLDB, and Frida.

It is designed for analysts and coding agents that need durable artifacts
instead of terminal-only notes:

- Ghidra import, headless export, decompilation, xrefs, and metadata recovery.
- LLDB runtime traces with static enrichment back into exported function context.
- Frida diagnostics, guarded runtime rechecks, Objective-C probes, and heap or archive inspection helpers.
- XPC surface and graph reports from exported Objective-C/string/symbol data.
- RE evidence reports, notes, case files, and release-gate validation checks.
- Cross-platform Python CLI support for macOS, Linux, Windows, OpenAI Codex, and Claude Code.

Runtime attach and target invocation are always explicit. The tooling favors
owned processes, no-attach validation, generated artifacts, and bounded probes
whose assumptions are recorded alongside the evidence.

## Public Scope

The public workbench is general Apple binary-analysis infrastructure: Ghidra
imports and exports, LLDB/Frida correlation, Mach-O/ObjC/Swift/XPC evidence,
and portable reports. It is not a project-specific research log or a generic
long-running agent memory system. Domain-specific research workflows should
live in private overlays or durable run artifacts, while generic long-run state
belongs in `long-run-agent`.

## Strongly Encouraged Companion Dependency

Use Cerberus RE with `long-run-agent` for substantial reverse-engineering work.
Cerberus RE provides the static, dynamic, and instrumentation workbench;
`long-run-agent` preserves mission state, claims, artifacts, failures, friction,
and next actions so longer investigations stay auditable and resumable.
Cerberus RE can run by itself for bounded tasks, but benchmark and release
workflows should prefer the combined `cerberus-re + long-run-agent`
configuration.

## Install

For a fresh checkout, start with the dependency installer in dry-run mode:

```bash
python3 scripts/install_dependencies.py
python3 scripts/install_dependencies.py --execute
source .venv/bin/activate
cerberus-re bootstrap
```

The installer creates a local virtual environment, installs Cerberus RE, and
adds Frida Python tooling. On macOS with Homebrew it can install Ghidra/Java
and Node. On Linux and Windows it prints package-manager-specific commands for
review instead of running system installs automatically.

If your system dependencies are already present:

```bash
pip install -e .
cerberus-re bootstrap
```

Optional skill install:

```bash
cerberus-re install --host codex
cerberus-re install --host claude
cerberus-re install --host both
```

## Requirements

- Python 3.11+
- Ghidra 12.x
- Java 21
- macOS, Linux, or Windows for the Python CLI and report tooling
- macOS for Apple runtime attach workflows against local Apple frameworks
- LLDB and Frida only for the workflows that use them

Default paths can be overridden with environment variables documented in
`templates/config.env.example`.

## Core Loop

```bash
cerberus-re doctor
cerberus-re bootstrap
cerberus-re import analyze /path/to/Binary my_project
cerberus-re export apple-bundle my_project BinaryName
cerberus-re bridge arm my_project BinaryName
cerberus-re bridge call /functions/search '{"query":"interestingName"}'
cerberus-re validate lldb-trace my_project BinaryName --launch-cmd /path/to/host --symbols '-[Owner selector:]'
cerberus-re validate lldb-trace my_project BinaryName --launch-cmd /path/to/host --symbols FirstExport --symbols SecondExport
cerberus-re frida validate-scripts
cerberus-re frida recheck-attach --target /path/to/owned-host --symbol '-[Owner selector:]' --allow-runtime
cerberus-re export runtime-enrich my_project BinaryName /path/to/runtime_hits.json
```

## Useful Commands

```bash
cerberus-re export xpc-surface my_project BinaryName
cerberus-re export xpc-graph my_project:BinaryName other_project:OtherBinary
cerberus-re export function-dossier my_project BinaryName --function '-[Owner selector:]'
cerberus-re export triage-bundle my_project BinaryName --top-candidates 25
cerberus-re polish release --mode quick --strict-command-surface
```

If `export xpc-surface` reports zero counts, inspect `warnings` and
`missing_input_count` before using that as absence evidence. Pass `--bundle-dir`
or explicit export JSON paths when analyzing an Apple bundle stored outside the
default export directory.

Use `python3 -m cerberus_re_skill` or `cerberus-re` for automation. Generic
long-running run state, steering files, durable project memory, and agent
closeout orchestration belong in `long-run-agent`, not this workbench.

## Benchmarks

The public benchmark scaffold defines a reproducible agent/task matrix without
shipping benchmark results:

```bash
python3 scripts/agent_benchmark.py list
python3 scripts/agent_benchmark.py scaffold --runner codex --configuration cerberus-re-long-run-agent --output benchmarks/results/example/codex/cerberus-re-long-run-agent
python3 scripts/agent_benchmark.py validate --bundle benchmarks/results/example/codex/cerberus-re-long-run-agent
```

Use `benchmarks/agent_benchmark.v1.json` as the machine-readable source of
truth. A scaffolded bundle is only a result after a real runner records durable
commands, claims, artifacts, failures, and metrics.

## Safety Model

- No runtime attach happens unless a command receives an explicit runtime flag.
- Mutating bridge calls require explicit write opt-in.
- Destructive bridge calls require a separate destructive opt-in.
- Generated harnesses leave calls commented or bounded until the caller supplies target-specific objects.
- Reports should distinguish successful runtime hits, no-hit status, attach blockers, and unverified assumptions.

## Repository Layout

- `SKILL.md`: agent-facing operating procedure.
- `cerberus_re_skill/`: Python CLI and report builders.
- `scripts/`: installer, helper scripts, sourced shell libraries, and Ghidra Java scripts.
- `bridge-extension/`: Ghidra bridge source.
- `references/`: public command and artifact references.
- `benchmarks/`: benchmark definition, result-bundle scaffold, and future public result shapes.
- `tests/`: smoke and regression tests.

## Validation

Before publishing a milestone:

```bash
python3 -m unittest discover -s tests
python3 -m compileall cerberus_re_skill scripts tests
python3 -m cerberus_re_skill polish release --mode quick --strict-command-surface
python3 -m cerberus_re_skill bridge audit
git diff --check
```

## License

Apache-2.0. See `LICENSE`.
