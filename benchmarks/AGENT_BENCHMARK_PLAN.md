# Agent Benchmark Plan

Status: scaffolded. This directory defines the public benchmarking shape and a
small result-bundle scaffold/validator. It does not run agents, assign scores,
or report benchmark results yet.

Summary: this scaffold does not run agents, assign scores, or report benchmark results yet.

## Purpose

Measure whether Cerberus RE and long-run-agent improve an agent's ability to
produce verified reverse-engineering evidence, preserve truth over a long task,
and recover context without drifting. The benchmark should be runnable by fresh
instances of Claude Code and Codex against public, reproducible fixtures.

## Agent Runners

- Claude Code, fresh instance.
- Codex, fresh instance.

## Skill Configuration Matrix

Each runner should execute the same task set under four configurations:

| Configuration | Enabled tools | Expected pressure |
| --- | --- | --- |
| No skills | No project-specific skills loaded. | Baseline exploration, command discovery, and documentation drift. |
| long-run-agent only | Mission harness and durable state procedures only. | Truth preservation, claim tracking, resumability, and user steering. |
| cerberus-re only | Cerberus RE static/dynamic/injection workflow only. | RE artifact quality, command selection, and verification discipline. |
| cerberus-re + long-run-agent | Both skills loaded. | Full static/dynamic/injection RE loop plus durable mission memory. |

## Definition And Scaffold

The machine-readable benchmark definition is:

```text
benchmarks/agent_benchmark.v1.json
```

Use the helper script to inspect the matrix, create a result bundle, and
generate the prompt to give to a fresh agent instance:

```bash
python3 scripts/agent_benchmark.py list
python3 scripts/agent_benchmark.py list --json
python3 scripts/agent_benchmark.py prompt \
  --runner codex \
  --configuration cerberus-re-long-run-agent \
  --bundle benchmarks/results/<date>/codex/cerberus-re-long-run-agent \
  --output benchmarks/results/<date>/codex/cerberus-re-long-run-agent.prompt.md
python3 scripts/agent_benchmark.py scaffold \
  --runner codex \
  --configuration cerberus-re-long-run-agent \
  --output benchmarks/results/<date>/codex/cerberus-re-long-run-agent
python3 scripts/agent_benchmark.py validate \
  --bundle benchmarks/results/<date>/codex/cerberus-re-long-run-agent
```

The scaffold command writes empty evidence files only. A bundle is not a
benchmark result until an actual runner fills in commands, claims, artifacts,
failures, and metrics with verification evidence.

The concrete task cards live in `benchmarks/tasks/`. The `prompt` command
embeds those cards with runner/configuration-specific operating rules so the
same benchmark can be handed to fresh Claude Code and Codex instances.

## Initial Task Set

Use public fixtures or locally generated binaries only. Do not require private
Apple targets, personal state, or manual GUI interaction for phase one.

1. Environment setup task: `benchmarks/tasks/environment-setup.md`.
   - Start from a fresh checkout.
   - Install dependencies with the documented install path.
   - Run `cerberus-re doctor` and record unresolved prerequisites honestly.

2. Static evidence task: `benchmarks/tasks/static-evidence.md`.
   - Build a small Objective-C fixture from `tests/fixtures`.
   - Import it into Ghidra or explain why Ghidra is unavailable.
   - Export an Apple bundle or equivalent static artifact.
   - Identify at least one class, selector, string, symbol, and function.

3. Dynamic evidence task: `benchmarks/tasks/dynamic-evidence.md`.
   - Run a bounded LLDB trace against the fixture.
   - Preserve command output and any generated JSON artifacts.
   - Correlate runtime hits back to static function context when possible.

4. Injection evidence task: `benchmarks/tasks/instrumentation-evidence.md`.
   - Generate or validate a Frida script without attaching unless runtime
     permissions and explicit flags are available.
   - If live Frida is unavailable, record the blocker and keep script validation
     evidence separate from runtime-hit claims.

5. Mission-memory task: `benchmarks/tasks/mission-memory.md`.
   - Record claims, artifacts, commands, failures, and next actions.
   - Interrupt and resume the run from durable files.
   - Verify that important context is not left only in chat history.

## Metrics

- Completion: task finished, partially finished, or blocked with a valid retry
  condition.
- Evidence quality: artifacts are durable, machine-readable where appropriate,
  and linked to the claim they support.
- Claim discipline: claims distinguish proposed, implemented, tested, blocked,
  and stale states.
- Verification coverage: each major claim has a command or explicit reason why
  verification was not possible.
- Recovery quality: a fresh agent can resume from files without relying on chat
  history.
- Command efficiency: number of failed or redundant commands before useful
  evidence appears.
- Safety/guardrails: runtime attach, writes, and destructive actions require
  explicit opt-in and are not hidden behind convenience wrappers.
- Public readiness: no benchmark task depends on internal research history.

## Result Shape

Benchmark runs should produce one result bundle per runner/configuration:

```text
benchmarks/results/<date>/<runner>/<configuration>/
  README.md
  commands.jsonl
  claims.json
  artifacts.json
  failures.md
  metrics.json
```

`metrics.json` includes the runner, configuration, commit hash, host platform,
elapsed time, task statuses, verification counts, and a short human-readable
assessment. Fresh scaffolded bundles start with every task marked `not_run`.

## Non-Goals For This Scaffold

- No automated agent runner is implemented yet.
- No scores are assigned yet.
- No private target, personal workflow, or security-research-specific task is
  part of the public benchmark.
- No hosted benchmark infrastructure is assumed.
- No benchmark data is included in the public repo until a real run has been
  executed and validated.
