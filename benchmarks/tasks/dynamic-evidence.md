# Dynamic Evidence

## Objective

Measure whether the fresh agent can collect bounded runtime evidence and keep
runtime claims separate from blockers.

## Fresh-Instance Prompt

Use the same fixture binary from the static task. Run a bounded LLDB trace when
LLDB and the fixture are available. Prefer a short-lived owned process over
attaching to unrelated live processes. If LLDB cannot run, record the exact
blocker and retry condition.

## Required Evidence

- Record the LLDB trace command or blocker.
- Preserve generated trace JSON, runtime hit JSON, and any enrichment artifact.
- Record whether runtime hits were observed, not observed, or unavailable.
- Update task status and verification counts in `metrics.json`.

## Acceptance Checks

- Runtime-hit claims require a generated artifact.
- Zero-hit evidence is kept separate from missing-breakpoint and missing-LLDB
  conditions.
- Partial traces or timeouts are not upgraded to clean success.
