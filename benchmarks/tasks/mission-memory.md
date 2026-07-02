# Mission Memory

## Objective

Measure whether the fresh agent preserves truth, context, claims, failures, and
next actions over a resumable task.

## Fresh-Instance Prompt

Use the result bundle as the durable state target. If long-run-agent is enabled
for this configuration, initialize and use its mission harness. If it is not
enabled, create equivalent human-readable and JSON/JSONL records manually in
the result bundle. Simulate a handoff by writing a concise resume note and then
using only files in the bundle to summarize current state.

## Required Evidence

- Record commands, claims, artifacts, failures, and next actions.
- Record at least one claim with a verification command or explicit
  no-verification reason.
- Record at least one failure or blocker if any task was partial or blocked.
- Include a resume summary that does not rely on chat-only context.

## Acceptance Checks

- Important state is not left only in the chat transcript.
- Claims, artifacts, and failures point to each other clearly enough for a fresh
  agent to resume.
- The final summary distinguishes completed, partial, blocked, and not-run
  work.
