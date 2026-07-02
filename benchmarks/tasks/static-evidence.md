# Static Evidence

## Objective

Measure whether the fresh agent can produce durable static reverse-engineering
evidence from a public local fixture.

## Fresh-Instance Prompt

Use `tests/fixtures/CodexObjCProbe.m` as the target fixture. Build it into a
local binary if the host toolchain supports that. Attempt a Cerberus/Ghidra
static import if Ghidra is available. If Ghidra is unavailable, produce the best
honest static artifact available from local command-line tools and record the
missing prerequisite.

## Required Evidence

- Record the fixture build command and output.
- Record the import/export command or the missing-prerequisite blocker.
- Preserve any generated JSON or Markdown static artifact.
- Record at least one claim about discovered static structure only if backed by
  an artifact.

## Acceptance Checks

- The result identifies at least one class, selector, string, symbol, or
  function when tooling is available.
- The claim source path points to a durable artifact, not terminal-only text.
- The agent does not treat a missing Ghidra installation as static absence
  evidence.
