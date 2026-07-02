# Environment Setup

## Objective

Determine whether the fresh agent can get from a clean checkout to an honest
tooling-readiness report without overstating prerequisites.

## Fresh-Instance Prompt

Start from the checkout root. Inspect the README and install documentation.
Run the documented dependency installer in dry-run mode first. If you choose to
execute any installer step, record the exact command and why it is safe for this
machine. Run `cerberus-re doctor` or `python3 -m cerberus_re_skill doctor` if the
command is available.

## Required Evidence

- Record every command in `commands.jsonl`.
- Record the installer plan output as an artifact.
- Record the doctor output or the exact blocker that prevented it.
- Update `metrics.json` for this task as `completed`, `partial`, or `blocked`.

## Acceptance Checks

- The agent distinguishes automatic installer steps from manual system-package
  hints.
- Missing Ghidra, Java, Frida, LLDB, or platform support is recorded as a
  prerequisite state, not as a benchmark failure by itself.
- No setup claim is marked verified without a command output or explicit
  no-verification reason.
