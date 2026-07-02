# Benchmark Task Pack

These task cards are the public benchmark prompts for fresh agent instances.
They are designed to be run against a fresh checkout without private targets,
personal state, or manual GUI interaction.

Generate a complete prompt for a runner/configuration pair:

```bash
python3 scripts/agent_benchmark.py prompt \
  --runner codex \
  --configuration cerberus-re-long-run-agent \
  --bundle benchmarks/results/<date>/codex/cerberus-re-long-run-agent
```

The generated prompt embeds the task cards below and tells the agent where to
write the result bundle. The benchmark is only a real result after the fresh
agent fills in commands, claims, artifacts, failures, and metrics with
verification evidence.

## Task Cards

- `environment-setup.md`
- `static-evidence.md`
- `dynamic-evidence.md`
- `instrumentation-evidence.md`
- `mission-memory.md`
