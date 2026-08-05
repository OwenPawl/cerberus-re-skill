# Cerberus MCP

`cerberus-mcp` is a local stdio server for a single operator. It invokes the
public `cerberus-re` CLI as a subprocess, so the CLI remains the compatibility
contract and every returned envelope records the exact command.

## Core Surface

The first-class tools cover environment checks, import, Apple and XPC exports,
triage, program diffing, runtime enrichment, guarded LLDB/Frida work, raw bridge
reads and approved mutations, and restart-safe background jobs. Use
`cerberus_run(argv)` only for the long tail. It cannot bypass runtime or bridge
mutation gates; network, installer, publishing, and arbitrary-script commands
remain blocked unless the explicit unsafe passthrough override is set.

Every tool returns `status`, `artifacts`, `warnings`, `command`, `exit_code`,
bounded `stdout`/`stderr`, and parsed `data` when JSON was recovered. Treat
`success`, `no_hit`, `blocked`, `failed`, and `unverified` as different evidence
states.

## Mission Composition

Install
[`long-run-agent`](https://github.com/OwenPawl/long-run-agent-skill) before
starting Cerberus to compose its domain-neutral `mission_*` tools into the same
server. `mission_companion_status` reports the effective state. Mission truth
continues to live in `.agent/`; Cerberus does not copy claims, friction, or
closeout state into its own job store.

## Approval And Audit

LLDB live operations and Frida calls with `allow_runtime=true` require a
per-call MCP approval unless the target matches
`CERBERUS_MCP_RUNTIME_PIDS` or `CERBERUS_MCP_RUNTIME_NAMES`. Unsupported or
timed-out elicitation fails closed.

Bridge reads run directly. A write requires both `body.write=true` and per-call
approval, unless `CERBERUS_MCP_BRIDGE_WRITE_OK=1` pre-approves only the write
tier. A destructive call additionally requires `body.destructive=true` and an
elicitation response that echoes the exact endpoint. Destructive approval has
no environment bypass.

Runtime decisions, bridge mutations, background jobs, and passthrough policy
decisions are appended as JSONL under
`$GHIDRA_WORKSPACE/.cerberus-mcp/audit.jsonl`.

## Durable Jobs

Imports and optional triage jobs execute through detached worker processes.
The worker owns the command logs and terminal record, so an MCP server restart
does not discard a still-running job. `job_close` archives terminal state
instead of deleting evidence. This execution state is intentionally narrower
than long-run-agent mission memory.

## Startup

`CERBERUS_MCP_PINNED_VERSION` makes startup fail when the installed
`cerberus-re` distribution version differs. `CERBERUS_MCP_STRICT_SURFACE=1`
also runs Cerberus's strict command-surface preflight. Use `CERBERUS_BIN` only
when the intended CLI cannot be reached through the server's Python
environment.
