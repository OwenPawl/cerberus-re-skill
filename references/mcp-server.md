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

## Probe Plans And Evidence

The artifact-only ProbePlan surface does not launch or attach to a target:

- `probe_plan_create` binds a workspace executable, stable target key,
  LLDB/Frida transport, timeout, detach/kill policy, expected signals, immutable
  helper identities, and output paths into `ghidra-re.probe-plan.v1`.
- `probe_plan_verify` accepts exactly one inline plan or workspace plan path and
  rechecks executable/helper content plus every confined path.
- `probe_plan_write` atomically writes a verified plan.
- `probe_lifecycle_record` appends one preflight, attach, launch, hit, detach,
  liveness, crash, or relaunch event to a plan-bound lifecycle file.
- `probe_lifecycle_summarize` verifies and summarizes that file. A timeout is
  reported as timeout and never inferred to be a no-hit observation.

Immutable evidence uses `evidence_append`, `evidence_export`, and bounded
`evidence_query`. `evidence_certification_gate` is read-only and verifies the
full dependency closure plus existing workspace verification files.
`evidence_certify` reruns that gate before appending a certified finding;
`evidence_append` rejects direct requests for certified status.

All paths may be workspace-relative or absolute inside `GHIDRA_WORKSPACE`.
Parent traversal and symlink escapes fail with `status=failed`. Certification
failures return `status=blocked`; malformed schemas, corrupt identities, helper
drift, and path violations return `status=failed`. Helper content is limited to
1 MiB per helper, plan helper/output counts are bounded, and evidence queries
return at most 200 nodes or dependency IDs per call.

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
than long-run-agent mission memory. On Windows, Cerberus first requests Job
Object breakaway and falls back to the local CIM process provider because MCP
stdio clients may intentionally terminate the server's descendant Job Object.
A launch is recorded as failed rather than claiming restart safety when neither
independent path is available.

## Startup

`CERBERUS_MCP_PINNED_VERSION` makes startup fail when the installed
`cerberus-re` distribution version differs. `CERBERUS_MCP_STRICT_SURFACE=1`
also runs Cerberus's strict command-surface preflight. Use `CERBERUS_BIN` only
when the intended CLI cannot be reached through the server's Python
environment. It accepts a platform-native command string or, for unambiguous
cross-platform paths, a JSON argument array such as
`["python", "-m", "cerberus_re_skill"]`.
