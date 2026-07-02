# Raw Bridge Recipes

The supported live-bridge path is:

```bash
python3 -m cerberus_re_skill bridge call <endpoint> '<json-body>'
```

Every body can include one of these selectors:

```json
{"session":"<session-id>"}
{"project":"<project-name>","program":"<program-name>"}
{"program":"<program-name>"}
```

Prefer `session` or `project` plus `program` when more than one Ghidra window is open.

## Discovery

List and inspect live sessions:

```bash
python3 -m cerberus_re_skill bridge sessions
python3 -m cerberus_re_skill bridge audit
python3 -m cerberus_re_skill bridge status '{"project":"codex_true_smoke","program":"true"}'
python3 -m cerberus_re_skill bridge health --project codex_true_smoke --program true
python3 -m cerberus_re_skill bridge call /session '{"project":"codex_true_smoke","program":"true"}'
python3 -m cerberus_re_skill bridge call /context '{"project":"codex_true_smoke","program":"true"}'
```

Close live validation sessions when you do not need the GUI to stay open:

```bash
python3 -m cerberus_re_skill bridge close --project codex_true_smoke --program true
```

## High-Value Endpoints

Search functions:

```bash
python3 -m cerberus_re_skill bridge call /functions/search '{"project":"codex_true_smoke","program":"true","query":"entry","limit":10}'
```

Ask the bridge to resolve the best target for a symbol, address, selector, or fuzzy name:

```bash
python3 -m cerberus_re_skill bridge call /analyze/target '{"project":"codex_true_smoke","program":"true","query":"entry"}'
```

Decompile by function name or address:

```bash
python3 -m cerberus_re_skill bridge call /decompile '{"project":"codex_true_smoke","program":"true","function":"entry"}'
python3 -m cerberus_re_skill bridge call /decompile '{"project":"codex_true_smoke","program":"true","address":"100000388"}'
```

Fetch references, variables, symbols, xrefs, strings, data, and memory ranges:

```bash
python3 -m cerberus_re_skill bridge call /references '{"project":"codex_true_smoke","program":"true","function":"entry","limit":20}'
python3 -m cerberus_re_skill bridge call /variables '{"project":"codex_true_smoke","program":"true","function":"entry"}'
python3 -m cerberus_re_skill bridge call /symbols/get '{"project":"codex_true_smoke","program":"true","query":"_mh_execute_header"}'
python3 -m cerberus_re_skill bridge call /symbols/xrefs '{"project":"sample_service_smoke","program":"SampleXPCService","query":"_OBJC_CLASS_$_NSXPCListener","limit":10}'
python3 -m cerberus_re_skill bridge call /strings/search '{"project":"sample_service_smoke","program":"SampleXPCService","query":"xpc","limit":20}'
python3 -m cerberus_re_skill bridge call /data/get '{"project":"codex_true_smoke","program":"true","address":"100000000"}'
python3 -m cerberus_re_skill bridge call /memory/range '{"project":"codex_true_smoke","program":"true","address":"100000000","length":64}'
```

Navigate the GUI without mutating the program:

```bash
python3 -m cerberus_re_skill bridge call /navigate '{"project":"codex_true_smoke","program":"true","address":"100000388"}'
```

Write comments and save the program. Mutating calls require `write=true`:

```bash
python3 -m cerberus_re_skill bridge call /edit/comment '{"project":"codex_true_smoke","program":"true","address":"100000388","comment":"validated from raw bridge","comment_type":"plate","write":true}'
python3 -m cerberus_re_skill bridge call /program/save '{"project":"codex_true_smoke","program":"true","write":true,"description":"raw bridge validation"}'
```

Destructive patch calls additionally require `destructive=true`.

## Body Files And Stdin

Use `@file` for complex bodies:

```bash
cat >/tmp/bridge-comment.json <<'JSON'
{
  "project": "codex_true_smoke",
  "program": "true",
  "address": "100000388",
  "comment": "validated from @file",
  "comment_type": "plate",
  "write": true
}
JSON

python3 -m cerberus_re_skill bridge call /edit/comment @/tmp/bridge-comment.json
```

Use `-` to read the JSON body from stdin:

```bash
printf '%s\n' '{"project":"codex_true_smoke","program":"true","query":"entry","limit":5}' \
  | python3 -m cerberus_re_skill bridge call /functions/search -
```

If the bridge returns an HTTP error, the CLI preserves JSON error bodies when available and truncates long text bodies with `...[truncated]`.

## PowerShell Raw Calls

The PowerShell module exposes the same raw endpoint path:

```powershell
Invoke-GhidraReBridgeCall -Endpoint "/functions/search" -Body @{
  project = "codex_true_smoke"
  program = "true"
  query = "entry"
  limit = 5
}

Invoke-GhidraReBridgeCall -Endpoint "/functions/search" -BodyJson '{"project":"codex_true_smoke","program":"true","query":"entry","limit":5}'
Invoke-GhidraReBridgeCall -Endpoint "/edit/comment" -BodyPath "C:\Temp\bridge-comment.json"
```

## Raw Snapshot Composition

There is intentionally no replacement for the old `scripts/ghidra_bridge_snapshot` wrapper. Compose snapshots from raw calls using one selector body:

```bash
selector='{"project":"codex_true_smoke","program":"true","function":"entry"}'
python3 -m cerberus_re_skill bridge call /session "$selector"
python3 -m cerberus_re_skill bridge call /context "$selector"
python3 -m cerberus_re_skill bridge call /function "$selector"
python3 -m cerberus_re_skill bridge call /decompile "$selector"
python3 -m cerberus_re_skill bridge call /references "$selector"
python3 -m cerberus_re_skill bridge call /variables "$selector"
```

This keeps the Python CLI as a raw endpoint transport while still making snapshot runs reproducible in shell history or a notebook.
