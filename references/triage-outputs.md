# Triage Outputs

The triage bundle writes to:

`~/ghidra-projects/exports/<project_name>/<program_name>/triage/`

Create it with:

`cerberus-re export triage-bundle <project_name> <program_name>`

Expected files:

- `entrypoints.json`
  - ranked candidate entrypoint functions with matched categories and evidence
  - `entrypoint_count` is the raw number of category matches emitted by the entrypoint scan
- `sinks.json`
  - ranked candidate sink functions with matched categories and evidence
  - `sink_count` is the raw number of category matches emitted by the sink scan
- `candidate_paths.json`
  - bounded entrypoint-to-sink paths with score, evidence, and ordered function nodes
  - `entrypoints_considered` and `sink_function_count` are triage-stage unique function counts after ranking/limits
- `summary.md`
  - human-readable summary of the top candidate paths

The Python result from `cerberus-re export triage-bundle` includes explicit
fields such as `entrypoint_match_count`, `sink_match_count`,
`triage_entrypoints_considered`, `triage_sink_function_count`, and
`candidate_count` so callers do not have to infer count semantics from the
individual JSON files.

Function dossiers write to:

`~/ghidra-projects/exports/<project_name>/<program_name>/dossiers/<slug>/`

Create one with either:

`cerberus-re export function-dossier <project_name> <program_name> --function <name>`

or:

`cerberus-re export function-dossier <project_name> <program_name> --address <addr>`

For Objective-C methods, `--function '-[Owner selector:]'` and
`--function '+[Owner selector:]'` resolve imports where Ghidra retained
`Owner` as the function namespace and retained only `selector:` as the
function name. Use `--address` when owner metadata is not available or a
selector is otherwise ambiguous. A selector-only imported function does not
by itself prove instance-versus-class method polarity.

Function dossier `imported_apis` include direct external calls and local import
thunks whose thunk target is external. Keep the direct callee list as the raw
control-flow view, and use `imported_apis` when ranking security, filesystem,
or process-boundary sinks.

Expected files:

- `context.json`
  - function metadata, callers, callees, imports, nearby strings/selectors, triage tags, conservatively referenced `FUN_<address>` helpers, and named `block_invoke` helpers embedded as decompiled function pointers
- `decompile.c`
  - decompiled C for the selected function
- `linear_instructions.txt`
  - bounded decoded-listing window used to expose likely analysis truncation; instructions marked `outside_body` require review or function recovery before being treated as control flow, and undisassembled gaps may remain
- `summary.md`
  - quick review notes for the selected function, including referenced block-invoke helpers and any possible auth-stub truncation warning

Applied findings write to:

`~/ghidra-projects/exports/<project_name>/<program_name>/findings/<slug>/finding_result.json`
