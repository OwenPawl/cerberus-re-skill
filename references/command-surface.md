# Cerberus RE Command Surface

Prefer the Python CLI:

```bash
cerberus-re <command>
python3 -m cerberus_re_skill <command>
```

## Environment

- `python3 scripts/install_dependencies.py [--execute] [--json] [--venv <path>] [--skip-system] [--no-frida] [--no-node]`
- `python3 scripts/agent_benchmark.py list [--json]`
- `python3 scripts/agent_benchmark.py scaffold --runner <runner-id> --configuration <configuration-id> --output <bundle-dir> [--force]`
- `python3 scripts/agent_benchmark.py validate --bundle <bundle-dir>`
- `cerberus-re bootstrap [--skip-smoke-test] [--skip-plugins-install]`
- `cerberus-re doctor [--frida-target <binary>]`
- `cerberus-re plugins install ghidraapple`
- `cerberus-re plugins status`
- `cerberus-re source add <name> --root <path> [--platform macos-image] [--copy cache|direct]`
- `cerberus-re source list`
- `cerberus-re source resolve <name> </path/in/source> [--copy cache|direct] [--no-extract]`; `--no-extract` resolves direct files or already-extracted cache copies only and stops before invoking dyld shared cache extraction.

## Import And Static Analysis

- `cerberus-re import analyze <binary|source:name:/path> [project_name] [--skip-macho-reexports] [--macho-arch <arch>] [--disable-analysis-option <name>]...`
- `cerberus-re import macos-framework <framework-binary> [--project <name>]`
- `cerberus-re import run-script <script_name> <project_name> [program_name]`
- `cerberus-re export macho-structure <project> <program>`
- `cerberus-re export objc-layout <project> <program>`
- `cerberus-re export swift-layout <project> <program>`
- `cerberus-re export term-index <label=/export/path|/export/path|project:program> [...] --term <text> [--json-file swift_metadata.json] [--max-samples N]`
- `cerberus-re export function-dossier <project> <program> --function <name> [--linear-instruction-limit N]`
- `cerberus-re export function-dossier <project> <program> --address <addr> [--linear-instruction-limit N]`
- `cerberus-re export xpc-surface <project> <program> [--bundle-dir <apple_bundle_dir>]`; if static export JSON lives outside the default export directory, pass one `--bundle-dir` for an apple-bundle directory or explicit `--objc-metadata`, `--strings`, and `--symbols` paths. Missing inputs are reported as warnings and in `missing_input_count`; Swift/XPCDistributed method descriptors are reported as distributed method hints when present.
- `cerberus-re export xpc-graph <project:program> [project:program ...]`
- `cerberus-re export xpc-interface-dossier <project:program> [project:program ...]`
- `cerberus-re export xpc-method-inventory <project:program> [project:program ...] [--macho <binary>|--macho <project:program=/binary>] [--macho-arch <arch>]`
- `cerberus-re export triage-bundle <project> <program> [--top-candidates N]`
- `cerberus-re export runtime-enrich <project> <program> <runtime_hits.json> [--function-inventory <json>] [--lldb-symbols <json>]`; address-backed symbol disagreements that land inside another static function are preserved as non-mutating `interior_symbol_mismatch` boundary-recovery candidates and keep `symbol_resolved_static_address` when the runtime symbol resolves to a different static entry. Auto-derived missing `lldb_symbols.json` is optional, but an explicit `--lldb-symbols` path must exist.

## Runtime Validation

- `cerberus-re validate lldb-trace <project> <program> --launch-cmd <binary> --symbols <symbol>`; repeat `--symbols` or pass comma-separated values for multiple breakpoints.
- `cerberus-re validate lldb-trace <project> <program> --attach-pid <pid> --symbols <symbol>`; `--addresses` follows the same repeatable/comma-separated normalization. When `--binary` is used for dyld-cache-backed Apple frameworks, pass the extracted dyld-cache Mach-O rather than a live `/System/Library/...framework` stub path.
- `cerberus-re frida diagnose [--target <binary>]`
- `cerberus-re frida validate-scripts [--symbol <objc-method>] [--class-name <ObjCClass>]`
- `cerberus-re frida recheck-attach [--target <binary> | --attach-pid <pid> | --attach-name <regex>] [--selector <selector> | --symbol <method> ... | --native-symbol <export>|<Module!export>] [--native-wait-seconds <seconds>] [--native-arg-preview] [--allow-runtime]`; ObjC exact-method, selector-wide, and native hook modes are exclusive to avoid partial-coverage ambiguity. `--native-arg-preview` is opt-in and adds bounded best-effort register previews to native-call hits.
- `cerberus-re frida objc-probe [--target <binary> | --attach-pid <pid>] [--class <ObjCClass> ...] [--call Class.method] [--call-string 'Class.method:=value'] [--allow-runtime]`
- `cerberus-re frida objc-heap [--target <binary> | --attach-pid <pid>] [--class <ObjCClass> ...] [--getter <getter> ...] [--allow-runtime]`
- `cerberus-re frida objc-archive --archive <secure-archive> --class <ObjCClass> [--getter <getter> ...] [--allow-runtime]`
- `cerberus-re frida objc-plan --plan <objc-plan.json> [--target <binary> | --attach-pid <pid>] [--allow-runtime]`

Runtime commands intentionally require explicit `--allow-runtime` for live
Frida work and explicit launch/attach choices for LLDB work.

## Bridge

- `cerberus-re bridge build`
- `cerberus-re bridge install`
- `cerberus-re bridge arm <project_name> [program_name]`
- `cerberus-re bridge sessions`
- `cerberus-re bridge audit`
- `cerberus-re bridge call <endpoint> [json_body|@json_file|-]`
- `cerberus-re bridge close [--session <id>|--project <name>|--program <name>]`

## RE Evidence Reports

Generic long-running run state, control files, durable project memory, and agent
closeout orchestration belong in `long-run-agent`. Target-specific action
helper commands and mission closeout commands are not part of the public
Cerberus RE command surface. `xpc-safe-read-readiness` is also hidden until its
selector-specific readiness policy is split from generic XPC evidence
extraction.

## Validation And Publishing

- `cerberus-re validate local [--headless-smoke] [--live-bridge-smoke] [--lldb-smoke] [--frida-smoke]`
- `cerberus-re polish release [--mode quick|release] [--strict-command-surface] [--live-bridge]`
- `cerberus-re publish share [output_zip]`
- `cerberus-re publish mac-desktop [output_zip] [--without-ghidra-payload]`
- `cerberus-re publish windows-desktop [output_zip] [--ghidra-zip /path/to/ghidra.zip]`

## Notes

- `cerberus-re notes add --title ... --body ... [--category workflow] [--target ...]`
- `cerberus-re notes sync`
- `cerberus-re notes pull`
- `cerberus-re notes status`
- `cerberus-re notes remediate <note_id> [--resolution ...] [--comment ...]`
- `cerberus-re notes open-shared`

Shared notes require `GHIDRA_NOTES_REPO` and an issue number to be configured
for the installation. Public defaults do not point at a project-specific repo.
