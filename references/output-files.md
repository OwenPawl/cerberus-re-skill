# Output Files

`cerberus-re` writes durable machine-readable evidence under:

`~/ghidra-projects/exports/<project_name>/<program_name>/`

Core bundle files:

- `program_summary.json`: program metadata, image base, memory blocks, symbol counts, and function counts.
- `objc_metadata.json`: Objective-C classes, protocols, categories, selectors, refs, and method metadata.
- `function_inventory.json`: discovered functions with addresses, signatures, parameters, and xref counts.
- `symbols.json`: symbols with import/export categorization.
- `strings.json`: defined strings with block names and sampled xrefs.
- `swift_metadata.json`: Swift symbols, metadata methods, runtime artifacts, property records, metadata-section summaries, and decoded Swift field/capture descriptors when `__swift5_fieldmd` or `__swift5_capture` are present. `field_descriptors` exposes stored-field names and mangled type references; `capture_descriptors` exposes captured symbolic type references such as `Unchecked<LocalInterface.Handoff>` so closure/request-shape evidence does not require ad hoc memory parsing.

Structure exports:

- `macho_structure.json`: Mach-O headers, UUID/build metadata, load commands, segments, sections, dylibs, rpaths, and optional entitlements.
- `objc_layout.json`: Objective-C class layout, ivars, protocols, categories, and method implementation addresses.
- `swift_layout.json`: Swift type metadata, fields, enum cases, and protocol conformance records when present.
- `term_index.json`: bounded cross-export term index over existing bundle JSON files, with per-input term counts, warnings for missing or empty inputs, and Markdown samples. Decoded Swift field/capture descriptor arrays are indexed as individual records; use `--json-file swift_metadata.json` when request-shape or closure metadata should not be drowned out by broad symbol hits.

Targeted analysis files:

- `dossiers/<slug>/context.json`: focused function metadata, callers, callees, nearby strings/classes/selectors, and conservative helper references.
- `dossiers/<slug>/decompile.c`: selected decompiler output.
- `dossiers/<slug>/linear_instructions.txt`: bounded decoded-listing window; when `context.json` reports `possible_authstub_truncation`, inspect this before relying on a short decompile result. Entries outside the current function body are leads for analysis repair, not recovered control-flow proof, and undisassembled gaps may remain.
- `dossiers/<slug>/summary.md`: human-readable function dossier summary.
- `triage/entrypoints.json`, `triage/sinks.json`, `triage/candidate_paths.json`: ranked static triage outputs.
- `xpc_*.json` and `nsxpc_*.json`: XPC surface, graph, method-shape, completion, allowed-class, and readiness evidence. `xpc_surface.json` includes `input_status`, `warnings`, `missing_input_count`, Swift distributed method evidence when exported symbols or strings expose XPCDistributed descriptors, distributed thunk symbol strings, or symbolic request/actor/response signatures, and low-confidence `reverse_dns_service_hints` for bare reverse-DNS strings near XPC evidence that do not satisfy the stricter `service_names` heuristic. Treat zero-count reports with missing-input warnings as incomplete input evidence, not proof that a target has no XPC surface. When an apple-bundle export lives outside the default export tree, `export xpc-surface --bundle-dir <dir>` reads `objc_metadata.json`, `strings.json`, and `symbols.json` from that directory and writes default `xpc_surface.*` outputs beside them. `xpc_method_inventory.json` reports `macho_protocol_method_count` when an optional `--macho` input decodes relative Objective-C protocol method lists into selector/type-encoding candidates.
- `runtime_hits.json`: normalized LLDB or Frida runtime-hit records.
- `runtime_hits_enriched.json`: runtime hits correlated back to static function inventory, symbols, xrefs, and optional decompile context. Address-derived matches include `static_match_status`; symbol disagreements are counted in `symbol_mismatch_count` and excluded from clean `matched_function_count` totals. Frida ObjC hits include `runtime.module` metadata when Frida can resolve the containing module; if `program_summary.json` supplies a static image base, `runtime-enrich` can use the module base as `slide_confidence=module_base` evidence. When runtime module metadata does not match the static program, hits include `runtime_image_match_status=cross_image_runtime_hit` and the bundle includes `cross_image_runtime_hit_count`, `cross_image_runtime_modules`, and `runtime_image_guidance`; import or materialize the callee image before trusting function-body correlation for those hits. When a disagreeing runtime symbol maps to an interior address of another static function, `static_match.boundary_status=interior_symbol_mismatch`, `address_offset_from_entry`, and `interior_boundary_mismatch_count` preserve a non-mutating function-boundary recovery lead. When the runtime symbol resolves to a different static function than the address-derived mapping, per-hit `symbol_resolved_static_address`, `static_match.symbol_resolution`, and bundle-level `symbol_resolved_conflicts` preserve the stronger symbol identity without hiding the address conflict. Small symbol/address deltas are classified as `neighboring_symbol_boundary_drift`; larger ones remain `distant_symbol_address_conflict`. If selector-backed runtime/static pairs imply multiple slides, `slide_conflict` and `slide_candidates` preserve the disagreement and `slide_confidence` is `conflicting`.
- `lldb-trace-validation.json`: guarded LLDB launch/attach validation, breakpoint preflight, trace status, hit counts, runtime module path/UUID identity, and enrichment status, including `interior_boundary_mismatch_count` when a runtime symbol lands within a conflicting static function body. The LLDB tracer durably saves its full breakpoint preflight and runtime module identity across a bounded wait, so a timed-out attached process can retain resolved zero-hit sentinels and image-drift evidence. If that preflight is unavailable but hits survive, hit-supported entries are still marked as partial recovery rather than reporting zero resolved locations. For `trace_incomplete` lifecycle failures, the Markdown report includes the preserved LLDB raw tail so wait/attach failures are visible without reopening JSON. Conflicting slide evidence is surfaced rather than treated as a high-confidence static correlation; compare the retained runtime UUID against static `macho_structure.json` identity before trusting cross-image mapping. Symbol/address disagreements also preserve `symbol_resolved_static_address` and `symbol_resolved_conflicts` so the report distinguishes symbol identity from address-derived boundary evidence, including `neighboring_symbol_boundary_drift` for small entry-adjacent mismatches.
- `frida-runtime-recheck.json`: guarded Frida attach validation, hook readiness, runtime hits, and structured failure classification. `no-runtime-hits` means hooks were observed but emitted no required hit; attach or spawn-gating failures before hook installation remain `blocked`; `target-failed-after-runtime-hit` preserves an observed call while refusing to label a target fatal termination as a passing probe. A generated runtime hit can set `hook_installation_inferred_from_hits` when an installation control line was lost in interleaved target output. Native-hook reports preserve requested/installed/missing targets in `native_target_hits`, `native_missing_targets`, and `native_zero_hit_targets` so unresolved exports and installed zero-hit sentinels are separate claims. Native call hits preserve raw register strings under `args`; when `native_arg_preview=true`, hits can also include `native_arg_preview_mode=best_effort_registers` and bounded `native_arg_previews` for readable strings or module pointers. With known Objective-C boundary classes, `frida recheck-attach --exact-class <Class>` without `--class-filter` records targeted selector installation without enumerating unrelated runtime class names.
- `frida-objc-probe.json`, `frida-objc-heap.json`, `frida-objc-archive.json`, `frida-objc-plan.json`: bounded Objective-C runtime observation reports.
- `simulator_framework_host.m`: optional load-only simulator host source for externally controlled LLDB/Frida probes.

Use `long-run-agent` for durable run state, user steering, project memory, and
agent closeout orchestration.

Bridge files live under:

- `~/.config/cerberus-re/bridge-sessions/`
- `~/.config/cerberus-re/bridge-current.json`
- `~/.config/cerberus-re/bridge-requests/`
- `~/ghidra-projects/logs/<project_name>/bridge-ops/`

Operational rule: if a command emits evidence that supports a claim, keep the
JSON or Markdown file path with the claim. Terminal-only observations are not
durable evidence.
