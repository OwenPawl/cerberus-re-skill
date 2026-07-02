# Frida Diagnostics

Use `cerberus-re doctor` for non-invasive Frida readiness checks before trying a live attach:

```bash
python3 -m cerberus_re_skill doctor
python3 -m cerberus_re_skill doctor --frida-target /tmp/cerberus-re-validation/CodexObjCProbe
```

The Frida section checks the active `PATH` first, then `GHIDRA_RE_FRIDA_BIN`, `GHIDRA_RE_FRIDA_VENV`, the stable local venv at `/opt/cerberus-re/frida-venv`, and temporary validation venvs under `/tmp`:

- `frida --version` from the active `PATH`.
- `import frida` from the detected Python interpreter.
- `frida-ps` against the local host process list, preferring the normal native path.
- macOS `DevToolsSecurity -status`.
- Optional target signing via `codesign` when `--frida-target` is passed.
- AMFI/helper policy checks when the host is intentionally booted with `amfi_get_out_of_my_way=1`.

## Failure Interpretation

| Diagnostic | Meaning | Remediation |
|---|---|---|
| `Frida CLI` warns | The command-line tools are missing or broken. | Install or activate the venv that owns `frida-tools`, then rerun `frida --version`. |
| `Frida Python module` warns | The active Python cannot import the Frida module. | Install `frida` into that Python or run from the intended venv. |
| `frida-ps local probe` warns | Local Frida enumeration failed before attach. | Fix the Frida install before debugging target-specific permissions. |
| `DevToolsSecurity` warns disabled | macOS developer-mode attach policy is disabled. | Run `sudo DevToolsSecurity -enable`, then retry diagnostics. |
| `Frida target signing` warns unsigned | The target is unsigned or still hardened in a way that can reject injection. | For local analysis copies, use `scripts/strip_hardened_runtime <src> [dst]` to copy and ad-hoc sign without hardened runtime. |
| `Frida helper policy` warns AMFI workaround incomplete | `amfi_get_out_of_my_way=1` is set, but the stable venv, sudoers file, or passwordless `sudo -n frida-ps` check is missing. | Prefer removing that boot-arg when possible. If it must remain set, install `/opt/cerberus-re/frida-venv`, install `/etc/sudoers.d/cerberus-re-frida`, then rerun diagnostics. |
| `Frida helper policy` is OK | AMFI is off and the local fallback workaround is active. | Runtime attach can use `sudo -n /opt/cerberus-re/frida-venv/bin/frida` against a non-hardened analysis copy, but this is not the preferred native path. |

## Preferred Native Workflow

When host policy allows it, prefer the normal Frida path:

1. Use `frida` and `frida-ps` from the active environment.
2. Keep `DevToolsSecurity` enabled.
3. Attach first to a local non-hardened fixture.
4. For Apple binaries, copy and ad-hoc sign an analysis copy when hardened runtime or signature policy blocks injection.

Example:

```bash
copy="$(scripts/strip_hardened_runtime /path/to/target /tmp/analysis/target)"
python3 -m cerberus_re_skill doctor --frida-target "$copy"
frida -p <pid> -l /path/to/script.js
```

This analyses a re-signed copy, not the original binary. If entitlement-gated behavior depends on the original signature or hardened runtime state, analyse the original separately.

For guarded fixture validation that writes unified runtime-hit artifacts:

```bash
python3 -m cerberus_re_skill frida recheck-attach \
  --target /tmp/cerberus-re-validation/CodexObjCProbe \
  --symbol '-[CodexProbe runWithInput:]' \
  --capture-returns \
  --allow-runtime \
  --output-dir /tmp/cerberus-re-frida-runtime
```

This command stays artifact-only unless `--allow-runtime` is present. Live runs write `frida-runtime-recheck.json` and `runtime_hits.json`. Reusable harnesses can pass argv with repeated `--target-arg`; reports record optional `--readiness-marker` evidence and summarize `GHIDRA_FRIDA_WAITING_CLASS`, `GHIDRA_FRIDA_INSTALLED`, `GHIDRA_FRIDA_MISSING_CLASS`, and `GHIDRA_FRIDA_MISSING_METHOD` lines. A preserved runtime hit is evidence that its generated hook was installed even if an interleaved control line is unavailable; if the target then terminates fatally, the report remains non-passing as `target-failed-after-runtime-hit`. To correlate Frida hits with the static export, run `cerberus-re export runtime-enrich <project> <program> <runtime_hits.json>` after the guarded recheck.

Frida recheck modes are intentionally exclusive. Exact ObjC method hooks
(`--symbol`), selector-wide ObjC hooks (`--selector`), and native hooks
(`--native-symbol` or `--address`) generate different trace scripts and should
be run as separate commands when a probe needs more than one coverage type.

When `--require-runtime-hit` is used, `no-runtime-hits` is reported only after
hook installation is observed. Spawn-gating privilege failures or attach
protection failures that occur before any hook installs are reported as
`blocked`, with the raw Frida result retained in the JSON artifact.

Selector-wide rechecks also record `GHIDRA_FRIDA_SELECTOR_NO_MATCH` for each
requested selector that installed no hook under the active class filters. When
using selectors as safety sentinels, check both `selector_installed` and
`selector_no_match`; an absent hook is not zero-hit evidence.

Generated trace scripts handle frameworks loaded after script startup by waiting briefly for missing Objective-C classes and installing the hook once the class appears. This is useful for harnesses that call `dlopen()` before invoking a private-framework selector.

Generated ObjC trace scripts also guard argument and return-value descriptions before calling `ObjC.Object(...)`. Small scalar values, nulls, unaligned addresses, and unreadable pointers are left as raw pointer strings instead of being coerced into ObjC objects. This intentionally loses some pretty-printing detail in exchange for avoiding target crashes while probing live private-framework UI paths.

When static analysis identifies an interesting ObjC class but the missing
evidence is live object provenance, use `objc-heap` before writing bespoke
Frida scripts:

```bash
python3 -m cerberus_re_skill frida objc-heap \
  --attach-pid <pid> \
  --class ExampleParameter \
  --getter possibleStates \
  --getter value \
  --include-ivars \
  --require-instance \
  --allow-runtime
```

This command enumerates selected live heap classes, records no-argument getter
results, and can include ivar snapshots. It is read-oriented, but still runtime
attach work: keep `--allow-runtime` explicit and preserve durable artifact
evidence for every claim.

When Objective-C is unavailable in an attach target, or when the interesting
surface is a C export/authstub target, use attach-by-PID plus native hooks:

```bash
python3 -m cerberus_re_skill frida recheck-attach \
  --attach-pid <pid> \
  --native-symbol 'ExampleFramework!ExampleExportedFunction' \
  --capture-returns \
  --native-arg-preview \
  --allow-runtime \
  --output-dir /tmp/cerberus-re-frida-native
```

Native hooks emit the same `GHIDRA_FRIDA_HIT` runtime-hit prefix as ObjC hooks
and add `GHIDRA_FRIDA_NATIVE_INSTALLED` / `GHIDRA_FRIDA_NATIVE_MISSING` summary
lines. Repeat `--native-symbol` for additional exports; prefer `Module!symbol`
when the intended framework or dylib is known, and use `--address` only for
absolute runtime addresses that already include the process slide.
Native call hits always preserve raw register strings under `args`. Add
`--native-arg-preview` when the run needs bounded best-effort previews such as
readable UTF-8 strings or module pointers; these previews are not a substitute
for a recovered function signature.
Runtime reports also include `native_target_hits`, `native_missing_targets`,
and `native_zero_hit_targets` for native-hook runs. Use missing targets when a
requested private export could not be resolved in the live process, and use
zero-hit targets when installed safety sentinels such as `activate` or `send`
must be preserved as explicit zero-hit evidence instead of inferred manually
from the raw Frida output.

For owned helpers that `dlopen` a framework and immediately call the interesting
native export, emit a post-`dlopen` readiness marker and delay briefly before
the call. Pair that with `--native-wait-seconds`, `--readiness-marker`, and
`--require-readiness-marker`; otherwise a zero-hit native trace may only prove
that Frida missed the late-loaded export before invocation.

Unqualified native exports remain supported for compatibility and fast probes,
but same-name exports or wrapper-adjacent symbols can install in a different
module than the one the static analysis selected. If an unqualified target is
installed and records zero hits, the runtime report includes
`native_unqualified_zero_hit_targets` and guidance to retry with
`Module!symbol`; this is reporting guidance, not a hard failure.

For Mach-O/`.tbd` Swift symbols, static exports often include a leading
object-file underscore while `dlsym` and Frida runtime export lookup use the
name without that underscore. Native trace generation records both candidate
spellings and tries them in order, so static-export names can be passed
directly.

If an owned helper calls `dlopen()` before invoking a private-framework C
export, add a short native wait window so hooks poll for the export before
declaring it missing:

```bash
python3 -m cerberus_re_skill frida recheck-attach \
  --target /tmp/owned-helper \
  --native-symbol 'ExampleFramework!ExampleExportedFunction' \
  --native-wait-seconds 3 \
  --require-runtime-hit \
  --allow-runtime
```

When a protected daemon rejects live attach but a controlled helper can
exercise the same framework setup path, preserve both outcomes in one fallback
report:

```bash
python3 -m cerberus_re_skill export frida-capture-plan \
  --live-attach daemon=/path/frida-live-attach.json \
  --runtime-recheck helper=/path/frida-runtime-recheck.json \
  --diagnostics helper=/path/frida-diagnostics.json \
  --enriched-runtime helper=/path/runtime_hits_enriched.json
```

This keeps daemon attach protection separate from controlled helper success and
records whether LLDB, live Frida, helper-spawn Frida, or a controlled
action-invocation fallback should be used next. Capture plans classify
controlled helper domains with generic labels such as `action_invocation_path`
and `xpc_setup_path` so useful invocation-path probes do not get collapsed into
generic instrumentation availability.

## AMFI-Off Fallback Workflow

If a host must intentionally boot with `amfi_get_out_of_my_way=1`, the native path can fail. In that fallback case:

1. Keep Frida in the stable arm64 venv at `/opt/cerberus-re/frida-venv`.
2. Allow only the Frida CLI binaries through `/etc/sudoers.d/cerberus-re-frida`.
3. Run Frida through `sudo -n /opt/cerberus-re/frida-venv/bin/frida`.
4. Attach to a copied, non-hardened, ad-hoc-signed target produced by `scripts/strip_hardened_runtime`.

Example:

```bash
copy="$(scripts/strip_hardened_runtime /path/to/target /tmp/analysis/target)"
python3 -m cerberus_re_skill doctor --frida-target "$copy"
sudo -n /opt/cerberus-re/frida-venv/bin/frida -p <pid> -l /path/to/script.js
```

This is fallback-only. Do not prefer it on hosts where the native path works.

## Dry-Run Script Validation

Generated Frida scripts can be syntax-checked without attach permission:

```bash
./scripts/ghidra_frida_trace codex_objc_probe CodexObjCProbe 'symbols=-[CodexProbe runWithInput:]' capture_returns=true dry_run=true script_output=/tmp/cerberus-re-validation/frida_probe_trace.js
./scripts/ghidra_frida_heap_scan CodexProbe dry_run=true script_output=/tmp/cerberus-re-validation/frida_probe_heap.js
node --check /tmp/cerberus-re-validation/frida_probe_trace.js
node --check /tmp/cerberus-re-validation/frida_probe_heap.js
```

This validates the generator and emitted JavaScript syntax. It does not validate attach permission, ObjC runtime availability, target process policy, or runtime-hit ingestion.

## Host Evidence Reminder

Host attach policy is part of the evidence. Revalidate Frida through the normal
native CLI/module path before relying on the sudo-backed fallback. The stable
`/opt/cerberus-re/frida-venv` path can still be the native Frida provider; it
should only be wrapped in `sudo -n` when AMFI-off boot args are detected or
`GHIDRA_RE_FRIDA_SUDO=1` is explicitly set. Hardened original targets may still
reject injection; use `scripts/strip_hardened_runtime` when behaviour under a
copied signature is acceptable.
