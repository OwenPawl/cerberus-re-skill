# Apple Mach-O Notes

Use this skill for:

- Mach-O binaries from live system paths
- dyld-extracted framework binaries
- XPC service executables
- simulator or iOSSupport binaries that already exist as standalone Mach-O files

V1 does not parse raw dyld shared cache files directly. Prefer already-extracted binaries.
For runtime validation, live `/System/Library/...framework` paths can be dyld-cache
stubs with no Mach-O file even when LLDB can resolve the loaded image in a
process. In that case, pass the extracted framework binary to `--binary` for
static LLDB symbol export and keep the live process as the trace target.

When a registered source may fall back to dyld shared cache extraction, use
`cerberus-re source resolve <name> <path> --no-extract` as a read-only preflight.
It resolves direct files and already-extracted cache copies, but exits with an
explicit blocker instead of starting extraction when only the raw dyld cache is
available.

## What the export bundle looks for

- Objective-C symbols such as `_OBJC_CLASS_$_*`, `_OBJC_METACLASS_$_*`, `_OBJC_PROTOCOL_$_*`
- Objective-C method names like `-[Class selector:]` and `+[Class selector:]`
- section or block names containing:
  - `objc`
  - `methname`
  - `classname`
  - `cfstring`
- imported and exported symbols
- demangled function names after `DemangleAllScript.java`

## Good Apple-first targets

- Small XPC or helper executables when you want quick iteration
- dyld-extracted private frameworks when the live on-disk framework has only resources
- App support binaries where the public bundle is a launcher and the implementation lives in a private framework

## Common follow-ups

- Export the default bundle first
- Decompile one function by exact name or address
- Export xrefs for `_objc_msgSend`, `_swift_allocObject`, `dispatch_*`, or a target selector string
