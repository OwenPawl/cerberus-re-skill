# Built-in Script Notes

The wrappers include these built-in script directories in `-scriptPath`:

- `$GHIDRA_INSTALL_DIR/Ghidra/Features/Base/ghidra_scripts`
- `$GHIDRA_INSTALL_DIR/Ghidra/Features/Decompiler/ghidra_scripts`
- `$GHIDRA_INSTALL_DIR/Ghidra/Features/PyGhidra/ghidra_scripts`
- `$GHIDRA_INSTALL_DIR/Ghidra/Features/SwiftDemangler/ghidra_scripts`
- `$GHIDRA_INSTALL_DIR/Ghidra/Features/Jython/ghidra_scripts`

## Recommended built-in

- `DemangleAllScript.java`
  - Good headless default for cleaner symbol names before export

## Custom headless scripts

- `ExportAppleBundle.java`
  - writes the default structured export bundle
- `DecompileFunction.java`
  - decompiles one function by name or address to a text file
- `ExportXrefs.java`
  - exports sampled xrefs for a symbol, function, address, or matching string

## Useful but cursor-sensitive

- `SwiftDemanglerScript.java`
  - Works at the current address, so it is best for an interactive GUI session or a script that sets context explicitly
- `MachO_Script.java`
  - Also expects a meaningful current address and is better treated as a targeted follow-up than a blanket export step

## Prompting built-ins

- `ExportFunctionInfoScript.java`
  - Uses `askFile`, so prefer `ExportAppleBundle.java` for non-interactive runs and read `function_inventory.json`
