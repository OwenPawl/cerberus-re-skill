// Set Ghidra analysis options before auto-analysis.
//
// Script arguments are KEY=VALUE pairs, for example:
//   "Objective-C Selector Trampoline Analysis=false"
//@category ghidra-re

import ghidra.app.script.GhidraScript;

public class SetAnalysisOptions extends GhidraScript {
	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		for (String arg : args) {
			int split = arg.indexOf('=');
			if (split <= 0 || split == arg.length() - 1) {
				throw new IllegalArgumentException("Expected analysis option as KEY=VALUE, got: " + arg);
			}
			String key = arg.substring(0, split);
			String value = arg.substring(split + 1);
			setAnalysisOption(currentProgram, key, value);
			println("Set analysis option: " + key + "=" + value);
		}
	}
}
