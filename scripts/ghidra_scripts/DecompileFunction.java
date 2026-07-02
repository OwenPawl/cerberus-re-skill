/* ###
 * IP: GHIDRA
 */
//@category Decompiler

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class DecompileFunction extends GhidraScript {

	@Override
	protected void run() throws Exception {
		Map<String, String> args = parseArgs();
		String outputPath = requireArg(args, "output");
		int timeout = parseIntArg(args, "timeout", 60);
		Function function = resolveFunction(args);
		if (function == null) {
			throw new IllegalArgumentException("unable to resolve a function to decompile");
		}

		DecompInterface decompiler = new DecompInterface();
		decompiler.openProgram(currentProgram);
		DecompileResults results = decompiler.decompileFunction(function, timeout, monitor);
		if (!results.decompileCompleted()) {
			throw new RuntimeException(
				"decompilation failed for " + function.getName() + ": " + results.getErrorMessage());
		}

		File outputFile = new File(outputPath);
		File parent = outputFile.getParentFile();
		if (parent != null && !parent.exists() && !parent.mkdirs()) {
			throw new IllegalStateException("failed to create " + parent);
		}
		try (Writer writer =
			new OutputStreamWriter(new FileOutputStream(outputFile), StandardCharsets.UTF_8)) {
			writer.write("// Program: " + currentProgram.getName() + "\n");
			writer.write("// Function: " + function.getName() + "\n");
			writer.write("// Entry: " + function.getEntryPoint() + "\n\n");
			writer.write(results.getDecompiledFunction().getC());
			writer.write("\n");
		}
		println("Wrote " + outputFile.getAbsolutePath());
	}

	private Map<String, String> parseArgs() {
		Map<String, String> args = new LinkedHashMap<>();
		for (String arg : getScriptArgs()) {
			int index = arg.indexOf('=');
			if (index > 0) {
				args.put(arg.substring(0, index).trim().toLowerCase().replace('-', '_'),
					arg.substring(index + 1));
			}
		}
		return args;
	}

	private String requireArg(Map<String, String> args, String key) {
		String value = args.get(key);
		if (value == null || value.isEmpty()) {
			throw new IllegalArgumentException("missing required argument: " + key + "=...");
		}
		return value;
	}

	private int parseIntArg(Map<String, String> args, String key, int defaultValue) {
		String value = args.get(key);
		if (value == null || value.isEmpty()) {
			return defaultValue;
		}
		return Integer.decode(value);
	}

	private Function resolveFunction(Map<String, String> args) {
		if (args.containsKey("address")) {
			Address address = toAddr(args.get("address"));
			Function containing = getFunctionContaining(address);
			if (containing != null) {
				return containing;
			}
			return currentProgram.getFunctionManager().getFunctionAt(address);
		}
		String functionName = args.get("function");
		if (functionName != null && !functionName.isEmpty()) {
			return findFunctionByName(functionName);
		}
		Function fromImageBase = getFunctionContaining(currentProgram.getImageBase());
		if (fromImageBase != null) {
			return fromImageBase;
		}
		for (FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true); iterator
				.hasNext();) {
			Function function = iterator.next();
			if (!function.isExternal()) {
				return function;
			}
		}
		return null;
	}

	private Function findFunctionByName(String name) {
		Function exact = null;
		Function normalizedExact = null;
		Function caseInsensitive = null;
		Function contains = null;
		String target = name.toLowerCase();
		String normalizedTarget = TriageSupport.normalizeFunctionLookupValue(name).toLowerCase();
		for (FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true); iterator
				.hasNext();) {
			Function function = iterator.next();
			String functionName = function.getName();
			if (functionName.equals(name)) {
				exact = function;
				break;
			}
			if (normalizedExact == null &&
				TriageSupport.normalizeFunctionLookupValue(functionName).toLowerCase().equals(
					normalizedTarget)) {
				normalizedExact = function;
			}
			if (caseInsensitive == null && functionName.toLowerCase().equals(target)) {
				caseInsensitive = function;
			}
			if (contains == null && TriageSupport.matchesFunctionLookup(functionName, name, false)) {
				contains = function;
			}
		}
		return exact != null ? exact :
			normalizedExact != null ? normalizedExact :
				caseInsensitive != null ? caseInsensitive : contains;
	}
}
