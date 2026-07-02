/* ###
 * IP: GHIDRA
 */
//@category Apple.Export

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.util.DefinedStringIterator;

public class ExportXPCSurface extends GhidraScript {

	private final Gson gson = new GsonBuilder().disableHtmlEscaping().setPrettyPrinting().create();

	@Override
	protected void run() throws Exception {
		Map<String, String> args = parseArgs();
		String outputPath = requireArg(args, "output");

		JsonObject payload = new JsonObject();
		payload.addProperty("program_name", currentProgram.getName());
		payload.addProperty("source", "ghidra_java");
		payload.add("service_names", collectServiceNames());
		payload.add("xpc_symbols", collectXpcSymbols());
		payload.add("connection_functions", collectFunctions("connection"));
		payload.add("listener_functions", collectFunctions("listener"));
		payload.add("protocol_hints", collectProtocolHints());

		writeJson(new File(outputPath), payload);
		println("Wrote " + outputPath);
	}

	private JsonArray collectServiceNames() {
		JsonArray array = new JsonArray();
		Set<String> seen = new LinkedHashSet<>();
		DefinedStringIterator strings = DefinedStringIterator.forProgram(currentProgram, currentSelection);
		for (Data data : strings) {
			if (monitor.isCancelled()) {
				break;
			}
			StringDataInstance instance = StringDataInstance.getStringDataInstance(data);
			if (instance == null) {
				continue;
			}
			String value = instance.getStringValue();
			if (!looksLikeServiceName(value) || !seen.add(value)) {
				continue;
			}
			JsonObject item = new JsonObject();
			item.addProperty("value", value);
			item.addProperty("address", String.valueOf(data.getAddress()));
			item.add("sample_xrefs", sampleReferences(data, 8));
			array.add(item);
		}
		return array;
	}

	private JsonArray collectXpcSymbols() {
		JsonArray array = new JsonArray();
		Set<String> seen = new LinkedHashSet<>();
		for (SymbolIterator iterator = currentProgram.getSymbolTable().getAllSymbols(true); iterator
				.hasNext();) {
			if (monitor.isCancelled()) {
				break;
			}
			Symbol symbol = iterator.next();
			String name = symbol.getName();
			String lower = name.toLowerCase(Locale.ROOT);
			if (!(lower.contains("xpc") || lower.contains("nsxpc"))) {
				continue;
			}
			String key = name + "@" + symbol.getAddress();
			if (!seen.add(key)) {
				continue;
			}
			JsonObject item = new JsonObject();
			item.addProperty("name", name);
			item.addProperty("address", String.valueOf(symbol.getAddress()));
			item.addProperty("external", symbol.isExternal());
			item.addProperty("source", String.valueOf(symbol.getSource()));
			array.add(item);
		}
		return array;
	}

	private JsonArray collectFunctions(String mode) {
		JsonArray array = new JsonArray();
		for (FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true); iterator
				.hasNext();) {
			if (monitor.isCancelled()) {
				break;
			}
			Function function = iterator.next();
			String name = function.getName();
			String lower = name.toLowerCase(Locale.ROOT);
			boolean keep;
			if ("listener".equals(mode)) {
				keep = lower.contains("listener") || lower.contains("shouldacceptnewconnection") ||
					lower.contains("xpcservice");
			}
			else {
				keep = lower.contains("connection") || lower.contains("remoteobject") ||
					lower.contains("interfacewithprotocol") || lower.contains("nsxpc");
			}
			if (!keep) {
				continue;
			}
			JsonObject item = new JsonObject();
			item.addProperty("name", name);
			item.addProperty("entry", String.valueOf(function.getEntryPoint()));
			item.addProperty("body_size", function.getBody().getNumAddresses());
			item.addProperty("caller_count", function.getCallingFunctions(monitor).size());
			array.add(item);
		}
		return array;
	}

	private JsonArray collectProtocolHints() {
		JsonArray array = new JsonArray();
		Set<String> seen = new LinkedHashSet<>();
		for (SymbolIterator iterator = currentProgram.getSymbolTable().getAllSymbols(true); iterator
				.hasNext();) {
			Symbol symbol = iterator.next();
			String name = symbol.getName();
			if (!(name.contains("Protocol") || name.contains("_OBJC_PROTOCOL_$_"))) {
				continue;
			}
			String lower = name.toLowerCase(Locale.ROOT);
			if (!(lower.contains("xpc") || lower.contains("service") || lower.contains("daemon") ||
				lower.contains("helper"))) {
				continue;
			}
			if (!seen.add(name)) {
				continue;
			}
			JsonObject item = new JsonObject();
			item.addProperty("name", name);
			item.addProperty("address", String.valueOf(symbol.getAddress()));
			array.add(item);
		}
		return array;
	}

	private JsonArray sampleReferences(Data data, int limit) {
		JsonArray refs = new JsonArray();
		int count = 0;
		ReferenceIterator iterator =
			currentProgram.getReferenceManager().getReferencesTo(data.getAddress());
		while (iterator.hasNext()) {
			Reference ref = iterator.next();
			if (count++ >= limit) {
				continue;
			}
			JsonObject item = new JsonObject();
			item.addProperty("from_address", String.valueOf(ref.getFromAddress()));
			Function fromFunction = getFunctionContaining(ref.getFromAddress());
			item.addProperty("from_function", fromFunction == null ? "" : fromFunction.getName());
			item.addProperty("ref_type", String.valueOf(ref.getReferenceType()));
			refs.add(item);
		}
		return refs;
	}

	private boolean looksLikeServiceName(String value) {
		if (value == null || value.length() < 4) {
			return false;
		}
		String lower = value.toLowerCase(Locale.ROOT);
		return lower.contains("xpc") || lower.endsWith(".xpc") ||
			lower.startsWith("com.apple.") || lower.startsWith("group.") ||
			lower.contains("mach");
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

	private void writeJson(File file, JsonObject payload) throws Exception {
		File parent = file.getParentFile();
		if (parent != null && !parent.exists() && !parent.mkdirs()) {
			throw new IllegalStateException("failed to create " + parent);
		}
		try (Writer writer =
			new OutputStreamWriter(new FileOutputStream(file), StandardCharsets.UTF_8)) {
			gson.toJson(payload, writer);
		}
	}
}
