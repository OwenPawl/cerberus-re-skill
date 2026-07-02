/* ###
 * IP: GHIDRA
 */
//@category References

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.util.DefinedStringIterator;

public class ExportXrefs extends GhidraScript {

	private final Gson gson = new GsonBuilder().disableHtmlEscaping().setPrettyPrinting().create();

	@Override
	protected void run() throws Exception {
		Map<String, String> args = parseArgs();
		String outputPath = requireArg(args, "output");
		int limit = parseIntArg(args, "xref_limit", 20);

		JsonArray targets = new JsonArray();
		if (args.containsKey("symbol")) {
			addSymbolTargets(targets, args.get("symbol"), limit);
		}
		else if (args.containsKey("string")) {
			addStringTargets(targets, args.get("string"), limit);
		}
		else {
			addAddressOrFunctionTarget(targets, args, limit);
		}
		if (targets.size() == 0) {
			throw new IllegalArgumentException("no xref targets were resolved");
		}

		JsonObject payload = new JsonObject();
		payload.addProperty("program_name", currentProgram.getName());
		payload.addProperty("xref_sample_limit", limit);
		payload.add("targets", targets);
		writeJson(new File(outputPath), payload);
		println("Wrote " + outputPath);
	}

	private void addSymbolTargets(JsonArray targets, String symbolName, int limit) {
		List<Symbol> matches = new ArrayList<>();
		for (SymbolIterator iterator = currentProgram.getSymbolTable().getAllSymbols(true); iterator
				.hasNext();) {
			Symbol symbol = iterator.next();
			if (symbol.getName().equals(symbolName)) {
				matches.add(symbol);
			}
		}
		if (matches.isEmpty()) {
			String lower = symbolName.toLowerCase();
			for (SymbolIterator iterator = currentProgram.getSymbolTable().getAllSymbols(true); iterator
					.hasNext();) {
				Symbol symbol = iterator.next();
				if (symbol.getName().toLowerCase().equals(lower)) {
					matches.add(symbol);
				}
			}
		}
		for (Symbol symbol : matches) {
			JsonObject target = new JsonObject();
			target.addProperty("kind", "symbol");
			target.addProperty("name", symbol.getName());
			target.addProperty("address", String.valueOf(symbol.getAddress()));
			JsonObject refs = sampleReferences(symbol.getAddress(), limit);
			target.addProperty("xref_count", refs.get("count").getAsInt());
			target.add("xrefs", refs.getAsJsonArray("items"));
			targets.add(target);
		}
	}

	private void addStringTargets(JsonArray targets, String needle, int limit) {
		DefinedStringIterator iterator = DefinedStringIterator.forProgram(currentProgram, currentSelection);
		for (Data data : iterator) {
			if (monitor.isCancelled()) {
				break;
			}
			StringDataInstance stringData = StringDataInstance.getStringDataInstance(data);
			String value = stringData.getStringValue();
			if (value == null || !value.contains(needle)) {
				continue;
			}
			JsonObject target = new JsonObject();
			target.addProperty("kind", "string");
			target.addProperty("value", value);
			target.addProperty("address", String.valueOf(data.getAddress()));
			JsonObject refs = sampleReferences(data.getAddress(), limit);
			target.addProperty("xref_count", refs.get("count").getAsInt());
			target.add("xrefs", refs.getAsJsonArray("items"));
			targets.add(target);
		}
	}

	private void addAddressOrFunctionTarget(JsonArray targets, Map<String, String> args, int limit) {
		Function function = null;
		Address address = null;
		if (args.containsKey("address")) {
			address = toAddr(args.get("address"));
			function = getFunctionContaining(address);
		}
		else if (args.containsKey("function")) {
			function = findFunctionByName(args.get("function"));
			if (function != null) {
				address = function.getEntryPoint();
			}
		}
		else {
			function = getFunctionContaining(currentProgram.getImageBase());
			if (function != null) {
				address = function.getEntryPoint();
			}
		}
		if (address == null) {
			throw new IllegalArgumentException("no address or function target was resolved");
		}
		JsonObject target = new JsonObject();
		target.addProperty("kind", function == null ? "address" : "function");
		target.addProperty("name", function == null ? null : function.getName());
		target.addProperty("address", String.valueOf(address));
		JsonObject refs = sampleReferences(address, limit);
		target.addProperty("xref_count", refs.get("count").getAsInt());
		target.add("xrefs", refs.getAsJsonArray("items"));
		targets.add(target);
	}

	private Function findFunctionByName(String name) {
		Function exact = null;
		Function normalizedExact = null;
		Function caseInsensitive = null;
		Function contains = null;
		String lower = name.toLowerCase();
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
			if (caseInsensitive == null && functionName.toLowerCase().equals(lower)) {
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

	private JsonObject sampleReferences(Address address, int limit) {
		JsonObject payload = new JsonObject();
		JsonArray refs = new JsonArray();
		int count = 0;
		ReferenceIterator iterator = currentProgram.getReferenceManager().getReferencesTo(address);
		while (iterator.hasNext()) {
			Reference ref = iterator.next();
			count++;
			if (refs.size() >= limit) {
				continue;
			}
			JsonObject refJson = new JsonObject();
			refJson.addProperty("from_address", String.valueOf(ref.getFromAddress()));
			refJson.addProperty("to_address", String.valueOf(ref.getToAddress()));
			Function containing = getFunctionContaining(ref.getFromAddress());
			refJson.addProperty("from_function", containing == null ? null : containing.getName());
			refJson.addProperty("ref_type", String.valueOf(ref.getReferenceType()));
			refJson.addProperty("operand_index", ref.getOperandIndex());
			refJson.addProperty("is_primary", ref.isPrimary());
			refs.add(refJson);
		}
		payload.addProperty("count", count);
		payload.add("items", refs);
		return payload;
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

	private void writeJson(File file, JsonElement payload) throws Exception {
		File parent = file.getParentFile();
		if (parent != null && !parent.exists() && !parent.mkdirs()) {
			throw new IOException("failed to create " + parent);
		}
		try (Writer writer =
			new OutputStreamWriter(new FileOutputStream(file), StandardCharsets.UTF_8)) {
			gson.toJson(payload, writer);
		}
	}
}
