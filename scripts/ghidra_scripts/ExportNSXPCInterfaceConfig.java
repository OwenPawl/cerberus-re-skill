/* ###
 * IP: GHIDRA
 */
//@category Apple.Export

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
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

public class ExportNSXPCInterfaceConfig extends GhidraScript {

	private static final String SCHEMA = "ghidra-re.nsxpc-interface-config.v1";
	private static final Pattern PROTOCOL_REF =
		Pattern.compile("__OBJC_PROTOCOL_REFERENCE_+\\$?([A-Za-z_][A-Za-z0-9_]*)");
	private static final Pattern CLASS_REF =
		Pattern.compile("__OBJC_CLASS_+\\$?([A-Za-z_][A-Za-z0-9_]*)");
	private static final Pattern SELECTOR_LITERAL =
		Pattern.compile("\"([A-Za-z_][A-Za-z0-9_]*:([A-Za-z_][A-Za-z0-9_]*:)*)\"");

	private final Gson gson = new GsonBuilder().disableHtmlEscaping().setPrettyPrinting().create();

	private static class Args {
		Map<String, String> options = new LinkedHashMap<>();
		List<String> functions = new ArrayList<>();
		List<String> addresses = new ArrayList<>();
	}

	private static class Candidate {
		Function function;
		Set<String> reasons = new LinkedHashSet<>();

		Candidate(Function function) {
			this.function = function;
		}
	}

	@Override
	protected void run() throws Exception {
		Args args = parseArgs();
		String outputPath = requireArg(args.options, "output");
		String projectName = args.options.getOrDefault("project", "");
		int timeout = parseInt(args.options.get("timeout"), 60);
		int limit = parseInt(args.options.get("limit"), 40);
		int excerptLines = parseInt(args.options.get("excerpt_lines"), 2);
		boolean includeDiscovered = parseBoolean(args.options.get("include_discovered"), true);

		Map<String, Candidate> candidates = new LinkedHashMap<>();
		for (String name : args.functions) {
			addFunctionByName(candidates, name, "explicit:function");
		}
		for (String address : args.addresses) {
			addFunctionByAddress(candidates, address, "explicit:address");
		}
		if (includeDiscovered) {
			discoverByCallReferences(candidates, limit);
			discoverBySelectorStrings(candidates, limit);
			discoverByName(candidates, limit);
		}

		JsonArray functions = new JsonArray();
		DecompInterface decompiler = new DecompInterface();
		decompiler.openProgram(currentProgram);
		int patternFunctionCount = 0;
		int allowedClassCallCount = 0;
		int interfaceWithProtocolCallCount = 0;
		Set<String> protocolRefs = new LinkedHashSet<>();
		int processed = 0;
		for (Candidate candidate : candidates.values()) {
			if (processed >= limit || monitor.isCancelled()) {
				break;
			}
			processed++;
			JsonObject item = analyzeFunction(decompiler, candidate, timeout, excerptLines);
			int itemAllowed = item.get("allowed_class_call_count").getAsInt();
			int itemInterface = item.get("interface_with_protocol_call_count").getAsInt();
			if (itemAllowed > 0 || itemInterface > 0) {
				patternFunctionCount++;
			}
			allowedClassCallCount += itemAllowed;
			interfaceWithProtocolCallCount += itemInterface;
			JsonArray itemProtocols = item.getAsJsonArray("protocol_references");
			for (int i = 0; i < itemProtocols.size(); i++) {
				protocolRefs.add(itemProtocols.get(i).getAsString());
			}
			functions.add(item);
		}
		decompiler.dispose();

		JsonObject summary = new JsonObject();
		summary.addProperty("function_count", functions.size());
		summary.addProperty("pattern_function_count", patternFunctionCount);
		summary.addProperty("allowed_class_call_count", allowedClassCallCount);
		summary.addProperty("interface_with_protocol_call_count", interfaceWithProtocolCallCount);
		summary.addProperty("protocol_reference_count", protocolRefs.size());

		JsonObject payload = new JsonObject();
		payload.addProperty("schema", SCHEMA);
		payload.addProperty("ok", true);
		payload.addProperty("project_name", projectName);
		payload.addProperty("program_name", currentProgram.getName());
		payload.addProperty("source", "ghidra_java");
		payload.add("summary", summary);
		payload.add("functions", functions);

		writeJson(new File(outputPath), payload);
		println("Wrote " + outputPath);
	}

	private JsonObject analyzeFunction(DecompInterface decompiler, Candidate candidate, int timeout,
			int excerptLines) {
		Function function = candidate.function;
		JsonObject item = new JsonObject();
		item.addProperty("function", function.getName());
		item.addProperty("entry", String.valueOf(function.getEntryPoint()));
		item.addProperty("body_size", function.getBody().getNumAddresses());
		item.add("selection_reasons", toJsonArray(candidate.reasons));
		item.add("allowed_class_calls", new JsonArray());
		item.add("interface_with_protocol_calls", new JsonArray());
		item.add("protocol_references", new JsonArray());
		item.addProperty("allowed_class_call_count", 0);
		item.addProperty("interface_with_protocol_call_count", 0);
		item.addProperty("decompile_excerpt", "");

		try {
			DecompileResults results = decompiler.decompileFunction(function, timeout, monitor);
			if (!results.decompileCompleted()) {
				item.addProperty("decompile_error", results.getErrorMessage());
				return item;
			}
			String text = results.getDecompiledFunction().getC();
			item.addProperty("decompile_excerpt", firstLines(text, 24));
			JsonArray allowedCalls = collectAllowedClassCalls(text, excerptLines);
			JsonArray interfaceCalls = collectInterfaceWithProtocolCalls(text, excerptLines);
			JsonArray protocols = toJsonArray(extractMatches(PROTOCOL_REF, text));
			item.add("allowed_class_calls", allowedCalls);
			item.add("interface_with_protocol_calls", interfaceCalls);
			item.add("protocol_references", protocols);
			item.addProperty("allowed_class_call_count", allowedCalls.size());
			item.addProperty("interface_with_protocol_call_count", interfaceCalls.size());
		}
		catch (Exception e) {
			item.addProperty("decompile_error", e.toString());
		}
		return item;
	}

	private JsonArray collectAllowedClassCalls(String text, int excerptLines) {
		JsonArray calls = new JsonArray();
		String[] lines = text.split("\\R", -1);
		for (int i = 0; i < lines.length; i++) {
			String selector = canonicalAllowedSelector(lines[i]);
			if (selector.isEmpty()) {
				continue;
			}
			String excerpt = excerpt(lines, i, excerptLines);
			JsonObject call = new JsonObject();
			call.addProperty("selector", selector);
			call.addProperty("line_number", i + 1);
			call.addProperty("line", lines[i].trim());
			call.addProperty("excerpt", excerpt);
			call.add("class_references", toJsonArray(extractMatches(CLASS_REF, excerpt)));
			call.add("selector_literals", toJsonArray(extractMatches(SELECTOR_LITERAL, excerpt)));
			calls.add(call);
		}
		return calls;
	}

	private JsonArray collectInterfaceWithProtocolCalls(String text, int excerptLines) {
		JsonArray calls = new JsonArray();
		String[] lines = text.split("\\R", -1);
		for (int i = 0; i < lines.length; i++) {
			if (!isInterfaceWithProtocolLine(lines[i])) {
				continue;
			}
			String excerpt = excerpt(lines, i, excerptLines);
			JsonObject call = new JsonObject();
			call.addProperty("selector", "interfaceWithProtocol:");
			call.addProperty("line_number", i + 1);
			call.addProperty("line", lines[i].trim());
			call.addProperty("excerpt", excerpt);
			call.add("protocol_references", toJsonArray(extractMatches(PROTOCOL_REF, excerpt)));
			calls.add(call);
		}
		return calls;
	}

	private void discoverByCallReferences(Map<String, Candidate> candidates, int limit) {
		for (SymbolIterator iterator = currentProgram.getSymbolTable().getAllSymbols(true);
				iterator.hasNext();) {
			if (monitor.isCancelled() || candidates.size() >= limit) {
				break;
			}
			Symbol symbol = iterator.next();
			String name = symbol.getName();
			if (!isConfigurationSymbolName(name)) {
				continue;
			}
			ReferenceIterator refs =
				currentProgram.getReferenceManager().getReferencesTo(symbol.getAddress());
			while (refs.hasNext() && candidates.size() < limit) {
				Reference ref = refs.next();
				Function function = getFunctionContaining(ref.getFromAddress());
				if (function == null) {
					continue;
				}
				addCandidate(candidates, function, "ref:" + name);
			}
		}
	}

	private void discoverByName(Map<String, Candidate> candidates, int limit) {
		FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
		while (functions.hasNext() && candidates.size() < limit) {
			if (monitor.isCancelled()) {
				break;
			}
			Function function = functions.next();
			if (looksLikeConfigurationFunction(function.getName())) {
				addCandidate(candidates, function, "name:configuration");
			}
		}
	}

	private void discoverBySelectorStrings(Map<String, Candidate> candidates, int limit) {
		DefinedStringIterator strings = DefinedStringIterator.forProgram(currentProgram, currentSelection);
		for (Data data : strings) {
			if (monitor.isCancelled() || candidates.size() >= limit) {
				break;
			}
			StringDataInstance instance = StringDataInstance.getStringDataInstance(data);
			String value = instance == null ? "" : instance.getStringValue();
			if (value == null || !isConfigurationSymbolName(value)) {
				continue;
			}
			ReferenceIterator refs =
				currentProgram.getReferenceManager().getReferencesTo(data.getAddress());
			while (refs.hasNext() && candidates.size() < limit) {
				Reference ref = refs.next();
				Function function = getFunctionContaining(ref.getFromAddress());
				if (function == null) {
					continue;
				}
				addCandidate(candidates, function, "selector-string:" + value);
			}
		}
	}

	private void addFunctionByName(Map<String, Candidate> candidates, String requested, String reason) {
		String normalized = requested.startsWith("_") ? requested.substring(1) : requested;
		FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
		while (functions.hasNext()) {
			Function function = functions.next();
			String name = function.getName();
			String nameNormalized = name.startsWith("_") ? name.substring(1) : name;
			if (name.equals(requested) || nameNormalized.equals(normalized)) {
				addCandidate(candidates, function, reason);
			}
		}
	}

	private void addFunctionByAddress(Map<String, Candidate> candidates, String requested, String reason) {
		try {
			Address address = toAddr(requested);
			Function function = getFunctionAt(address);
			if (function == null) {
				function = getFunctionContaining(address);
			}
			if (function != null) {
				addCandidate(candidates, function, reason);
			}
		}
		catch (Exception ignored) {
		}
	}

	private void addCandidate(Map<String, Candidate> candidates, Function function, String reason) {
		String key = function.getEntryPoint().toString();
		Candidate candidate = candidates.get(key);
		if (candidate == null) {
			candidate = new Candidate(function);
			candidates.put(key, candidate);
		}
		candidate.reasons.add(reason);
	}

	private boolean looksLikeConfigurationFunction(String name) {
		String lower = name.toLowerCase(Locale.ROOT);
		return lower.contains("configurexpcinterface") ||
			(lower.contains("xpc") && lower.contains("interface")) ||
			lower.contains("interfacewithprotocol");
	}

	private boolean isConfigurationSymbolName(String name) {
		String lower = name.toLowerCase(Locale.ROOT);
		return lower.contains("setclass:forselector:argumentindex:ofreply") ||
			lower.contains("setclasses:forselector:argumentindex:ofreply") ||
			lower.contains("setclass_forselector_argumentindex_ofreply") ||
			lower.contains("setclasses_forselector_argumentindex_ofreply") ||
			lower.contains("interfacewithprotocol");
	}

	private String canonicalAllowedSelector(String line) {
		String lower = line.toLowerCase(Locale.ROOT);
		if (lower.contains("setclasses:forselector:argumentindex:ofreply") ||
				lower.contains("setclasses_forselector_argumentindex_ofreply")) {
			return "setClasses:forSelector:argumentIndex:ofReply:";
		}
		if (lower.contains("setclass:forselector:argumentindex:ofreply") ||
				lower.contains("setclass_forselector_argumentindex_ofreply")) {
			return "setClass:forSelector:argumentIndex:ofReply:";
		}
		return "";
	}

	private boolean isInterfaceWithProtocolLine(String line) {
		String lower = line.toLowerCase(Locale.ROOT);
		return lower.contains("interfacewithprotocol:") || lower.contains("interfacewithprotocol_");
	}

	private Set<String> extractMatches(Pattern pattern, String text) {
		Set<String> matches = new LinkedHashSet<>();
		Matcher matcher = pattern.matcher(text);
		while (matcher.find()) {
			String value = matcher.group(1);
			if (value != null && !value.isEmpty()) {
				matches.add(value);
			}
		}
		return matches;
	}

	private String excerpt(String[] lines, int index, int radius) {
		int start = Math.max(0, index - radius);
		int end = Math.min(lines.length, index + radius + 1);
		StringBuilder builder = new StringBuilder();
		for (int i = start; i < end; i++) {
			builder.append(i + 1).append(": ").append(lines[i]).append("\n");
		}
		return builder.toString().trim();
	}

	private String firstLines(String text, int limit) {
		String[] lines = text.split("\\R", -1);
		StringBuilder builder = new StringBuilder();
		for (int i = 0; i < Math.min(limit, lines.length); i++) {
			builder.append(lines[i]).append("\n");
		}
		return builder.toString().trim();
	}

	private JsonArray toJsonArray(Iterable<String> values) {
		JsonArray array = new JsonArray();
		for (String value : values) {
			array.add(value);
		}
		return array;
	}

	private Args parseArgs() {
		Args parsed = new Args();
		for (String arg : getScriptArgs()) {
			int index = arg.indexOf('=');
			if (index <= 0) {
				continue;
			}
			String key = arg.substring(0, index).trim().toLowerCase(Locale.ROOT).replace('-', '_');
			String value = arg.substring(index + 1);
			if ("function".equals(key)) {
				parsed.functions.add(value);
			}
			else if ("address".equals(key)) {
				parsed.addresses.add(value);
			}
			else {
				parsed.options.put(key, value);
			}
		}
		return parsed;
	}

	private String requireArg(Map<String, String> args, String key) {
		String value = args.get(key);
		if (value == null || value.isEmpty()) {
			throw new IllegalArgumentException("missing required argument: " + key);
		}
		return value;
	}

	private int parseInt(String value, int fallback) {
		if (value == null || value.isEmpty()) {
			return fallback;
		}
		return Integer.parseInt(value);
	}

	private boolean parseBoolean(String value, boolean fallback) {
		if (value == null || value.isEmpty()) {
			return fallback;
		}
		return "1".equals(value) || "true".equalsIgnoreCase(value) || "yes".equalsIgnoreCase(value);
	}

	private void writeJson(File file, JsonObject payload) throws Exception {
		File parent = file.getParentFile();
		if (parent != null && !parent.exists() && !parent.mkdirs()) {
			throw new IllegalStateException("failed to create " + parent);
		}
		try (Writer writer = new OutputStreamWriter(new FileOutputStream(file), StandardCharsets.UTF_8)) {
			gson.toJson(payload, writer);
			writer.write("\n");
		}
	}
}
