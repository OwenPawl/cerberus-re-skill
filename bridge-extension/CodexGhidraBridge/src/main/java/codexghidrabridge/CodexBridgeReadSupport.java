/* ###
 * IP: GHIDRA
 */
package codexghidrabridge;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.io.Writer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.swing.Timer;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.ProjectLocator;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.QWordDataType;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.UnicodeDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.LocalVariable;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;


abstract class CodexBridgeReadSupport extends CodexBridgeMutationSupport {

	CodexBridgeReadSupport(CodexBridgePlugin plugin, CodexBridgeProvider provider) {
		super(plugin, provider);
	}

	protected JsonElement handleHealth() {
		JsonObject result = new JsonObject();
		result.addProperty("armed", armed);
		result.addProperty("bridge_url", bridgeUrl);
		result.addProperty("state_version", plugin.getStateVersion());
		return result;
	}

	protected JsonElement handleSession() {
		JsonObject result = new JsonObject();
		result.addProperty("armed", armed);
		result.addProperty("session_id", sessionId);
		result.addProperty("bridge_url", bridgeUrl);
		result.addProperty("tool_name", plugin.getTool().getToolName());
		result.addProperty("started_at", startedAt);
		result.add("repository", repositoryToJson(repositoryStateFor(plugin.getCurrentProgram())));
		result.add("current_context", handleContext());
		return result;
	}

	protected JsonObject handleContext() {
		JsonObject result = new JsonObject();
		Program program = plugin.getCurrentProgram();
		result.addProperty("has_program", program != null);
		if (program != null) {
			result.addProperty("program_name", program.getName());
			result.addProperty("program_path", programPath(program));
			result.addProperty("executable_path", empty(program.getExecutablePath()));
		}
		Address currentAddress = plugin.getCurrentAddress();
		if (currentAddress != null) {
			result.add("location_ref", locationRef(program, currentAddress));
			result.addProperty("address", currentAddress.toString());
		}
		Function currentFunction = plugin.getCurrentFunction();
		if (currentFunction != null) {
			result.add("function_ref", functionRef(currentFunction));
			result.addProperty("function_name", currentFunction.getName());
		}
		ProgramLocation location = plugin.getProgramLocation();
		if (location != null) {
			result.addProperty("location_class", location.getClass().getName());
		}
		JsonArray selection = selectionToJson(plugin.getProgramSelection(), 32);
		JsonArray highlight = selectionToJson(plugin.getProgramHighlight(), 32);
		result.add("selection", selection);
		result.add("highlight", highlight);
		return result;
	}

	protected JsonElement handleAnalyzeTarget(JsonObject body) throws Exception {
		Program program = requireProgram();
		boolean navigate = optBoolean(body, "navigate", true);
		boolean hasExplicitTarget = optObject(body, "function_ref") != null ||
			hasAny(body, "address", "entry", "start", "function", "function_name");
		String query = optString(body, "query", "name");
		Address explicitAddress = hasExplicitAddressSelector(body) ?
			resolveExactAddress(program, body, true) : null;
		Function function = hasExplicitTarget ? resolveFunction(program, body, true) : null;
		JsonObject search = new JsonObject();
		boolean includeSearch = false;
		if (function == null && explicitAddress == null) {
			if (query.isEmpty()) {
				function = resolveFunction(program, body, true);
			}
			if (function == null && query.isEmpty()) {
				throw new BridgeException(400, "missing query or address/function");
			}
			if (function == null) {
				int limit = Math.max(1, Math.min(optInt(body, "limit", 5), 25));
				boolean exact = optBoolean(body, "exact", false);
				boolean caseSensitive = optBoolean(body, "case_sensitive", false);
				String field = optString(body, "field");
				if (field.isEmpty()) {
					field = "both";
				}
				search = buildFunctionSearchResult(program, query, limit, exact, caseSensitive, field);
				includeSearch = true;
				JsonArray matches = search.getAsJsonArray("matches");
				if (matches.size() == 0) {
					throw new BridgeException(404, "no function matches for query: " + query);
				}
				String entry =
					matches.get(0).getAsJsonObject().get("entry").getAsString();
				function = program.getFunctionManager().getFunctionAt(parseAddress(program, entry));
				if (function == null) {
					throw new BridgeException(404, "resolved search hit no longer maps to a function");
				}
			}
		}
		Address address = function != null ? function.getEntryPoint() : explicitAddress;
		if (address == null) {
			throw new BridgeException(404, "unable to resolve analysis target");
		}
		if (navigate) {
			if (!plugin.navigateTo(address)) {
				throw new BridgeException(500, "failed to navigate to " + address);
			}
		}
		JsonObject targetBody = new JsonObject();
		targetBody.addProperty("address", address.toString());
		if (function != null) {
			targetBody.add("function_ref", functionRef(function));
		}
		JsonObject result = new JsonObject();
		if (includeSearch) {
			result.add("search", search);
		}
		result.add("context", handleContext());
		result.add("function", function == null ? JsonNull.INSTANCE : functionToJson(function, true));
		result.add("references", handleReferences(targetBody));
		result.add("decompile", handleDecompile(targetBody));
		return result;
	}

	protected JsonElement handleFunction(JsonObject body) throws Exception {
		Program program = requireProgram();
		Function function = resolveFunction(program, body);
		return functionToJson(function, true);
	}

	protected JsonElement handleFunctionSearch(JsonObject body) throws Exception {
		Program program = requireProgram();
		String query = optString(body, "query", "name", "function", "function_name");
		if (query.isEmpty()) {
			throw new BridgeException(400, "missing query");
		}
		int limit = Math.max(1, Math.min(optInt(body, "limit", MAX_RESULTS), 250));
		boolean exact = optBoolean(body, "exact", false);
		boolean caseSensitive = optBoolean(body, "case_sensitive", false);
		String field = optString(body, "field");
		if (field.isEmpty()) {
			field = "both";
		}
		if (!"name".equalsIgnoreCase(field) && !"signature".equalsIgnoreCase(field) &&
			!"both".equalsIgnoreCase(field)) {
			throw new BridgeException(400, "unsupported field: " + field);
		}
		return buildFunctionSearchResult(program, query, limit, exact, caseSensitive, field);
	}

	protected JsonObject buildFunctionSearchResult(Program program, String query, int limit,
			boolean exact, boolean caseSensitive, String field) {
		JsonObject result = new JsonObject();
		result.addProperty("query", query);
		result.addProperty("field", field);
		result.addProperty("exact", exact);
		result.addProperty("case_sensitive", caseSensitive);

		String normalizedQuery = normalizeForSearch(query, caseSensitive);
		List<FunctionSearchHit> hits = new ArrayList<>();
		Set<String> seenEntries = new LinkedHashSet<>();
		for (ghidra.program.model.listing.FunctionIterator iterator =
			program.getFunctionManager().getFunctions(true); iterator.hasNext();) {
			Function function = iterator.next();
			FunctionSearchHit hit = matchFunctionSearch(function, query, normalizedQuery, exact,
				caseSensitive, field);
			if (hit == null) {
				continue;
			}
			if (!seenEntries.add(function.getEntryPoint().toString())) {
				continue;
			}
			hits.add(hit);
		}

		hits.sort(Comparator
			.comparingInt((FunctionSearchHit hit) -> hit.rank)
			.thenComparing(hit -> hit.function.getName(), String.CASE_INSENSITIVE_ORDER)
			.thenComparing(hit -> hit.function.getEntryPoint().toString()));
		result.addProperty("total_matches", hits.size());
		JsonArray matches = new JsonArray();
		for (int i = 0; i < hits.size() && i < limit; i++) {
			FunctionSearchHit hit = hits.get(i);
			JsonObject match = functionToJson(hit.function, false);
			match.addProperty("match_kind", hit.matchKind);
			match.addProperty("match_field", hit.matchField);
			match.addProperty("match_value", hit.matchValue);
			matches.add(match);
		}
		result.add("matches", matches);
		return result;
	}

	protected JsonElement handleObjcSelectorTrace(JsonObject body) throws Exception {
		Program program = requireProgram();
		String selector = optString(body, "selector", "query", "name");
		if (selector.isEmpty()) {
			throw new BridgeException(400, "missing selector");
		}
		int limit = Math.max(1, Math.min(optInt(body, "limit", 25), 100));
		boolean exact = optBoolean(body, "exact", false);
		boolean caseSensitive = optBoolean(body, "case_sensitive", false);
		String normalizedSelector = normalizeForSearch(selector, caseSensitive);

		JsonObject result = new JsonObject();
		result.addProperty("selector", selector);
		result.addProperty("exact", exact);
		result.addProperty("case_sensitive", caseSensitive);
		result.add("implementations",
			buildFunctionSearchResult(program, selector, limit, exact, caseSensitive, "name")
				.getAsJsonArray("matches"));

		JsonArray selectorStrings = new JsonArray();
		JsonArray senderCallsites = new JsonArray();
		Map<String, Function> senderFunctions = new LinkedHashMap<>();
		FlatProgramAPI flat = new FlatProgramAPI(program, TaskMonitor.DUMMY);
		DataIterator iterator = program.getListing().getDefinedData(true);
		while (iterator.hasNext()) {
			Data data = iterator.next();
			String candidate = candidateDataString(data);
			if (candidate.isEmpty()) {
				continue;
			}
			String normalizedCandidate = normalizeForSearch(candidate, caseSensitive);
			boolean matched = exact ? normalizedCandidate.equals(normalizedSelector) :
				normalizedCandidate.contains(normalizedSelector);
			if (!matched) {
				continue;
			}
			JsonObject stringHit = new JsonObject();
			stringHit.add("location_ref", locationRef(program, data.getAddress()));
			stringHit.addProperty("address", data.getAddress().toString());
			stringHit.addProperty("value", candidate);
			JsonArray sampleReferences = new JsonArray();
			Reference[] refs = flat.getReferencesTo(data.getAddress());
			stringHit.addProperty("reference_count", refs.length);
			for (int i = 0; i < refs.length && i < limit; i++) {
				Reference ref = refs[i];
				JsonObject refJson = referenceToJson(ref);
				Function sender = program.getFunctionManager().getFunctionContaining(ref.getFromAddress());
				if (sender != null) {
					refJson.add("function_ref", functionRef(sender));
					refJson.addProperty("function_name", sender.getName());
					senderFunctions.putIfAbsent(sender.getEntryPoint().toString(), sender);
				}
				sampleReferences.add(refJson);
				if (senderCallsites.size() < limit) {
					senderCallsites.add(refJson.deepCopy());
				}
			}
			stringHit.add("sample_references", sampleReferences);
			selectorStrings.add(stringHit);
			if (selectorStrings.size() >= limit) {
				break;
			}
		}

		List<Function> sortedSenderFunctions = new ArrayList<>(senderFunctions.values());
		sortedSenderFunctions.sort(
			Comparator.comparing((Function function) -> function.getName(),
				String.CASE_INSENSITIVE_ORDER)
				.thenComparing(function -> function.getEntryPoint().toString()));
		JsonArray senders = new JsonArray();
		for (int i = 0; i < sortedSenderFunctions.size() && i < limit; i++) {
			senders.add(functionToJson(sortedSenderFunctions.get(i), false));
		}

		result.add("selector_string_matches", selectorStrings);
		result.add("sender_functions", senders);
		result.add("sender_callsites", senderCallsites);
		return result;
	}

	protected JsonElement handleDecompile(JsonObject body) throws Exception {
		Program program = requireProgram();
		Function function = resolveFunction(program, body, true);
		if (function == null) {
			Address address = resolveExactAddress(program, body, true);
			if (address == null) {
				throw new BridgeException(404, "unable to resolve function from explicit target");
			}
			return buildAddressDecompileFallback(program, address);
		}
		DecompInterface decompiler = new DecompInterface();
		try {
			if (!decompiler.openProgram(program)) {
				throw new BridgeException(500, "failed to open program in decompiler");
			}
			DecompileResults results = decompiler.decompileFunction(function, 60, TaskMonitor.DUMMY);
			if (!results.decompileCompleted() || results.getDecompiledFunction() == null) {
				throw new BridgeException(500, "decompilation failed: " + results.getErrorMessage());
			}
			JsonObject payload = new JsonObject();
			String cText = results.getDecompiledFunction().getC();
			payload.add("function_ref", functionRef(function));
			payload.addProperty("signature", function.getPrototypeString(false, false));
			payload.addProperty("c", cText);
			if (isLowSignalDecompile(function, cText)) {
				payload.addProperty("signal", "low");
				payload.add("enrichment", buildLowSignalFunctionContext(program, function, 12));
			}
			return payload;
		}
		finally {
			decompiler.dispose();
		}
	}

	protected JsonObject buildAddressDecompileFallback(Program program, Address address)
			throws Exception {
		JsonObject payload = new JsonObject();
		payload.addProperty("requested_address", address.toString());
		payload.addProperty("available", false);
		payload.addProperty("reason", "no containing function");
		payload.add("location_ref", locationRef(program, address));
		Function containing = program.getFunctionManager().getFunctionContaining(address);
		payload.add("containing_function",
			containing == null ? JsonNull.INSTANCE : functionToJson(containing, false));
		Instruction instruction = program.getListing().getInstructionContaining(address);
		if (instruction != null) {
			payload.add("instruction",
				instructionSnapshot(program, instruction, instruction.getAddress(),
					instructionBytes(new FlatProgramAPI(program, TaskMonitor.DUMMY), instruction)));
		}
		Data data = program.getListing().getDefinedDataContaining(address);
		if (data != null) {
			payload.add("data", dataToJson(program, data, 10));
		}
		Address start = address;
		Address end = address;
		try {
			end = address.add(31);
		}
		catch (Exception ignored) {
			end = address;
		}
		payload.add("range", rangeSnapshot(program, start, end));
		return payload;
	}

	protected JsonElement handleReferences(JsonObject body) throws Exception {
		Program program = requireProgram();
		JsonObject result = new JsonObject();
		boolean rawAddressRequested = hasExplicitAddressSelector(body);
		Function function = null;
		Address address;
		if (rawAddressRequested) {
			address = resolveExactAddress(program, body, false);
			Function containing = program.getFunctionManager().getFunctionContaining(address);
			if (containing != null) {
				result.add("containing_function", functionToJson(containing, false));
			}
		}
		else {
			try {
				function = resolveFunction(program, body);
			}
			catch (BridgeException ignored) {
				// Fall through and try raw address resolution.
			}
			address = function == null ? resolveExactAddress(program, body, true) : function.getEntryPoint();
		}
		if (function != null) {
			result.add("function_ref", functionRef(function));
			JsonArray callers = new JsonArray();
			List<Function> sortedCallers = new ArrayList<>(function.getCallingFunctions(TaskMonitor.DUMMY));
			sortedCallers.sort(Comparator.comparing(f -> f.getEntryPoint().toString()));
			for (Function caller : sortedCallers) {
				callers.add(functionToJson(caller, false));
			}
			result.add("callers", callers);

			JsonArray callees = new JsonArray();
			List<Function> sortedCallees = new ArrayList<>(function.getCalledFunctions(TaskMonitor.DUMMY));
			sortedCallees.sort(Comparator.comparing(f -> f.getEntryPoint().toString()));
			for (Function callee : sortedCallees) {
				callees.add(functionToJson(callee, false));
			}
			result.add("callees", callees);
		}
		result.addProperty("address", address.toString());
		result.add("references_to", referencesToJson(new FlatProgramAPI(program), address, MAX_RESULTS));
		result.add("references_from", referencesFromJson(new FlatProgramAPI(program), address, MAX_RESULTS));
		Data data = program.getListing().getDefinedDataContaining(address);
		if (data != null) {
			result.add("data", dataToJson(program, data, 10));
		}
		return result;
	}

	protected JsonElement handleDataGet(JsonObject body) throws Exception {
		Program program = requireProgram();
		Address address = resolveExactAddress(program, body, false);
		Data data = program.getListing().getDefinedDataContaining(address);
		if (data == null) {
			throw new BridgeException(404, "no defined data at or containing " + address);
		}
		JsonObject result = dataToJson(program, data, MAX_RESULTS);
		result.addProperty("requested_address", address.toString());
		return result;
	}

	protected JsonElement handleStringsSearch(JsonObject body) throws Exception {
		Program program = requireProgram();
		String query = optString(body, "query", "value", "string");
		if (query.isEmpty()) {
			throw new BridgeException(400, "missing query");
		}
		int limit = Math.max(1, Math.min(optInt(body, "limit", MAX_RESULTS), 250));
		boolean exact = optBoolean(body, "exact", false);
		boolean caseSensitive = optBoolean(body, "case_sensitive", false);
		String normalizedQuery = normalizeForSearch(query, caseSensitive);
		JsonObject result = new JsonObject();
		result.addProperty("query", query);
		result.addProperty("exact", exact);
		result.addProperty("case_sensitive", caseSensitive);
		JsonArray matches = new JsonArray();
		DataIterator iterator = program.getListing().getDefinedData(true);
		while (iterator.hasNext()) {
			Data data = iterator.next();
			String candidate = candidateDataString(data);
			if (candidate.isEmpty()) {
				continue;
			}
			String normalizedCandidate = normalizeForSearch(candidate, caseSensitive);
			boolean matched = exact ? normalizedCandidate.equals(normalizedQuery) :
				normalizedCandidate.contains(normalizedQuery);
			if (!matched) {
				continue;
			}
			matches.add(dataToJson(program, data, 10));
			if (matches.size() >= limit) {
				break;
			}
		}
		result.addProperty("match_count", matches.size());
		result.add("matches", matches);
		return result;
	}

	protected JsonElement handleSymbolsGet(JsonObject body) throws Exception {
		Program program = requireProgram();
		List<Symbol> symbols = resolveSymbols(program, body, false);
		JsonObject result = new JsonObject();
		JsonArray matches = new JsonArray();
		for (Symbol symbol : symbols) {
			matches.add(symbolToJson(program, symbol, 10));
		}
		result.addProperty("match_count", matches.size());
		result.add("matches", matches);
		if (!symbols.isEmpty()) {
			result.add("symbol", symbolToJson(program, symbols.get(0), 10));
		}
		return result;
	}

	protected JsonElement handleSymbolXrefs(JsonObject body) throws Exception {
		Program program = requireProgram();
		List<Symbol> symbols = resolveSymbols(program, body, false);
		Symbol symbol = symbols.get(0);
		JsonObject result = new JsonObject();
		result.add("symbol", symbolToJson(program, symbol, 10));
		result.add("references_to",
			referencesToJson(new FlatProgramAPI(program), symbol.getAddress(), MAX_RESULTS));
		result.add("references_from",
			referencesFromJson(new FlatProgramAPI(program), symbol.getAddress(), MAX_RESULTS));
		return result;
	}

	protected JsonElement handleMemoryRange(JsonObject body) throws Exception {
		Program program = requireProgram();
		Address start = resolveExactAddress(program, body, false);
		Address end = resolveEndAddress(program, body, start);
		long lengthLong = end.subtract(start) + 1L;
		int length = (int) Math.max(1L, Math.min(lengthLong, MAX_BYTES_IN_LOG));
		byte[] bytes;
		try {
			bytes = new FlatProgramAPI(program, TaskMonitor.DUMMY).getBytes(start, length);
		}
		catch (Exception e) {
			throw new BridgeException(500, "failed to read memory range: " + e.getMessage());
		}
		JsonObject result = rangeSnapshot(program, start, end);
		result.addProperty("ascii", bytesToAscii(bytes));
		result.addProperty("effective_length", length);
		MemoryBlock block = program.getMemory().getBlock(start);
		if (block != null) {
			result.addProperty("block", block.getName());
			result.addProperty("source_name", block.getSourceName());
		}
		return result;
	}

	protected JsonElement handleVariables(JsonObject body) throws Exception {
		Program program = requireProgram();
		Function function = resolveFunction(program, body);
		JsonObject result = new JsonObject();
		result.add("function_ref", functionRef(function));
		JsonArray params = new JsonArray();
		for (Parameter parameter : function.getParameters()) {
			params.add(variableToJson(parameter));
		}
		result.add("parameters", params);
		JsonArray locals = new JsonArray();
		for (Variable local : function.getLocalVariables()) {
			locals.add(variableToJson(local));
		}
		result.add("locals", locals);
		result.add("return", variableToJson(function.getReturn()));
		return result;
	}

	protected JsonElement handleDatatypeSearch(JsonObject body) throws Exception {
		Program program = requireProgram();
		String query = optString(body, "query", "name", "type");
		if (query.isEmpty()) {
			throw new BridgeException(400, "missing query");
		}
		int limit = optInt(body, "limit", MAX_RESULTS);
		DataTypeManager manager = program.getDataTypeManager();
		List<DataType> matches = new ArrayList<>();
		manager.findDataTypes(query, matches);
		matches.sort(Comparator.comparing(DataType::getPathName));
		JsonArray result = new JsonArray();
		Set<String> seen = new LinkedHashSet<>();
		for (DataType dataType : matches) {
			if (dataType == null) {
				continue;
			}
			if (!seen.add(dataType.getPathName())) {
				continue;
			}
			result.add(dataTypeToJson(dataType));
			if (result.size() >= limit) {
				break;
			}
		}
		return result;
	}

	protected JsonElement handleNavigate(JsonObject body) throws Exception {
		Program program = requireProgram();
		Address address = resolveAddress(program, body, false);
		if (!plugin.navigateTo(address)) {
			throw new BridgeException(500, "failed to navigate to " + address);
		}
		JsonObject result = new JsonObject();
		result.add("location_ref", locationRef(program, address));
		result.add("context", handleContext());
		return result;
	}

	protected JsonElement handleProgramSave(JsonObject body) throws Exception {
		Program program = requireProgram();
		requireWriteFlags(body, false);
		ensureWritable(program);
		RepositoryState before = repositoryStateFor(program);
		String description = optString(body, "description", "comment", "message");
		if (description.isEmpty()) {
			description = "CodexBridge: program-save";
		}
		try {
			if (before.canSave && before.changed) {
				program.save(description, TaskMonitor.DUMMY);
			}
		}
		catch (Exception e) {
			throw new BridgeException(500, "program save failed: " + e.getMessage());
		}
		plugin.incrementState("program-save");
		updateSessionIfArmed();
		RepositoryState after = repositoryStateFor(program);
		JsonObject result = new JsonObject();
		result.addProperty("saved", !after.changed);
		result.addProperty("changed_before", before.changed);
		result.addProperty("changed_after", after.changed);
		result.addProperty("description", description);
		result.add("repository", repositoryToJson(after));
		return result;
	}
}
