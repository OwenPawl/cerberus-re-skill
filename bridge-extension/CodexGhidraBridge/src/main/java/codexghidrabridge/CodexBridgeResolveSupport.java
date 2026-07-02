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


abstract class CodexBridgeResolveSupport extends CodexBridgeJsonSupport {

	CodexBridgeResolveSupport(CodexBridgePlugin plugin, CodexBridgeProvider provider) {
		super(plugin, provider);
	}

	protected Program requireProgram() throws BridgeException {
		Program program = plugin.getCurrentProgram();
		if (program == null) {
			throw new BridgeException(409, "no active program in the GUI session");
		}
		return program;
	}

	protected void ensureWritable(Program program) throws BridgeException {
		RepositoryState state = repositoryStateFor(program);
		if (!state.hasProgram) {
			throw new BridgeException(409, "no active program");
		}
		if (state.readOnly) {
			throw new BridgeException(409, "program is read-only");
		}
		if (state.versioned && !state.checkedOut) {
			throw new BridgeException(409, "versioned program is not checked out for write");
		}
		if (!state.writableProject) {
			throw new BridgeException(409, "program is not in a writable project");
		}
	}

	protected void requireWriteFlags(JsonObject body, boolean destructive) throws BridgeException {
		if (!optBoolean(body, "write", false)) {
			throw new BridgeException(400, "mutating requests require write=true");
		}
		if (destructive && !optBoolean(body, "destructive", false)) {
			throw new BridgeException(400, "destructive requests require destructive=true");
		}
	}

	protected boolean isAuthorized(Headers headers) {
		String authorization = headers.getFirst("Authorization");
		return authorization != null && authorization.equals("Bearer " + token);
	}

	protected JsonObject readBody(HttpExchange exchange) throws IOException {
		try (InputStream inputStream = exchange.getRequestBody()) {
			String text = new String(inputStream.readAllBytes(), StandardCharsets.UTF_8).trim();
			if (text.isEmpty()) {
				return new JsonObject();
			}
			JsonElement element = JsonParser.parseString(text);
			if (!element.isJsonObject()) {
				throw new IOException("request body must be a JSON object");
			}
			return element.getAsJsonObject();
		}
	}

	protected void sendJson(HttpExchange exchange, int statusCode, JsonElement result, String error)
			throws IOException {
		JsonObject envelope = new JsonObject();
		envelope.addProperty("ok", error == null);
		envelope.add("result", result == null ? JsonNull.INSTANCE : result);
		envelope.addProperty("error", error);
		envelope.addProperty("state_version", plugin.getStateVersion());
		envelope.addProperty("program_path", programPath(plugin.getCurrentProgram()));
		envelope.addProperty("tool_name", plugin.getTool().getToolName());
		byte[] bytes = GSON.toJson(envelope).getBytes(StandardCharsets.UTF_8);
		exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
		exchange.sendResponseHeaders(statusCode, bytes.length);
		try (OutputStream outputStream = exchange.getResponseBody()) {
			outputStream.write(bytes);
		}
	}

	protected boolean hasExplicitSessionSelector(JsonObject body) {
		return hasAny(body, "session", "session_id", "project", "project_name", "program",
			"program_name");
	}

	protected boolean hasExplicitFunctionSelector(JsonObject body) {
		return optObject(body, "function_ref") != null || hasAny(body, "function", "function_name");
	}

	protected boolean hasExplicitAddressSelector(JsonObject body) {
		return optObject(body, "location_ref") != null || hasAny(body, "address", "entry", "start");
	}

	protected boolean hasAnyExplicitTargetSelector(JsonObject body) {
		return hasExplicitSessionSelector(body) || hasExplicitFunctionSelector(body) ||
			hasExplicitAddressSelector(body);
	}

	protected Function resolveFunction(Program program, JsonObject body) throws Exception {
		return resolveFunction(program, body, false);
	}

	protected Function resolveFunction(Program program, JsonObject body, boolean allowMissing)
			throws Exception {
		JsonObject functionRef = optObject(body, "function_ref");
		if (functionRef != null) {
			String entry = optString(functionRef, "entry");
			if (!entry.isEmpty()) {
				Function function = program.getFunctionManager().getFunctionAt(parseAddress(program, entry));
				if (function != null) {
					return function;
				}
			}
		}
		String functionName = optString(body, "function", "function_name");
		if (!functionName.isEmpty()) {
			Function byName = resolveFunctionByName(program, functionName);
			if (byName != null) {
				return byName;
			}
			Address parsed = tryParseAddress(program, functionName);
			if (parsed != null) {
				Function byAddress = program.getFunctionManager().getFunctionContaining(parsed);
				if (byAddress != null) {
					return byAddress;
				}
			}
		}
		String addressString = optString(body, "address", "entry");
		if (!addressString.isEmpty()) {
			Address address = parseAddress(program, addressString);
			Function byAddress = program.getFunctionManager().getFunctionContaining(address);
			if (byAddress != null) {
				return byAddress;
			}
		}
		if (hasAnyExplicitTargetSelector(body)) {
			if (allowMissing) {
				return null;
			}
			throw new BridgeException(404, "unable to resolve function from explicit target");
		}
		Function current = plugin.getCurrentFunction();
		if (current != null) {
			return current;
		}
		if (allowMissing) {
			return null;
		}
		throw new BridgeException(404, "unable to resolve function");
	}

	protected Function resolveFunctionByName(Program program, String name) {
		String normalizedName = normalizeFunctionLookupValue(name, false);
		Function exact = null;
		Function normalizedExact = null;
		Function caseInsensitive = null;
		Function contains = null;
		for (Function function : program.getListing().getGlobalFunctions(name)) {
			return function;
		}
		for (ghidra.program.model.listing.FunctionIterator iterator =
			program.getFunctionManager().getFunctions(true); iterator.hasNext();) {
			Function function = iterator.next();
			String functionName = function.getName();
			String signature = function.getPrototypeString(false, false);
			if (name.equals(functionName) || name.equals(signature)) {
				exact = function;
				break;
			}
			if (normalizedExact == null && (normalizedName.equals(
				normalizeFunctionLookupValue(functionName, false)) || normalizedName.equals(
					normalizeFunctionLookupValue(signature, false)))) {
				normalizedExact = function;
			}
			if (caseInsensitive == null &&
				(functionName.equalsIgnoreCase(name) || signature.equalsIgnoreCase(name))) {
				caseInsensitive = function;
			}
			if (contains == null &&
				(matchesNormalizedQuery(functionName, name, false, false) ||
					matchesNormalizedQuery(signature, name, false, false))) {
				contains = function;
			}
		}
		return exact != null ? exact :
			normalizedExact != null ? normalizedExact :
				caseInsensitive != null ? caseInsensitive : contains;
	}

	protected Variable resolveVariable(Program program, JsonObject body, boolean allowMissing)
			throws Exception {
		JsonObject ref = optObject(body, "variable_ref");
		Function function = null;
		String variableName = "";
		String kind = "";
		String storage = "";
		if (ref != null) {
			String functionEntry = optString(ref, "function_entry");
			if (!functionEntry.isEmpty()) {
				function = program.getFunctionManager().getFunctionAt(parseAddress(program, functionEntry));
			}
			variableName = optString(ref, "name");
			kind = optString(ref, "kind");
			storage = optString(ref, "storage");
		}
		if (function == null) {
			function = resolveFunction(program, body, true);
		}
		if (variableName.isEmpty()) {
			variableName = optString(body, "variable", "name");
		}
		if (kind.isEmpty()) {
			kind = optString(body, "kind");
		}
		if (storage.isEmpty()) {
			storage = optString(body, "storage");
		}
		if (function != null) {
			if ("return".equals(kind)) {
				return function.getReturn();
			}
			for (Parameter parameter : function.getParameters()) {
				if (matchesVariable(parameter, variableName, kind, storage)) {
					return parameter;
				}
			}
			for (Variable local : function.getLocalVariables()) {
				if (matchesVariable(local, variableName, kind, storage)) {
					return local;
				}
			}
		}
		if (allowMissing) {
			return null;
		}
		throw new BridgeException(404, "unable to resolve variable");
	}

	protected boolean matchesVariable(Variable variable, String name, String kind, String storage) {
		if (!name.isEmpty() && !name.equals(variable.getName())) {
			return false;
		}
		if (!kind.isEmpty() && !kind.equalsIgnoreCase(variableKind(variable))) {
			return false;
		}
		if (!storage.isEmpty() && !storage.equals(variable.getVariableStorage().toString())) {
			return false;
		}
		return true;
	}

	protected Address resolveAddress(Program program, JsonObject body, boolean allowMissing)
			throws Exception {
		Address explicit = resolveExactAddress(program, body, true);
		if (explicit != null) {
			return explicit;
		}
		if (hasAnyExplicitTargetSelector(body)) {
			if (allowMissing) {
				return null;
			}
			throw new BridgeException(404, "unable to resolve address from explicit target");
		}
		Function function = resolveFunction(program, body, true);
		if (function != null) {
			return function.getEntryPoint();
		}
		Address current = plugin.getCurrentAddress();
		if (current != null) {
			return current;
		}
		if (allowMissing) {
			return null;
		}
		throw new BridgeException(404, "unable to resolve address");
	}

	protected Address resolveExactAddress(Program program, JsonObject body, boolean allowMissing)
			throws Exception {
		JsonObject locationRef = optObject(body, "location_ref");
		if (locationRef != null) {
			String address = optString(locationRef, "address");
			if (!address.isEmpty()) {
				return parseAddress(program, address);
			}
		}
		String address = optString(body, "address", "entry", "start");
		if (!address.isEmpty()) {
			return parseAddress(program, address);
		}
		if (allowMissing) {
			return null;
		}
		throw new BridgeException(404, "unable to resolve exact address");
	}

	protected List<Symbol> resolveSymbols(Program program, JsonObject body, boolean allowMissing)
			throws Exception {
		List<Symbol> matches = new ArrayList<>();
		JsonObject symbolRef = optObject(body, "symbol_ref");
		String query = optString(body, "symbol", "name", "query");
		String addressText = optString(body, "address");
		if (symbolRef != null) {
			if (query.isEmpty()) {
				query = optString(symbolRef, "name");
			}
			if (addressText.isEmpty()) {
				addressText = optString(symbolRef, "address");
			}
		}
		if (!addressText.isEmpty()) {
			Address address = parseAddress(program, addressText);
			for (Symbol symbol : program.getSymbolTable().getSymbols(address)) {
				matches.add(symbol);
			}
		}
		if (!query.isEmpty()) {
			String normalizedQuery = normalizeForSearch(query, false);
			for (SymbolIterator iterator = program.getSymbolTable().getAllSymbols(true); iterator
					.hasNext();) {
				Symbol symbol = iterator.next();
				String name = symbol.getName();
				if (name.equals(query) || name.equalsIgnoreCase(query) ||
					normalizeForSearch(name, false).contains(normalizedQuery)) {
					matches.add(symbol);
				}
			}
		}
		if (matches.isEmpty() && !allowMissing) {
			throw new BridgeException(404, "unable to resolve symbol");
		}
		List<Symbol> unique = new ArrayList<>();
		Set<String> seen = new LinkedHashSet<>();
		for (Symbol symbol : matches) {
			String key = symbol.getAddress().toString() + "|" + symbol.getName() + "|" +
				symbol.getSymbolType();
			if (seen.add(key)) {
				unique.add(symbol);
			}
		}
		final String requestedQuery = query;
		unique.sort(Comparator
			.comparing((Symbol symbol) -> !symbol.getName().equals(requestedQuery))
			.thenComparing(symbol -> !symbol.getName().equalsIgnoreCase(requestedQuery))
			.thenComparing(Symbol::isExternal)
			.thenComparing((Symbol symbol) -> -referenceCount(program, symbol.getAddress()))
			.thenComparing(Symbol::getName, String.CASE_INSENSITIVE_ORDER)
			.thenComparing(symbol -> symbol.getAddress().toString()));
		return unique;
	}

	protected Address resolveEndAddress(Program program, JsonObject body, Address start) throws Exception {
		String endString = optString(body, "end", "body_end");
		if (!endString.isEmpty()) {
			return parseAddress(program, endString);
		}
		if (body.has("length")) {
			long length = body.get("length").getAsLong();
			return start.add(Math.max(length - 1L, 0L));
		}
		return start;
	}

	protected DataType resolveDataType(Program program, JsonObject body, boolean allowBuiltin)
			throws Exception {
		JsonObject datatypeRef = optObject(body, "datatype_ref");
		if (datatypeRef != null) {
			DataType byRef = resolveDataType(program, optString(datatypeRef, "category_path"),
				optString(datatypeRef, "name"));
			if (byRef != null) {
				return byRef;
			}
		}
		String typeName = optString(body, "datatype", "type", "base_type");
		return resolveDataType(program, typeName, allowBuiltin);
	}

	protected DataType resolveDataType(Program program, String typeName, boolean allowBuiltin)
			throws Exception {
		if (typeName == null || typeName.isEmpty()) {
			throw new BridgeException(400, "missing datatype");
		}
		DataTypeManager manager = program.getDataTypeManager();
		DataType exact = manager.getDataType(typeName);
		if (exact != null) {
			return exact;
		}
		exact = manager.findDataType(typeName);
		if (exact != null) {
			return exact;
		}
		List<DataType> matches = new ArrayList<>();
		manager.findDataTypes(typeName, matches);
		if (!matches.isEmpty()) {
			return matches.get(0);
		}
		if (allowBuiltin) {
			DataType builtin = builtinType(typeName);
			if (builtin != null) {
				return builtin;
			}
		}
		throw new BridgeException(404, "unable to resolve datatype: " + typeName);
	}

	protected DataType resolveDataType(Program program, String categoryPath, String name) {
		if (name == null || name.isEmpty()) {
			return null;
		}
		DataTypeManager manager = program.getDataTypeManager();
		if (categoryPath != null && !categoryPath.isEmpty()) {
			return manager.getDataType(new CategoryPath(categoryPath), name);
		}
		return manager.findDataType(name);
	}

	protected DataType builtinType(String name) {
		String normalized = name.trim().toLowerCase(Locale.ROOT);
		switch (normalized) {
			case "byte":
			case "u8":
			case "uint8":
			case "int8":
				return ByteDataType.dataType;
			case "word":
			case "u16":
			case "uint16":
			case "short":
				return WordDataType.dataType;
			case "dword":
			case "u32":
			case "uint32":
			case "int":
			case "int32":
				return DWordDataType.dataType;
			case "qword":
			case "u64":
			case "uint64":
			case "longlong":
			case "int64":
				return QWordDataType.dataType;
			case "char":
				return CharDataType.dataType;
			case "float":
				return FloatDataType.dataType;
			case "double":
				return DoubleDataType.dataType;
			case "string":
			case "ascii":
				return StringDataType.dataType;
			case "unicode":
			case "utf16":
				return UnicodeDataType.dataType;
			case "pointer":
			case "void*":
				return PointerDataType.dataType;
			case "void":
				return DataType.VOID;
			default:
				return null;
		}
	}

	protected DataType createStruct(DataTypeManager manager, JsonObject body, Program program)
			throws Exception {
		String name = optString(body, "name");
		if (name.isEmpty()) {
			throw new BridgeException(400, "missing datatype name");
		}
		String categoryPath = optString(body, "category_path");
		int length = optInt(body, "length", 0);
		StructureDataType structure =
			new StructureDataType(new CategoryPath(defaultCategory(categoryPath)), name, length, manager);
		JsonArray members = optArray(body, "members");
		if (members != null) {
			for (JsonElement element : members) {
				JsonObject member = element.getAsJsonObject();
				String memberName = optString(member, "name");
				String memberTypeName = optString(member, "type", "datatype");
				DataType memberType = resolveDataType(program, memberTypeName, true);
				int memberLength = optInt(member, "length", Math.max(memberType.getLength(), 1));
				structure.add(memberType, memberLength, memberName, optString(member, "comment"));
			}
		}
		String description = optString(body, "description");
		if (!description.isEmpty()) {
			structure.setDescription(description);
		}
		return manager.addDataType(structure, DataTypeConflictHandler.DEFAULT_HANDLER);
	}

	protected DataType createEnum(DataTypeManager manager, JsonObject body, Program program)
			throws Exception {
		String name = optString(body, "name");
		if (name.isEmpty()) {
			throw new BridgeException(400, "missing datatype name");
		}
		String categoryPath = optString(body, "category_path");
		int length = optInt(body, "length", 4);
		EnumDataType dataType =
			new EnumDataType(new CategoryPath(defaultCategory(categoryPath)), name, length, manager);
		JsonArray members = optArray(body, "members");
		if (members != null) {
			for (JsonElement element : members) {
				JsonObject member = element.getAsJsonObject();
				String memberName = optString(member, "name");
				long value = member.get("value").getAsLong();
				String comment = optString(member, "comment");
				if (comment.isEmpty()) {
					dataType.add(memberName, value);
				}
				else {
					dataType.add(memberName, value, comment);
				}
			}
		}
		String description = optString(body, "description");
		if (!description.isEmpty()) {
			dataType.setDescription(description);
		}
		return manager.addDataType(dataType, DataTypeConflictHandler.DEFAULT_HANDLER);
	}

	protected DataType createTypedef(DataTypeManager manager, JsonObject body, Program program)
			throws Exception {
		String name = optString(body, "name");
		if (name.isEmpty()) {
			throw new BridgeException(400, "missing datatype name");
		}
		String categoryPath = optString(body, "category_path");
		DataType baseType = resolveDataType(program, optString(body, "base_type", "type"), true);
		TypedefDataType type =
			new TypedefDataType(new CategoryPath(defaultCategory(categoryPath)), name, baseType, manager);
		String description = optString(body, "description");
		if (!description.isEmpty()) {
			type.setDescription(description);
		}
		return manager.addDataType(type, DataTypeConflictHandler.DEFAULT_HANDLER);
	}

	protected void updateDatatype(DataType dataType, JsonObject body, Program program)
			throws Exception {
		String newName = optString(body, "new_name", "rename");
		String categoryPath = optString(body, "new_category_path", "category_path");
		String description = optString(body, "description");
		if (!newName.isEmpty() && !categoryPath.isEmpty()) {
			dataType.setNameAndCategory(new CategoryPath(defaultCategory(categoryPath)), newName);
		}
		else if (!newName.isEmpty()) {
			dataType.setName(newName);
		}
		else if (!categoryPath.isEmpty()) {
			dataType.setCategoryPath(new CategoryPath(defaultCategory(categoryPath)));
		}
		if (!description.isEmpty()) {
			dataType.setDescription(description);
		}
		JsonArray members = optArray(body, "members");
		if (members != null && dataType instanceof Structure) {
			Structure structure = (Structure) dataType;
			structure.deleteAll();
			for (JsonElement element : members) {
				JsonObject member = element.getAsJsonObject();
				DataType memberType =
					resolveDataType(program, optString(member, "type", "datatype"), true);
				int memberLength = optInt(member, "length", Math.max(memberType.getLength(), 1));
				structure.add(memberType, memberLength, optString(member, "name"),
					optString(member, "comment"));
			}
		}
		if (members != null && dataType instanceof Enum) {
			Enum enumType = (Enum) dataType;
			for (String name : enumType.getNames()) {
				enumType.remove(name);
			}
			for (JsonElement element : members) {
				JsonObject member = element.getAsJsonObject();
				String name = optString(member, "name");
				long value = member.get("value").getAsLong();
				String comment = optString(member, "comment");
				if (comment.isEmpty()) {
					enumType.add(name, value);
				}
				else {
					enumType.add(name, value, comment);
				}
			}
		}
	}

	protected JsonObject readJsonObject(File path) throws IOException {
		try (Reader reader =
			new InputStreamReader(new FileInputStream(path), StandardCharsets.UTF_8)) {
			JsonElement element = JsonParser.parseReader(reader);
			if (!element.isJsonObject()) {
				throw new IOException("expected JSON object in " + path);
			}
			return element.getAsJsonObject();
		}
	}

	protected void writeJson(File path, JsonObject payload) throws IOException {
		File parent = path.getParentFile();
		if (parent != null && !parent.exists() && !parent.mkdirs()) {
			throw new IOException("failed to create " + parent);
		}
		File tempFile = File.createTempFile(path.getName(), ".tmp", parent);
		try (Writer writer =
			new OutputStreamWriter(new FileOutputStream(tempFile), StandardCharsets.UTF_8)) {
			GSON.toJson(payload, writer);
		}
		try {
			Files.move(tempFile.toPath(), path.toPath(), StandardCopyOption.REPLACE_EXISTING,
				StandardCopyOption.ATOMIC_MOVE);
		}
		catch (AtomicMoveNotSupportedException e) {
			Files.move(tempFile.toPath(), path.toPath(), StandardCopyOption.REPLACE_EXISTING);
		}
	}

	protected Address parseAddress(Program program, String text) throws BridgeException {
		Address address = tryParseAddress(program, text);
		if (address == null) {
			throw new BridgeException(404, "unable to resolve address: " + text);
		}
		return address;
	}

	protected Address tryParseAddress(Program program, String text) {
		if (text == null || text.isEmpty()) {
			return null;
		}
		Address[] parsed = program.parseAddress(text);
		if (parsed != null && parsed.length > 0) {
			return parsed[0];
		}
		try {
			return new FlatProgramAPI(program, TaskMonitor.DUMMY).toAddr(text);
		}
		catch (Exception ignored) {
			return null;
		}
	}

}
