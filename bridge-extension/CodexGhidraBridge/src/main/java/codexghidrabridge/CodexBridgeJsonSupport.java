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


abstract class CodexBridgeJsonSupport extends CodexBridgeBaseSupport {

	CodexBridgeJsonSupport(CodexBridgePlugin plugin, CodexBridgeProvider provider) {
		super(plugin, provider);
	}

	protected JsonObject repositoryToJson(RepositoryState state) {
		JsonObject object = new JsonObject();
		object.addProperty("has_program", state.hasProgram);
		object.addProperty("program_name", state.programName);
		object.addProperty("project_name", state.projectName);
		object.addProperty("project_location", state.projectLocation);
		object.addProperty("project_path", state.projectMarkerPath);
		object.addProperty("program_path", state.domainPath);
		object.addProperty("versioned", state.versioned);
		object.addProperty("read_only", state.readOnly);
		object.addProperty("checked_out", state.checkedOut);
		object.addProperty("checked_out_exclusive", state.exclusiveCheckout);
		object.addProperty("modified_since_checkout", state.modifiedSinceCheckout);
		object.addProperty("writable_project", state.writableProject);
		object.addProperty("can_save", state.canSave);
		object.addProperty("changed", state.changed);
		return object;
	}

	protected JsonObject functionToJson(Function function, boolean includeVariables) {
		JsonObject object = new JsonObject();
		object.add("function_ref", functionRef(function));
		object.addProperty("name", function.getName());
		object.addProperty("entry", function.getEntryPoint().toString());
		object.addProperty("signature", function.getPrototypeString(false, false));
		object.addProperty("calling_convention", empty(function.getCallingConventionName()));
		object.addProperty("comment", empty(function.getComment()));
		object.addProperty("repeatable_comment", empty(function.getRepeatableComment()));
		object.addProperty("thunk", function.isThunk());
		object.addProperty("external", function.isExternal());
		object.addProperty("is_inline", function.isInline());
		object.addProperty("has_var_args", function.hasVarArgs());
		object.addProperty("no_return", function.hasNoReturn());
		object.add("body", addressSetToJson(function.getBody(), 32));
		if (includeVariables) {
			JsonArray parameters = new JsonArray();
			for (Parameter parameter : function.getParameters()) {
				parameters.add(variableToJson(parameter));
			}
			object.add("parameters", parameters);
			JsonArray locals = new JsonArray();
			for (Variable local : function.getLocalVariables()) {
				locals.add(variableToJson(local));
			}
			object.add("locals", locals);
			object.add("return", variableToJson(function.getReturn()));
		}
		return object;
	}

	protected FunctionSearchHit matchFunctionSearch(Function function, String query,
			String normalizedQuery, boolean exact, boolean caseSensitive, String field) {
		FunctionSearchHit best = null;
		if ("name".equalsIgnoreCase(field) || "both".equalsIgnoreCase(field)) {
			best = betterFunctionSearchHit(best,
				matchFunctionSearchCandidate(function, "name", function.getName(), query,
					normalizedQuery, exact, caseSensitive));
		}
		if ("signature".equalsIgnoreCase(field) || "both".equalsIgnoreCase(field)) {
			best = betterFunctionSearchHit(best,
				matchFunctionSearchCandidate(function, "signature",
					function.getPrototypeString(false, false), query, normalizedQuery, exact,
					caseSensitive));
		}
		return best;
	}

	protected FunctionSearchHit betterFunctionSearchHit(FunctionSearchHit current,
			FunctionSearchHit candidate) {
		if (candidate == null) {
			return current;
		}
		if (current == null || candidate.rank < current.rank) {
			return candidate;
		}
		return current;
	}

	protected FunctionSearchHit matchFunctionSearchCandidate(Function function, String field,
			String candidateValue, String query, String normalizedQuery, boolean exact,
			boolean caseSensitive) {
		if (candidateValue == null || candidateValue.isEmpty()) {
			return null;
		}
		String normalizedCandidate = normalizeForSearch(candidateValue, caseSensitive);
		boolean matched = exact ? normalizedCandidate.equals(normalizedQuery) :
			normalizedCandidate.contains(normalizedQuery);
		if (!matched) {
			matched = matchesNormalizedQuery(candidateValue, query, exact, caseSensitive);
		}
		if (!matched) {
			return null;
		}
		String matchKind;
		int rank;
		if (normalizedCandidate.equals(normalizedQuery)) {
			matchKind = "exact";
			rank = "name".equals(field) ? 0 : 1;
		}
		else if (normalizedCandidate.startsWith(normalizedQuery)) {
			matchKind = "prefix";
			rank = "name".equals(field) ? 2 : 3;
		}
		else {
			matchKind = "substring";
			rank = "name".equals(field) ? 4 : 5;
		}
		return new FunctionSearchHit(function, field, candidateValue, matchKind, rank);
	}

	protected String normalizeForSearch(String value, boolean caseSensitive) {
		if (value == null) {
			return "";
		}
		return caseSensitive ? value : value.toLowerCase(Locale.ROOT);
	}

	protected String normalizeFunctionLookupValue(String value, boolean caseSensitive) {
		String normalized = normalizeForSearch(value, caseSensitive).trim();
		if (normalized.isEmpty()) {
			return normalized;
		}
		normalized = normalized.replaceAll("\\s+", " ");
		if (normalized.startsWith("-[") || normalized.startsWith("+[")) {
			int closeIndex = normalized.indexOf(']');
			int spaceIndex = normalized.indexOf(' ');
			if (spaceIndex < 0 || (closeIndex > 0 && spaceIndex > closeIndex)) {
				int separatorIndex = normalized.indexOf('_', 2);
				if (separatorIndex > 2 && (closeIndex < 0 || separatorIndex < closeIndex)) {
					normalized = normalized.substring(0, separatorIndex) + " " +
						normalized.substring(separatorIndex + 1);
				}
			}
			normalized = normalized.replace("[ ", "[");
			normalized = normalized.replace(" ]", "]");
			normalized = normalized.replace(" :", ":");
			normalized = normalized.replace("( ", "(");
			normalized = normalized.replace(" )", ")");
		}
		return normalized;
	}

	protected boolean matchesNormalizedQuery(String candidate, String query, boolean exact,
			boolean caseSensitive) {
		String normalizedCandidate = normalizeFunctionLookupValue(candidate, caseSensitive);
		String normalizedQuery = normalizeFunctionLookupValue(query, caseSensitive);
		if (normalizedCandidate.isEmpty() || normalizedQuery.isEmpty()) {
			return false;
		}
		return exact ? normalizedCandidate.equals(normalizedQuery) :
			normalizedCandidate.contains(normalizedQuery);
	}

	protected JsonObject variableToJson(Variable variable) {
		JsonObject object = new JsonObject();
		if (variable == null) {
			return object;
		}
		object.add("variable_ref", variableRef(variable));
		object.addProperty("name", variable.getName());
		object.addProperty("datatype", pathName(variable.getDataType()));
		object.addProperty("comment", empty(variable.getComment()));
		object.addProperty("storage", variable.getVariableStorage().toString());
		object.addProperty("kind", variableKind(variable));
		object.addProperty("stack_offset", variable.hasStackStorage() ? variable.getStackOffset() : 0);
		object.addProperty("first_use_offset", variable.getFirstUseOffset());
		return object;
	}

	protected JsonObject dataTypeToJson(DataType dataType) {
		JsonObject object = new JsonObject();
		object.add("datatype_ref", dataTypeRef(dataType));
		object.addProperty("name", dataType.getName());
		object.addProperty("display_name", dataType.getDisplayName());
		object.addProperty("path_name", dataType.getPathName());
		object.addProperty("category_path", dataType.getCategoryPath().getPath());
		object.addProperty("length", dataType.getLength());
		object.addProperty("description", empty(dataType.getDescription()));
		object.addProperty("kind", dataType.getClass().getSimpleName());
		return object;
	}

	protected JsonObject dataToJson(Program program, Data data, int xrefLimit) {
		JsonObject object = new JsonObject();
		object.add("location_ref", locationRef(program, data.getAddress()));
		object.addProperty("address", data.getAddress().toString());
		object.addProperty("datatype", data.getDataType().getPathName());
		object.addProperty("length", data.getLength());
		object.addProperty("value", safeValue(data));
		MemoryBlock block = program.getMemory().getBlock(data.getAddress());
		String blockName = block == null ? "" : empty(block.getName());
		object.addProperty("block", blockName);
		object.addProperty("artifact_type", classifyDataArtifact(data, blockName));
		String candidate = candidateDataString(data);
		if (!candidate.isEmpty()) {
			object.addProperty("string_value", candidate);
		}
		object.add("references_to",
			referencesToJson(new FlatProgramAPI(program, TaskMonitor.DUMMY), data.getAddress(),
				xrefLimit));
		return object;
	}

	protected JsonObject dataRef(Program program, Data data) {
		JsonObject object = new JsonObject();
		object.addProperty("program_path", programPath(program));
		object.addProperty("address", data == null ? "" : data.getAddress().toString());
		object.addProperty("datatype",
			data == null || data.getDataType() == null ? "" : data.getDataType().getPathName());
		return object;
	}

	protected String safeValue(Data data) {
		try {
			Object value = data.getValue();
			return value == null ? "" : value.toString();
		}
		catch (Exception ignored) {
			return "";
		}
	}

	protected String candidateDataString(Data data) {
		String value = safeValue(data).trim();
		if (value.isEmpty()) {
			return "";
		}
		if (value.length() >= 2 && value.startsWith("\"") && value.endsWith("\"")) {
			value = value.substring(1, value.length() - 1);
		}
		return value;
	}

	protected String classifyDataArtifact(Data data, String blockName) {
		String lowerBlock = blockName == null ? "" : blockName.toLowerCase(Locale.ROOT);
		String dataType = data.getDataType() == null ? "" : data.getDataType().getPathName().toLowerCase(Locale.ROOT);
		if (lowerBlock.contains("objc_methname")) {
			return "objc_selector";
		}
		if (lowerBlock.contains("objc_classname")) {
			return "objc_classname";
		}
		if (lowerBlock.contains("cfstring")) {
			return "cfstring";
		}
		if (lowerBlock.contains("classref")) {
			return "objc_classref";
		}
		if (lowerBlock.contains("selref")) {
			return "objc_selref";
		}
		if (lowerBlock.contains("ivar")) {
			return "objc_ivar";
		}
		if (lowerBlock.contains("protocol")) {
			return "objc_protocol";
		}
		if (dataType.contains("string")) {
			return "string";
		}
		return "data";
	}

	protected boolean isLowSignalDecompile(Function function, String cText) {
		String name = function == null ? "" : empty(function.getName());
		String c = cText == null ? "" : cText;
		if (name.startsWith("_OUTLINED_FUNCTION_")) {
			return true;
		}
		if (name.startsWith("FUN_") && function != null && function.getBody().getNumAddresses() <= 16) {
			return true;
		}
		return c.contains("_OUTLINED_FUNCTION_") || c.contains("/* WARNING:") ||
			(function != null && function.getBody().getNumAddresses() <= 12);
	}

	protected JsonObject buildLowSignalFunctionContext(Program program, Function function, int limit) {
		JsonObject payload = new JsonObject();
		payload.addProperty("name", function.getName());
		payload.addProperty("entry", function.getEntryPoint().toString());
		payload.addProperty("body_size", function.getBody().getNumAddresses());
		MemoryBlock block = program.getMemory().getBlock(function.getEntryPoint());
		payload.addProperty("section", block == null ? "" : empty(block.getName()));

		Set<String> nearbyStrings = new LinkedHashSet<>();
		Set<String> nearbySelectors = new LinkedHashSet<>();
		Set<String> nearbySymbols = new LinkedHashSet<>();
		Set<String> calledSymbols = new LinkedHashSet<>();
		Listing listing = program.getListing();
		SymbolTable symbolTable = program.getSymbolTable();
		InstructionIterator iterator = listing.getInstructions(function.getBody(), true);
		while (iterator.hasNext()) {
			Instruction instruction = iterator.next();
			for (Reference reference : instruction.getReferencesFrom()) {
				Address toAddress = reference.getToAddress();
				if (toAddress == null) {
					continue;
				}
				Data data = listing.getDefinedDataContaining(toAddress);
				if (data != null) {
					String value = candidateDataString(data);
					if (!value.isEmpty()) {
						MemoryBlock dataBlock = program.getMemory().getBlock(data.getAddress());
						String blockName =
							dataBlock == null ? "" : empty(dataBlock.getName()).toLowerCase(Locale.ROOT);
						if (blockName.contains("objc_methname") || blockName.contains("selref")) {
							nearbySelectors.add(value);
						}
						else {
							nearbyStrings.add(value);
						}
					}
				}
				Symbol symbol = symbolTable.getPrimarySymbol(toAddress);
				if (symbol != null) {
					String name = empty(symbol.getName());
					if (!name.isEmpty()) {
						nearbySymbols.add(name);
						if (reference.getReferenceType().isCall()) {
							calledSymbols.add(name);
						}
					}
				}
			}
		}
		payload.add("nearby_strings", toJsonArray(nearbyStrings, limit));
		payload.add("nearby_selectors", toJsonArray(nearbySelectors, limit));
		payload.add("nearby_symbols", toJsonArray(nearbySymbols, limit));
		payload.add("called_symbols", toJsonArray(calledSymbols, limit));
		return payload;
	}

	protected JsonArray toJsonArray(Collection<String> values, int limit) {
		JsonArray array = new JsonArray();
		int count = 0;
		for (String value : values) {
			if (value == null || value.isEmpty()) {
				continue;
			}
			array.add(value);
			count++;
			if (count >= limit) {
				break;
			}
		}
		return array;
	}

	protected String classifySymbolArtifact(Symbol symbol) {
		String name = symbol.getName();
		String lower = name.toLowerCase(Locale.ROOT);
		if (name.startsWith("-[") || name.startsWith("+[")) {
			return "objc_method";
		}
		if (name.startsWith("_OBJC_CLASS_$_")) {
			return "objc_class";
		}
		if (name.startsWith("_OBJC_METACLASS_$_")) {
			return "objc_metaclass";
		}
		if (name.startsWith("_OBJC_PROTOCOL_$_")) {
			return "objc_protocol";
		}
		if (name.startsWith("_OBJC_CATEGORY_$_")) {
			return "objc_category";
		}
		if (name.startsWith("selRef_")) {
			return "objc_selref";
		}
		if (lower.contains("classref")) {
			return "objc_classref";
		}
		if (lower.contains("ivar")) {
			return "objc_ivar";
		}
		if (name.startsWith("$s") || name.startsWith("_$s") || lower.contains("swift")) {
			return "swift_symbol";
		}
		return "symbol";
	}

	protected int referenceCount(Program program, Address address) {
		int count = 0;
		ReferenceIterator iterator = program.getReferenceManager().getReferencesTo(address);
		while (iterator.hasNext()) {
			iterator.next();
			count++;
		}
		return count;
	}

	protected String bytesToAscii(byte[] bytes) {
		StringBuilder builder = new StringBuilder();
		for (byte value : bytes) {
			int unsigned = value & 0xff;
			if (unsigned >= 32 && unsigned <= 126) {
				builder.append((char) unsigned);
			}
			else {
				builder.append('.');
			}
		}
		return builder.toString();
	}

	protected JsonArray referencesToJson(FlatProgramAPI flat, Address address, int limit) {
		JsonArray array = new JsonArray();
		Reference[] references = flat.getReferencesTo(address);
		for (int i = 0; i < references.length && i < limit; i++) {
			array.add(referenceToJson(references[i]));
		}
		return array;
	}

	protected JsonArray referencesFromJson(FlatProgramAPI flat, Address address, int limit) {
		JsonArray array = new JsonArray();
		Reference[] references = flat.getReferencesFrom(address);
		for (int i = 0; i < references.length && i < limit; i++) {
			array.add(referenceToJson(references[i]));
		}
		return array;
	}

	protected JsonObject referenceToJson(Reference reference) {
		JsonObject object = new JsonObject();
		object.addProperty("from_address", reference.getFromAddress().toString());
		object.addProperty("to_address", reference.getToAddress().toString());
		object.addProperty("reference_type", reference.getReferenceType().toString());
		object.addProperty("operand_index", reference.getOperandIndex());
		object.addProperty("primary", reference.isPrimary());
		return object;
	}

	protected JsonArray selectionToJson(ProgramSelection selection, int maxRanges) {
		if (selection == null || selection.isEmpty()) {
			return new JsonArray();
		}
		return addressSetToJson(selection, maxRanges);
	}

	protected JsonArray addressSetToJson(AddressSetView view, int maxRanges) {
		JsonArray array = new JsonArray();
		if (view == null) {
			return array;
		}
		AddressRangeIterator iterator = view.getAddressRanges();
		int count = 0;
		while (iterator.hasNext() && count < maxRanges) {
			AddressRange range = iterator.next();
			JsonObject item = new JsonObject();
			item.addProperty("start", range.getMinAddress().toString());
			item.addProperty("end", range.getMaxAddress().toString());
			item.addProperty("length", range.getLength());
			array.add(item);
			count++;
		}
		return array;
	}

	protected JsonObject locationRef(Program program, Address address) {
		JsonObject object = new JsonObject();
		object.addProperty("program_path", programPath(program));
		object.addProperty("address", address == null ? "" : address.toString());
		return object;
	}

	protected JsonObject functionRef(Function function) {
		JsonObject object = new JsonObject();
		object.addProperty("program_path", programPath(function == null ? null : function.getProgram()));
		object.addProperty("entry", function == null ? "" : function.getEntryPoint().toString());
		return object;
	}

	protected String namespacePath(Namespace namespace) {
		if (namespace == null) {
			return "";
		}
		List<String> names = new ArrayList<>();
		Namespace current = namespace;
		while (current != null && !current.isGlobal()) {
			names.add(0, current.getName());
			current = current.getParentNamespace();
		}
		return String.join("::", names);
	}

	protected JsonObject variableRef(Variable variable) {
		JsonObject object = new JsonObject();
		object.addProperty("program_path",
			programPath(variable == null ? null : variable.getProgram()));
		object.addProperty("function_entry",
			variable != null && variable.getFunction() != null ?
				variable.getFunction().getEntryPoint().toString() :
				"");
		object.addProperty("name", variable == null ? "" : variable.getName());
		object.addProperty("kind", variableKind(variable));
		object.addProperty("storage", variable == null ? "" : variable.getVariableStorage().toString());
		return object;
	}

	protected JsonObject dataTypeRef(DataType dataType) {
		JsonObject object = new JsonObject();
		object.addProperty("program_path", programPath(plugin.getCurrentProgram()));
		object.addProperty("category_path",
			dataType == null ? "" : dataType.getCategoryPath().getPath());
		object.addProperty("name", dataType == null ? "" : dataType.getName());
		object.addProperty("kind", dataType == null ? "" : dataType.getClass().getSimpleName());
		return object;
	}

	protected JsonObject symbolToJson(Program program, Symbol symbol, int xrefLimit) {
		JsonObject object = new JsonObject();
		object.addProperty("name", symbol.getName());
		object.addProperty("address", symbol.getAddress().toString());
		object.addProperty("kind", symbol.getSymbolType().toString());
		object.addProperty("source", symbol.getSource().toString());
		object.addProperty("namespace", namespacePath(symbol.getParentNamespace()));
		object.addProperty("artifact_type", classifySymbolArtifact(symbol));
		object.add("location_ref", locationRef(program, symbol.getAddress()));
		object.addProperty("xref_count",
			referenceCount(program, symbol.getAddress()));
		object.add("sample_xrefs",
			referencesToJson(new FlatProgramAPI(program, TaskMonitor.DUMMY), symbol.getAddress(),
				xrefLimit));
		return object;
	}

	protected JsonObject commentSnapshot(Program program, Address address) {
		JsonObject object = new JsonObject();
		object.addProperty("address", address.toString());
		Listing listing = program.getListing();
		object.addProperty("plate", empty(listing.getComment(CommentType.PLATE, address)));
		object.addProperty("pre", empty(listing.getComment(CommentType.PRE, address)));
		object.addProperty("post", empty(listing.getComment(CommentType.POST, address)));
		object.addProperty("eol", empty(listing.getComment(CommentType.EOL, address)));
		object.addProperty("repeatable", empty(listing.getComment(CommentType.REPEATABLE, address)));
		return object;
	}

	protected JsonObject bookmarksToJson(ghidra.program.model.listing.Bookmark[] bookmarks) {
		JsonObject object = new JsonObject();
		JsonArray array = new JsonArray();
		for (ghidra.program.model.listing.Bookmark bookmark : bookmarks) {
			JsonObject item = new JsonObject();
			item.addProperty("type", bookmark.getTypeString());
			item.addProperty("category", bookmark.getCategory());
			item.addProperty("comment", bookmark.getComment());
			array.add(item);
		}
		object.add("bookmarks", array);
		return object;
	}

	protected JsonObject bytePatchSnapshot(Program program, Address address, byte[] bytes) {
		JsonObject object = new JsonObject();
		object.addProperty("address", address.toString());
		object.addProperty("length", bytes.length);
		object.addProperty("bytes", toHex(bytes));
		Instruction instruction = program.getListing().getInstructionAt(address);
		if (instruction != null) {
			object.addProperty("instruction", instruction.toString());
		}
		return object;
	}

	protected JsonObject instructionSnapshot(Program program, Instruction instruction, Address address,
			byte[] bytes) {
		JsonObject object = new JsonObject();
		object.addProperty("address", address.toString());
		object.addProperty("bytes", toHex(bytes));
		object.addProperty("instruction", instruction == null ? "" : instruction.toString());
		object.addProperty("length", instruction == null ? bytes.length : instruction.getLength());
		return object;
	}

	protected JsonObject rangeSnapshot(Program program, Address start, Address end) {
		JsonObject object = new JsonObject();
		object.addProperty("start", start.toString());
		object.addProperty("end", end.toString());
		int length = (int) Math.min(end.subtract(start) + 1L, MAX_BYTES_IN_LOG);
		object.addProperty("captured_length", length);
		try {
			object.addProperty("bytes",
				toHex(new FlatProgramAPI(program, TaskMonitor.DUMMY).getBytes(start, length)));
		}
		catch (Exception e) {
			object.addProperty("bytes", "");
		}
		object.addProperty("instructions",
			program.getListing().getInstructions(new AddressSet(start, end), true).hasNext());
		object.addProperty("data",
			program.getListing().getDefinedData(new AddressSet(start, end), true).hasNext());
		return object;
	}

	protected byte[] instructionBytes(FlatProgramAPI flat, Instruction instruction) throws Exception {
		if (instruction == null) {
			return new byte[0];
		}
		return flat.getBytes(instruction.getAddress(), instruction.getLength());
	}
}
