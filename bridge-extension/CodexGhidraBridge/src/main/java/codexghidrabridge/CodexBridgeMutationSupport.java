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


abstract class CodexBridgeMutationSupport extends CodexBridgeResolveSupport {

	CodexBridgeMutationSupport(CodexBridgePlugin plugin, CodexBridgeProvider provider) {
		super(plugin, provider);
	}

	protected JsonElement handleEditRename(JsonObject body) throws Exception {
		return executeMutation("edit-rename", body, false, (program, flat) -> {
			String newName = optString(body, "rename", "new_name", "name");
			if (newName.isEmpty()) {
				throw new BridgeException(400, "missing rename/new_name");
			}
			MutationResult mutation = new MutationResult();
			Variable variable = resolveVariable(program, body, true);
			if (variable != null) {
				mutation.before = variableToJson(variable);
				variable.setName(newName, SourceType.USER_DEFINED);
				mutation.result = variableToJson(variable);
				mutation.targets.add(variableRef(variable));
				return mutation;
			}
			Function function = resolveFunction(program, body, true);
			if (function != null) {
				mutation.before = functionToJson(function, false);
				function.setName(newName, SourceType.USER_DEFINED);
				mutation.result = functionToJson(function, false);
				mutation.targets.add(functionRef(function));
				return mutation;
			}
			Address address = resolveAddress(program, body, false);
			Symbol symbol = program.getSymbolTable().getPrimarySymbol(address);
			if (symbol == null) {
				throw new BridgeException(404, "no symbol at " + address);
			}
			mutation.before = symbolToJson(program, symbol, 10);
			symbol.setName(newName, SourceType.USER_DEFINED);
			mutation.result = symbolToJson(program, symbol, 10);
			mutation.targets.add(locationRef(program, address));
			return mutation;
		});
	}

	protected JsonElement handleEditComment(JsonObject body) throws Exception {
		return executeMutation("edit-comment", body, false, (program, flat) -> {
			String comment = optString(body, "comment", "text");
			if (comment.isEmpty()) {
				throw new BridgeException(400, "missing comment");
			}
			Address address = resolveAddress(program, body, false);
			String type = optString(body, "comment_type", "type");
			if (type.isEmpty()) {
				type = "plate";
			}
			MutationResult mutation = new MutationResult();
			mutation.before = commentSnapshot(program, address);
			switch (type.toLowerCase(Locale.ROOT)) {
				case "plate":
					flat.setPlateComment(address, comment);
					break;
				case "pre":
					flat.setPreComment(address, comment);
					break;
				case "post":
					flat.setPostComment(address, comment);
					break;
				case "eol":
					flat.setEOLComment(address, comment);
					break;
				case "repeatable":
					flat.setRepeatableComment(address, comment);
					break;
				case "function":
					Function function = resolveFunction(program, body);
					function.setComment(comment);
					function.setRepeatableComment(comment);
					mutation.targets.add(functionRef(function));
					break;
				default:
					throw new BridgeException(400, "unsupported comment_type: " + type);
			}
			if (mutation.targets.size() == 0) {
				mutation.targets.add(locationRef(program, address));
			}
			mutation.result = commentSnapshot(program, address);
			return mutation;
		});
	}

	protected JsonElement handleEditBookmark(JsonObject body) throws Exception {
		return executeMutation("edit-bookmark", body, false, (program, flat) -> {
			Address address = resolveAddress(program, body, false);
			String category = optString(body, "bookmark_category", "category");
			String comment = optString(body, "message", "comment", "title");
			if (category.isEmpty()) {
				category = "codex";
			}
			MutationResult mutation = new MutationResult();
			mutation.before = bookmarksToJson(flat.getBookmarks(address));
			flat.createBookmark(address, category, comment);
			mutation.result = bookmarksToJson(flat.getBookmarks(address));
			mutation.targets.add(locationRef(program, address));
			return mutation;
		});
	}

	protected JsonElement handleEditFunctionSignature(JsonObject body) throws Exception {
		return executeMutation("edit-function-signature", body, false, (program, flat) -> {
			Function function = resolveFunction(program, body);
			MutationResult mutation = new MutationResult();
			mutation.before = functionToJson(function, true);

			String rename = optString(body, "rename", "new_name");
			if (!rename.isEmpty()) {
				function.setName(rename, SourceType.USER_DEFINED);
			}

			String returnTypeName = optString(body, "return_type");
			if (!returnTypeName.isEmpty()) {
				DataType returnType = resolveDataType(program, returnTypeName, true);
				function.setReturnType(returnType, SourceType.USER_DEFINED);
			}

			String callingConvention = optString(body, "calling_convention");
			if (!callingConvention.isEmpty()) {
				function.setCallingConvention(callingConvention);
			}

			if (hasAny(body, "inline", "is_inline")) {
				boolean inline = optBoolean(body, "inline",
					optBoolean(body, "is_inline", function.isInline()));
				function.setInline(inline);
			}

			if (hasAny(body, "no_return")) {
				function.setNoReturn(optBoolean(body, "no_return", function.hasNoReturn()));
			}

			if (hasAny(body, "has_var_args", "var_args")) {
				boolean hasVarArgs = optBoolean(body, "has_var_args",
					optBoolean(body, "var_args", function.hasVarArgs()));
				function.setVarArgs(hasVarArgs);
			}

			JsonArray params = optArray(body, "params", "parameters");
			if (params != null) {
				List<Variable> replacement = new ArrayList<>();
				for (JsonElement element : params) {
					JsonObject paramObject = element.getAsJsonObject();
					String paramName = optString(paramObject, "name");
					if (paramName.isEmpty()) {
						paramName = "param_" + replacement.size();
					}
					String typeName = optString(paramObject, "type", "datatype");
					DataType dataType = resolveDataType(program, typeName, true);
					ParameterImpl parameter =
						new ParameterImpl(paramName, dataType, program, SourceType.USER_DEFINED);
					String comment = optString(paramObject, "comment");
					if (!comment.isEmpty()) {
						parameter.setComment(comment);
					}
					replacement.add(parameter);
				}
				function.replaceParameters(replacement, FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
					true, SourceType.USER_DEFINED);
			}

			mutation.result = functionToJson(function, true);
			mutation.targets.add(functionRef(function));
			return mutation;
		});
	}

	protected JsonElement handleEditVariable(JsonObject body) throws Exception {
		return executeMutation("edit-variable", body, false, (program, flat) -> {
			Variable variable = resolveVariable(program, body, false);
			MutationResult mutation = new MutationResult();
			mutation.before = variableToJson(variable);
			String rename = optString(body, "rename", "new_name");
			if (!rename.isEmpty()) {
				variable.setName(rename, SourceType.USER_DEFINED);
			}
			String comment = optString(body, "comment");
			if (!comment.isEmpty()) {
				variable.setComment(comment);
			}
			String typeName = optString(body, "type", "datatype");
			if (!typeName.isEmpty()) {
				DataType dataType = resolveDataType(program, typeName, true);
				variable.setDataType(dataType, SourceType.USER_DEFINED);
			}
			mutation.result = variableToJson(variable);
			mutation.targets.add(variableRef(variable));
			return mutation;
		});
	}

	protected JsonElement handleEditDatatype(JsonObject body) throws Exception {
		return executeMutation("edit-datatype", body, false, (program, flat) -> {
			MutationResult mutation = new MutationResult();
			String action = optString(body, "action");
			if (action.isEmpty()) {
				action = "rename";
			}
			DataTypeManager manager = program.getDataTypeManager();
			switch (action) {
				case "create_struct":
					mutation.result = dataTypeToJson(createStruct(manager, body, program));
					break;
				case "create_enum":
					mutation.result = dataTypeToJson(createEnum(manager, body, program));
					break;
				case "create_typedef":
					mutation.result = dataTypeToJson(createTypedef(manager, body, program));
					break;
				case "rename":
				case "update_struct":
				case "update_enum":
					DataType dataType = resolveDataType(program, body, false);
					mutation.before = dataTypeToJson(dataType);
					updateDatatype(dataType, body, program);
					mutation.result = dataTypeToJson(dataType);
					break;
				default:
					throw new BridgeException(400, "unsupported datatype action: " + action);
			}
			mutation.targets.add(mutation.result.deepCopy());
			return mutation;
		});
	}

	protected JsonElement handlePatchBytes(JsonObject body) throws Exception {
		return executeMutation("patch-bytes", body, true, (program, flat) -> {
			Address address = resolveAddress(program, body, false);
			byte[] newBytes = parseHexBytes(optString(body, "bytes", "hex"));
			if (newBytes.length == 0) {
				throw new BridgeException(400, "missing bytes/hex");
			}
			byte[] beforeBytes = flat.getBytes(address, newBytes.length);
			MutationResult mutation = new MutationResult();
			mutation.before = bytePatchSnapshot(program, address, beforeBytes);
			flat.setBytes(address, newBytes);
			mutation.result = bytePatchSnapshot(program, address, flat.getBytes(address, newBytes.length));
			mutation.targets.add(locationRef(program, address));
			mutation.inverse.addProperty("kind", "patch-bytes");
			mutation.inverse.addProperty("address", address.toString());
			mutation.inverse.addProperty("bytes", toHex(beforeBytes));
			return mutation;
		});
	}

	protected JsonElement handlePatchInstruction(JsonObject body) throws Exception {
		return executeMutation("patch-instruction", body, true, (program, flat) -> {
			Address address = resolveAddress(program, body, false);
			String assembly = optString(body, "assembly", "instruction");
			if (assembly.isEmpty()) {
				throw new BridgeException(400, "missing assembly");
			}
			Instruction before = flat.getInstructionAt(address);
			byte[] beforeBytes = instructionBytes(flat, before);
			Assembler assembler = Assemblers.getAssembler(program);
			assembler.assemble(address, assembly);
			Instruction after = flat.getInstructionAt(address);
			MutationResult mutation = new MutationResult();
			mutation.before = instructionSnapshot(program, before, address, beforeBytes);
			mutation.result = instructionSnapshot(program, after, address, instructionBytes(flat, after));
			mutation.targets.add(locationRef(program, address));
			mutation.inverse.addProperty("kind", "patch-bytes");
			mutation.inverse.addProperty("address", address.toString());
			mutation.inverse.addProperty("bytes", toHex(beforeBytes));
			return mutation;
		});
	}

	protected JsonElement handleListingClear(JsonObject body) throws Exception {
		return executeMutation("listing-clear", body, true, (program, flat) -> {
			Address start = resolveAddress(program, body, false);
			Address end = resolveEndAddress(program, body, start);
			String mode = optString(body, "mode");
			if (mode.isEmpty()) {
				mode = "all";
			}
			MutationResult mutation = new MutationResult();
			mutation.before = rangeSnapshot(program, start, end);
			Listing listing = program.getListing();
			if ("all".equalsIgnoreCase(mode)) {
				listing.clearCodeUnits(start, end, false);
			}
			else if ("code".equalsIgnoreCase(mode)) {
				InstructionIterator iterator =
					listing.getInstructions(new AddressSet(start, end), true);
				List<Address> addresses = new ArrayList<>();
				while (iterator.hasNext()) {
					addresses.add(iterator.next().getAddress());
				}
				for (Address address : addresses) {
					flat.removeInstructionAt(address);
				}
			}
			else if ("data".equalsIgnoreCase(mode)) {
				DataIterator iterator = listing.getDefinedData(new AddressSet(start, end), true);
				List<Address> addresses = new ArrayList<>();
				while (iterator.hasNext()) {
					addresses.add(iterator.next().getAddress());
				}
				for (Address address : addresses) {
					flat.removeDataAt(address);
				}
			}
			else {
				throw new BridgeException(400, "unsupported clear mode: " + mode);
			}
			mutation.result = rangeSnapshot(program, start, end);
			mutation.targets.add(locationRef(program, start));
			mutation.inverse.addProperty("kind", "range-snapshot");
			mutation.inverse.add("snapshot", mutation.before.deepCopy());
			return mutation;
		});
	}

	protected JsonElement handleListingDisassemble(JsonObject body) throws Exception {
		return executeMutation("listing-disassemble", body, true, (program, flat) -> {
			Address start = resolveAddress(program, body, false);
			Address end = resolveEndAddress(program, body, start);
			AddressSet set = new AddressSet(start, end);
			MutationResult mutation = new MutationResult();
			mutation.before = rangeSnapshot(program, start, end);
			DisassembleCommand command = new DisassembleCommand(start, set, true);
			if (!command.applyTo(program, TaskMonitor.DUMMY)) {
				throw new BridgeException(500, "disassemble failed: " + command.getStatusMsg());
			}
			mutation.result = rangeSnapshot(program, start, end);
			mutation.targets.add(locationRef(program, start));
			mutation.inverse.addProperty("kind", "range-snapshot");
			mutation.inverse.add("snapshot", mutation.before.deepCopy());
			return mutation;
		});
	}

	protected JsonElement handleFunctionCreate(JsonObject body) throws Exception {
		return executeMutation("function-create", body, true, (program, flat) -> {
			Address entry = resolveAddress(program, body, false);
			String name = optString(body, "name");
			Address bodyEnd = hasAny(body, "end", "body_end", "length") ? resolveEndAddress(program, body, entry) :
				null;
			MutationResult mutation = new MutationResult();
			mutation.before = rangeSnapshot(program, entry, bodyEnd == null ? entry : bodyEnd);
			Function function;
			if (bodyEnd != null && !entry.equals(bodyEnd)) {
				function = program.getListing().createFunction(name, entry, new AddressSet(entry, bodyEnd),
					SourceType.USER_DEFINED);
			}
			else {
				CreateFunctionCmd command = new CreateFunctionCmd(entry);
				if (!command.applyTo(program, TaskMonitor.DUMMY)) {
					throw new BridgeException(500, "create function failed");
				}
				function = command.getFunction();
				if (function != null && !name.isEmpty()) {
					function.setName(name, SourceType.USER_DEFINED);
				}
			}
			if (function == null) {
				throw new BridgeException(500, "function creation did not return a function");
			}
			mutation.result = functionToJson(function, true);
			mutation.targets.add(functionRef(function));
			mutation.inverse.addProperty("kind", "function-delete");
			mutation.inverse.addProperty("entry", function.getEntryPoint().toString());
			return mutation;
		});
	}

	protected JsonElement handleFunctionDelete(JsonObject body) throws Exception {
		return executeMutation("function-delete", body, true, (program, flat) -> {
			Function function = resolveFunction(program, body);
			MutationResult mutation = new MutationResult();
			mutation.before = functionToJson(function, true);
			mutation.targets.add(functionRef(function));
			mutation.inverse.addProperty("kind", "function-create");
			mutation.inverse.addProperty("entry", function.getEntryPoint().toString());
			mutation.inverse.addProperty("name", function.getName());
			mutation.inverse.add("body", addressSetToJson(function.getBody(), 32));
			flat.removeFunction(function);
			mutation.result = new JsonObject();
			mutation.result.addProperty("deleted", true);
			return mutation;
		});
	}

	protected JsonElement handleFunctionFixup(JsonObject body) throws Exception {
		return executeMutation("function-fixup", body, true, (program, flat) -> {
			Function function = resolveFunction(program, body);
			MutationResult mutation = new MutationResult();
			mutation.before = functionToJson(function, true);
			boolean fixed = CreateFunctionCmd.fixupFunctionBody(program, function, TaskMonitor.DUMMY);
			if (!fixed) {
				throw new BridgeException(500, "function fixup failed");
			}
			mutation.result = functionToJson(function, true);
			mutation.targets.add(functionRef(function));
			mutation.inverse.addProperty("kind", "range-snapshot");
			mutation.inverse.add("snapshot", mutation.before.deepCopy());
			return mutation;
		});
	}

	protected JsonElement handleDataCreate(JsonObject body) throws Exception {
		return executeMutation("data-create", body, true, (program, flat) -> {
			Address address = resolveAddress(program, body, false);
			DataType dataType = resolveDataType(program, body, true);
			int length = Math.max(dataType.getLength(), 1);
			Address end = address.add(length - 1L);
			MutationResult mutation = new MutationResult();
			mutation.before = rangeSnapshot(program, address, end);
			program.getListing().clearCodeUnits(address, end, false);
			Data data = flat.createData(address, dataType);
			mutation.result = dataToJson(program, data, 10);
			mutation.targets.add(locationRef(program, address));
			mutation.inverse.addProperty("kind", "data-delete");
			mutation.inverse.addProperty("address", address.toString());
			return mutation;
		});
	}

	protected JsonElement handleDataDelete(JsonObject body) throws Exception {
		return executeMutation("data-delete", body, true, (program, flat) -> {
			Address start = resolveAddress(program, body, false);
			Address end = resolveEndAddress(program, body, start);
			Listing listing = program.getListing();
			MutationResult mutation = new MutationResult();
			mutation.before = rangeSnapshot(program, start, end);
			DataIterator iterator = listing.getDefinedData(new AddressSet(start, end), true);
			List<Address> addresses = new ArrayList<>();
			while (iterator.hasNext()) {
				addresses.add(iterator.next().getAddress());
			}
			for (Address address : addresses) {
				flat.removeDataAt(address);
			}
			mutation.result = rangeSnapshot(program, start, end);
			mutation.targets.add(locationRef(program, start));
			mutation.inverse.addProperty("kind", "range-snapshot");
			mutation.inverse.add("snapshot", mutation.before.deepCopy());
			return mutation;
		});
	}

	protected JsonElement executeMutation(String opName, JsonObject body, boolean destructive,
			MutationAction action) throws Exception {
		Program program = requireProgram();
		requireWriteFlags(body, destructive);
		ensureWritable(program);

		FlatProgramAPI flat = new FlatProgramAPI(program, TaskMonitor.DUMMY);
		int tx = program.startTransaction("CodexBridge:" + opName);
		boolean commit = false;
		MutationResult mutation = null;
		try {
			mutation = action.apply(program, flat);
			commit = true;
		}
		finally {
			program.endTransaction(tx, commit);
		}
		plugin.incrementState(opName);
		updateSessionIfArmed();
		if (destructive && mutation != null) {
			writeOperationLog(opName, body, mutation);
		}
		return mutation == null ? JsonNull.INSTANCE : mutation.result;
	}

	protected void writeOperationLog(String opName, JsonObject request, MutationResult mutation) {
		try {
			Program program = plugin.getCurrentProgram();
			RepositoryState repository = repositoryStateFor(program);
			String projectName = repository.projectName.isEmpty() ? "unknown-project" : repository.projectName;
			File logDir =
				new File(new File(new File(System.getProperty("user.home"), "ghidra-projects"), "logs"),
					projectName + "/bridge-ops");
			if (!logDir.exists()) {
				logDir.mkdirs();
			}
			File output =
				new File(logDir, DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss").withZone(java.time.ZoneId.systemDefault()).format(Instant.now()) +
					"-" + slug(opName) + ".json");
			JsonObject payload = new JsonObject();
			payload.addProperty("operation_kind", opName);
			payload.add("request_body", request.deepCopy());
			payload.add("before_state", mutation.before == null ? JsonNull.INSTANCE : mutation.before.deepCopy());
			payload.add("after_state_summary",
				mutation.result == null ? JsonNull.INSTANCE : mutation.result.deepCopy());
			payload.add("target_refs", mutation.targets.deepCopy());
			payload.add("inverse", mutation.inverse.deepCopy());
			payload.addProperty("tool_name", plugin.getTool().getToolName());
			payload.addProperty("program_path", repository.domainPath);
			payload.addProperty("project_path", repository.projectMarkerPath);
			payload.addProperty("pid", ProcessHandle.current().pid());
			payload.addProperty("created_at", DateTimeFormatter.ISO_INSTANT.format(Instant.now()));
			payload.add("repository", repositoryToJson(repository));
			writeJson(output, payload);
		}
		catch (Exception e) {
			log("operation log failure: " + e.getMessage());
		}
	}
}
