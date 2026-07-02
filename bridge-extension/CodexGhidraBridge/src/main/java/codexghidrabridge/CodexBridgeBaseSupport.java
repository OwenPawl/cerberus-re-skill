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


abstract class CodexBridgeBaseSupport {

	protected static final Gson GSON =
		new GsonBuilder().disableHtmlEscaping().setPrettyPrinting().create();
	protected static final int MAX_BYTES_IN_LOG = 4096;
	protected static final int MAX_RESULTS = 50;

	protected final CodexBridgePlugin plugin;
	protected final CodexBridgeProvider provider;
	protected boolean armed;
	protected final String sessionId;
	protected String bridgeUrl = "";
	protected String token = "";
	protected String startedAt = "";
	protected long lastHeartbeatMillis = 0L;

	CodexBridgeBaseSupport(CodexBridgePlugin plugin, CodexBridgeProvider provider) {
		this.plugin = plugin;
		this.provider = provider;
		this.sessionId = UUID.randomUUID().toString();
	}

	void log(String message) {
		provider.appendLog(DateTimeFormatter.ISO_INSTANT.format(Instant.now()) + " " + message);
		Msg.info(plugin, "CodexBridge " + message);
	}

	RepositoryState repositoryStateFor(Program program) {
		RepositoryState state = new RepositoryState();
		if (program == null) {
			return state;
		}
		state.programName = program.getName();
		DomainFile domainFile = program.getDomainFile();
		if (domainFile == null) {
			return state;
		}
		state.hasProgram = true;
		state.domainPath = domainFile.getPathname();
		state.versioned = domainFile.isVersioned();
		state.readOnly = domainFile.isReadOnly();
		state.checkedOut = domainFile.isCheckedOut();
		state.exclusiveCheckout = domainFile.isCheckedOutExclusive();
		state.modifiedSinceCheckout = domainFile.modifiedSinceCheckout();
		state.writableProject = domainFile.isInWritableProject();
		state.changed = domainFile.isChanged();
		state.canSave = domainFile.canSave();
		ProjectLocator locator = domainFile.getProjectLocator();
		if (locator != null) {
			state.projectLocation = locator.getLocation();
			state.projectName = locator.getName();
			File marker = locator.getMarkerFile();
			state.projectMarkerPath = marker == null ? "" : marker.getAbsolutePath();
		}
		return state;
	}

	String describeRepository(RepositoryState state) {
		if (state == null || !state.hasProgram) {
			return "no active program";
		}
		List<String> bits = new ArrayList<>();
		if (state.versioned) {
			bits.add(state.checkedOut ? "versioned+checked-out" : "versioned+read-only");
		}
		else {
			bits.add(state.readOnly ? "read-only" : "local-writable");
		}
		if (state.modifiedSinceCheckout) {
			bits.add("modified");
		}
		if (state.exclusiveCheckout) {
			bits.add("exclusive");
		}
		return String.join(", ", bits);
	}

	protected void updateSessionIfArmed() {
		if (!armed) {
			return;
		}
		try {
			writeSessionFile();
		}
		catch (IOException e) {
			log("session update failed: " + e.getMessage());
		}
	}

	protected abstract void writeSessionFile() throws IOException;

	protected String programPath(Program program) {
		if (program == null || program.getDomainFile() == null) {
			return "";
		}
		return program.getDomainFile().getPathname();
	}

	protected String variableKind(Variable variable) {
		if (variable == null) {
			return "";
		}
		if (variable instanceof Parameter) {
			Parameter parameter = (Parameter) variable;
			if (parameter.getOrdinal() < 0 || variable.getName().equals("RETURN")) {
				return "return";
			}
			return "parameter";
		}
		return "local";
	}

	protected String pathName(DataType dataType) {
		return dataType == null ? "" : dataType.getPathName();
	}

	protected String empty(String value) {
		return value == null ? "" : value;
	}

	protected String defaultCategory(String categoryPath) {
		return categoryPath == null || categoryPath.isEmpty() ? "/" : categoryPath;
	}

	protected String toHex(byte[] bytes) {
		if (bytes == null) {
			return "";
		}
		StringBuilder builder = new StringBuilder(bytes.length * 2);
		for (byte value : bytes) {
			builder.append(String.format("%02x", value));
		}
		return builder.toString();
	}

	protected byte[] parseHexBytes(String text) {
		String normalized = text.replace("0x", "").replaceAll("[^0-9A-Fa-f]", "");
		if (normalized.isEmpty()) {
			return new byte[0];
		}
		if ((normalized.length() % 2) != 0) {
			normalized = "0" + normalized;
		}
		byte[] output = new byte[normalized.length() / 2];
		for (int i = 0; i < output.length; i++) {
			int offset = i * 2;
			output[i] = (byte) Integer.parseInt(normalized.substring(offset, offset + 2), 16);
		}
		return output;
	}

	protected String slug(String value) {
		return value.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]+", "-");
	}

	protected String optString(JsonObject object, String... keys) {
		for (String key : keys) {
			if (object.has(key) && object.get(key).isJsonPrimitive()) {
				return object.get(key).getAsString();
			}
		}
		return "";
	}

	protected int optInt(JsonObject object, String key, int defaultValue) {
		if (!object.has(key)) {
			return defaultValue;
		}
		try {
			return object.get(key).getAsInt();
		}
		catch (Exception ignored) {
			return defaultValue;
		}
	}

	protected boolean optBoolean(JsonObject object, String key, boolean defaultValue) {
		if (!object.has(key)) {
			return defaultValue;
		}
		try {
			return object.get(key).getAsBoolean();
		}
		catch (Exception ignored) {
			return defaultValue;
		}
	}

	protected JsonObject optObject(JsonObject object, String key) {
		if (!object.has(key) || !object.get(key).isJsonObject()) {
			return null;
		}
		return object.getAsJsonObject(key);
	}

	protected JsonArray optArray(JsonObject object, String... keys) {
		for (String key : keys) {
			if (object.has(key) && object.get(key).isJsonArray()) {
				return object.getAsJsonArray(key);
			}
		}
		return null;
	}

	protected boolean hasAny(JsonObject object, String... keys) {
		for (String key : keys) {
			if (object.has(key)) {
				return true;
			}
		}
		return false;
	}

	@FunctionalInterface
	protected interface MutationAction {
		MutationResult apply(Program program, FlatProgramAPI flat) throws Exception;
	}

	protected static class MutationResult {
		JsonObject before = new JsonObject();
		JsonObject result = new JsonObject();
		JsonArray targets = new JsonArray();
		JsonObject inverse = new JsonObject();
	}

	static class RepositoryState {
		boolean hasProgram;
		boolean versioned;
		boolean readOnly;
		boolean checkedOut;
		boolean exclusiveCheckout;
		boolean modifiedSinceCheckout;
		boolean writableProject;
		boolean canSave;
		boolean changed;
		String programName = "";
		String projectName = "";
		String projectLocation = "";
		String projectMarkerPath = "";
		String domainPath = "";
	}

	protected static class FunctionSearchHit {
		final Function function;
		final String matchField;
		final String matchValue;
		final String matchKind;
		final int rank;

		FunctionSearchHit(Function function, String matchField, String matchValue,
				String matchKind, int rank) {
			this.function = function;
			this.matchField = matchField;
			this.matchValue = matchValue;
			this.matchKind = matchKind;
			this.rank = rank;
		}
	}

	protected static class BridgeException extends Exception {
		final int statusCode;

		BridgeException(int statusCode, String message) {
			super(message);
			this.statusCode = statusCode;
		}
	}
}
