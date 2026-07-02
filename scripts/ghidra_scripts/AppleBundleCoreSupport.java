import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.util.DefinedStringIterator;

abstract class AppleBundleCoreSupport extends GhidraScript {


	protected static final Pattern OBJC_METHOD_PATTERN = Pattern.compile("^([+-])\\[(.+?) (.+)\\]$");
	protected static final Pattern SWIFT_TYPE_PATTERN = Pattern.compile(
		"(?:type metadata accessor for |nominal type descriptor for |type metadata for )(.+)$");
	protected static final Pattern SWIFT_PROTOCOL_PATTERN = Pattern.compile(
		"(?:protocol conformance descriptor for |protocol witness for )(.+)$");
	protected static final Pattern SWIFT_PROPERTY_ENCODING_PATTERN = Pattern.compile(
		"T@\"([A-Za-z_][A-Za-z0-9_]*)\".*?,V_([A-Za-z_][A-Za-z0-9_]*)");
	protected static final Pattern OBJC_CLASS_LITERAL_PATTERN = Pattern.compile(
		"@\"([A-Za-z_][A-Za-z0-9_]*)\"");
	protected static final String[] SWIFT_METADATA_SECTION_NAMES = {
		"__swift5_types",
		"__swift5_typeref",
		"__swift5_fieldmd",
		"__swift5_capture",
		"__swift5_proto",
		"__swift5_reflstr",
		"__swift5_assocty"
	};
	protected static final String[] SWIFT_OBJC_RUNTIME_PREFIXES = {
		"_OBJC_CLASS_$_",
		"_OBJC_METACLASS_$_",
		"__INSTANCE_METHODS_",
		"__CLASS_METHODS_",
		"__PROPERTIES_",
		"__IVARS_",
		"__DATA_",
		"__METACLASS_DATA_"
	};

	protected final Gson gson = new GsonBuilder().disableHtmlEscaping().setPrettyPrinting().create();
	protected final Map<String, String> swiftDemangleCache = new HashMap<>();
	protected final Map<String, String> swiftBridgeTypeHints = new LinkedHashMap<>();
	protected final Set<String> swiftKnownTypeHints = new LinkedHashSet<>();
	protected String swiftDemangleTool = null;
	protected boolean swiftDemangleToolResolved = false;
	protected boolean swiftNameHintsResolved = false;

	protected Map<String, String> parseArgs() {
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

	protected String requireArg(Map<String, String> args, String key) {
		String value = args.get(key);
		if (value == null || value.isEmpty()) {
			throw new IllegalArgumentException("missing required argument: " + key + "=...");
		}
		return value;
	}

	protected void writeJson(File file, JsonElement payload) throws IOException {
		File parent = file.getParentFile();
		if (parent != null && !parent.exists() && !parent.mkdirs()) {
			throw new IOException("failed to create directory " + parent);
		}
		try (Writer writer =
			new OutputStreamWriter(new FileOutputStream(file), StandardCharsets.UTF_8)) {
			gson.toJson(payload, writer);
		}
	}

	protected JsonObject baseProgramMetadata() {
		JsonObject payload = new JsonObject();
		payload.addProperty("program_name", currentProgram.getName());
		payload.addProperty("executable_format", currentProgram.getExecutableFormat());
		payload.addProperty("language_id", String.valueOf(currentProgram.getLanguageID()));
		payload.addProperty("compiler_spec_id",
			String.valueOf(currentProgram.getCompilerSpec().getCompilerSpecID()));
		payload.addProperty("processor",
			String.valueOf(currentProgram.getLanguage().getProcessor()));
		payload.addProperty("pointer_size", currentProgram.getDefaultPointerSize());
		payload.addProperty("image_base", String.valueOf(currentProgram.getImageBase()));
		payload.addProperty("min_address", String.valueOf(currentProgram.getMinAddress()));
		payload.addProperty("max_address", String.valueOf(currentProgram.getMaxAddress()));
		payload.addProperty("executable_md5", empty(currentProgram.getExecutableMD5()));

		String executablePath = empty(currentProgram.getExecutablePath());
		payload.addProperty("executable_path", executablePath);
		payload.addProperty("source_image_path", inferSourceImagePath(executablePath));
		payload.addProperty("binary_sha256", sha256ForPath(executablePath));
		payload.addProperty("binary_size", fileSizeForPath(executablePath));
		payload.addProperty("binary_identity",
			currentProgram.getName() + "|" + currentProgram.getExecutableFormat() + "|" +
				empty(currentProgram.getExecutableMD5()) + "|" + sha256ForPath(executablePath));

		DomainFile domainFile = currentProgram.getDomainFile();
		payload.addProperty("program_path", domainFile == null ? "" : empty(domainFile.getPathname()));

		JsonObject metadata = new JsonObject();
		if (domainFile != null && domainFile.getMetadata() != null) {
			for (Map.Entry<String, String> entry : domainFile.getMetadata().entrySet()) {
				metadata.addProperty(entry.getKey(), entry.getValue());
			}
		}
		payload.add("metadata", metadata);

		JsonArray blocks = new JsonArray();
		for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
			JsonObject blockJson = new JsonObject();
			blockJson.addProperty("name", block.getName());
			blockJson.addProperty("start", String.valueOf(block.getStart()));
			blockJson.addProperty("end", String.valueOf(block.getEnd()));
			blockJson.addProperty("size", block.getSize());
			blockJson.addProperty("read", block.isRead());
			blockJson.addProperty("write", block.isWrite());
			blockJson.addProperty("execute", block.isExecute());
			blockJson.addProperty("volatile", block.isVolatile());
			blockJson.addProperty("initialized", block.isInitialized());
			blockJson.addProperty("source_name", empty(block.getSourceName()));
			blocks.add(blockJson);
		}
		payload.add("memory_blocks", blocks);
		return payload;
	}

	protected JsonObject buildProgramSummary() {
		JsonObject payload = baseProgramMetadata();
		int functionCount = currentProgram.getFunctionManager().getFunctionCount();
		int functionInventoryCount = countProgramFunctions();
		payload.addProperty("function_count", functionCount);
		payload.addProperty("function_inventory_count", functionInventoryCount);
		if (functionCount >= functionInventoryCount) {
			payload.addProperty("non_inventory_function_count",
				functionCount - functionInventoryCount);
		}
		int symbolCount = 0;
		int externalSymbolCount = 0;
		for (SymbolIterator iterator = currentProgram.getSymbolTable().getAllSymbols(true); iterator
				.hasNext();) {
			Symbol symbol = iterator.next();
			symbolCount++;
			if (symbol.isExternal()) {
				externalSymbolCount++;
			}
		}
		payload.addProperty("symbol_count", symbolCount);
		payload.addProperty("external_symbol_count", externalSymbolCount);
		return payload;
	}

	protected JsonObject sampleReferences(Address address, int limit) {
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
			Function function = getFunctionContaining(ref.getFromAddress());
			refJson.addProperty("from_function", function == null ? null : function.getName());
			refJson.addProperty("ref_type", String.valueOf(ref.getReferenceType()));
			refJson.addProperty("operand_index", ref.getOperandIndex());
			refJson.addProperty("is_primary", ref.isPrimary());
			refs.add(refJson);
		}
		payload.addProperty("count", count);
		payload.add("items", refs);
		return payload;
	}

	protected Function findFunctionForAddress(String addressValue) {
		if (addressValue == null || addressValue.isEmpty()) {
			return null;
		}
		try {
			Address address = toAddr(addressValue);
			if (address == null) {
				return null;
			}
			Function at = currentProgram.getFunctionManager().getFunctionAt(address);
			if (at != null) {
				return at;
			}
			return getFunctionContaining(address);
		}
		catch (Exception ignored) {
			return null;
		}
	}

	protected Function resolveCanonicalFunction(Function function) {
		if (function == null) {
			return null;
		}
		Set<String> seen = new LinkedHashSet<>();
		Function current = function;
		for (int depth = 0; depth < 8 && current != null; depth++) {
			String entry = String.valueOf(current.getEntryPoint());
			if (!seen.add(entry)) {
				break;
			}
			Function next = null;
			if (current.isThunk()) {
				next = current.getThunkedFunction(true);
			}
			if (next == null && current.getBody().getNumAddresses() <= 16) {
				Set<Function> called = current.getCalledFunctions(monitor);
				if (called.size() == 1) {
					next = called.iterator().next();
				}
			}
			if (next == null) {
				break;
			}
			current = next;
		}
		return current == null ? function : current;
	}

	protected JsonArray buildImplementationChain(Function function) {
		JsonArray chain = new JsonArray();
		if (function == null) {
			return chain;
		}
		Set<String> seen = new LinkedHashSet<>();
		Function current = function;
		for (int depth = 0; depth < 8 && current != null; depth++) {
			String entry = String.valueOf(current.getEntryPoint());
			if (!seen.add(entry)) {
				break;
			}
			JsonObject step = new JsonObject();
			step.addProperty("address", entry);
			step.addProperty("name", current.getName());
			step.addProperty("is_thunk", current.isThunk());
			step.addProperty("body_size", current.getBody().getNumAddresses());
			chain.add(step);
			Function next = null;
			if (current.isThunk()) {
				next = current.getThunkedFunction(true);
			}
			if (next == null && current.getBody().getNumAddresses() <= 16) {
				Set<Function> called = current.getCalledFunctions(monitor);
				if (called.size() == 1) {
					next = called.iterator().next();
				}
			}
			if (next == null) {
				break;
			}
			current = next;
		}
		return chain;
	}

	protected JsonArray toJsonArray(Set<String> values) {
		JsonArray array = new JsonArray();
		for (String value : values) {
			array.add(value);
		}
		return array;
	}

	protected int countProgramFunctions() {
		int count = 0;
		for (FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true); iterator
				.hasNext();) {
			iterator.next();
			count++;
		}
		return count;
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

	protected String empty(String value) {
		return value == null ? "" : value;
	}

	protected String inferSourceImagePath(String executablePath) {
		if (executablePath == null || executablePath.isEmpty()) {
			return "";
		}
		if (executablePath.contains("/System/iOSSupport/")) {
			return executablePath.substring(executablePath.indexOf("/System/iOSSupport/") + 8);
		}
		int systemIndex = executablePath.indexOf("/System/");
		if (systemIndex >= 0) {
			return executablePath.substring(systemIndex);
		}
		return executablePath;
	}

	protected long fileSizeForPath(String pathValue) {
		if (pathValue == null || pathValue.isEmpty()) {
			return 0L;
		}
		try {
			return Files.size(new File(pathValue).toPath());
		}
		catch (Exception ignored) {
			return 0L;
		}
	}

	protected String sha256ForPath(String pathValue) {
		if (pathValue == null || pathValue.isEmpty()) {
			return "";
		}
		File file = new File(pathValue);
		if (!file.isFile()) {
			return "";
		}
		try (FileInputStream input = new FileInputStream(file)) {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] buffer = new byte[8192];
			int read;
			while ((read = input.read(buffer)) >= 0) {
				if (read == 0) {
					continue;
				}
				digest.update(buffer, 0, read);
			}
			StringBuilder builder = new StringBuilder();
			for (byte value : digest.digest()) {
				builder.append(String.format("%02x", value));
			}
			return builder.toString();
		}
		catch (Exception ignored) {
			return "";
		}
	}

	protected String sha256ForString(String value) {
		if (value == null) {
			value = "";
		}
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
			digest.update(bytes, 0, bytes.length);
			StringBuilder builder = new StringBuilder();
			for (byte item : digest.digest()) {
				builder.append(String.format("%02x", item));
			}
			return builder.toString();
		}
		catch (Exception ignored) {
			return "";
		}
	}

}
