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

abstract class AppleBundleInventorySupport extends AppleBundleSwiftDescriptorSupport {

	protected JsonObject buildFunctionInventory() {
		JsonObject payload = new JsonObject();
		payload.addProperty("program_name", currentProgram.getName());
		payload.addProperty("scope", "program_functions");
		payload.addProperty("includes_external_functions", false);
		JsonArray functions = new JsonArray();
		for (FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true); iterator
				.hasNext();) {
			if (monitor.isCancelled()) {
				break;
			}
			functions.add(functionToJson(iterator.next()));
		}
		payload.addProperty("function_count", functions.size());
		payload.add("functions", functions);
		return payload;
	}

	protected JsonObject buildFunctionFingerprints() {
		JsonObject payload = new JsonObject();
		payload.addProperty("program_name", currentProgram.getName());
		payload.addProperty("scope", "program_functions");
		payload.addProperty("algorithm", "mnemonic_sequence_sha256");
		payload.addProperty("includes_external_functions", false);
		JsonArray functions = new JsonArray();
		for (FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true); iterator
				.hasNext();) {
			if (monitor.isCancelled()) {
				break;
			}
			Function function = iterator.next();
			if (!function.isExternal()) {
				functions.add(functionFingerprintToJson(function));
			}
		}
		payload.addProperty("function_count", functions.size());
		payload.add("functions", functions);
		return payload;
	}

	protected JsonObject functionFingerprintToJson(Function function) {
		JsonObject object = new JsonObject();
		object.addProperty("name", function.getName());
		object.addProperty("entry", String.valueOf(function.getEntryPoint()));
		object.addProperty("body_size", function.getBody().getNumAddresses());
		object.addProperty("artifact_type", classifyFunctionArtifact(function));

		JsonArray mnemonics = new JsonArray();
		List<String> sequence = new ArrayList<>();
		InstructionIterator iterator =
			currentProgram.getListing().getInstructions(function.getBody(), true);
		while (iterator.hasNext() && !monitor.isCancelled()) {
			Instruction instruction = iterator.next();
			String mnemonic = instruction.getMnemonicString().toLowerCase(Locale.ROOT);
			sequence.add(mnemonic);
			mnemonics.add(mnemonic);
		}
		String sequenceText = String.join(" ", sequence);
		object.addProperty("mnemonic_count", sequence.size());
		object.addProperty("mnemonic_sha256", sha256ForString(sequenceText));
		object.add("mnemonics", mnemonics);
		return object;
	}

	protected JsonObject functionToJson(Function function) {
		JsonObject object = new JsonObject();
		object.addProperty("name", function.getName());
		object.addProperty("entry", String.valueOf(function.getEntryPoint()));
		object.addProperty("namespace", namespacePath(function.getParentNamespace()));
		object.addProperty("signature", function.getPrototypeString(false, false));
		object.addProperty("return_type", String.valueOf(function.getReturnType()));
		object.addProperty("calling_convention", function.getCallingConventionName());
		object.addProperty("is_thunk", function.isThunk());
		object.addProperty("is_external", function.isExternal());
		object.addProperty("is_inline", function.isInline());
		object.addProperty("has_var_args", function.hasVarArgs());
		object.addProperty("no_return", function.hasNoReturn());
		object.addProperty("body_size", function.getBody().getNumAddresses());
		object.addProperty("caller_count", function.getCallingFunctions(monitor).size());
		object.addProperty("callee_count", function.getCalledFunctions(monitor).size());
		object.addProperty("artifact_type", classifyFunctionArtifact(function));
		MemoryBlock block = currentProgram.getMemory().getBlock(function.getEntryPoint());
		object.addProperty("block", block == null ? "" : empty(block.getName()));
		JsonObject refs = sampleReferences(function.getEntryPoint(), 8);
		object.addProperty("xref_count", refs.get("count").getAsInt());
		object.add("sample_xrefs", refs.getAsJsonArray("items"));
		JsonArray params = new JsonArray();
		for (Parameter parameter : function.getParameters()) {
			JsonObject param = new JsonObject();
			param.addProperty("name", parameter.getName());
			param.addProperty("data_type", String.valueOf(parameter.getDataType()));
			param.addProperty("storage", String.valueOf(parameter.getVariableStorage()));
			param.addProperty("source", String.valueOf(parameter.getSource()));
			params.add(param);
		}
		object.addProperty("parameter_count", params.size());
		object.add("parameters", params);
		Matcher matcher = OBJC_METHOD_PATTERN.matcher(function.getName());
		if (matcher.matches()) {
			JsonObject objcMethod = new JsonObject();
			objcMethod.addProperty("kind", "+".equals(matcher.group(1)) ? "class" : "instance");
			objcMethod.addProperty("class_name", matcher.group(2));
			objcMethod.addProperty("selector", matcher.group(3));
			object.add("objc_method", objcMethod);
		}
		if (isSwiftSymbol(function.getName())) {
			object.addProperty("swift_symbol", true);
		}
		return object;
	}

	protected JsonObject buildSymbols() {
		JsonObject payload = new JsonObject();
		payload.addProperty("program_name", currentProgram.getName());
		JsonArray symbols = new JsonArray();
		JsonArray imports = new JsonArray();
		JsonArray exports = new JsonArray();
		JsonArray objcRelated = new JsonArray();
		JsonArray swiftRelated = new JsonArray();

		for (SymbolIterator iterator = currentProgram.getSymbolTable().getAllSymbols(true); iterator
				.hasNext();) {
			if (monitor.isCancelled()) {
				break;
			}
			Symbol symbol = iterator.next();
			boolean keep = symbol.isExternal() || symbol.isExternalEntryPoint()
				|| !"DEFAULT".equals(String.valueOf(symbol.getSource()));
			JsonObject symbolJson = symbolToJson(symbol, 12);
			if (keep) {
				symbols.add(symbolJson);
			}
			if (symbol.isExternal()) {
				imports.add(symbolJson);
			}
			if (symbol.isExternalEntryPoint() && !symbol.isExternal()) {
				exports.add(symbolJson);
			}
			String artifactType = symbolJson.get("artifact_type").getAsString();
			if (artifactType.startsWith("objc_")) {
				objcRelated.add(symbolJson);
			}
			if ("swift_symbol".equals(artifactType)) {
				swiftRelated.add(symbolJson);
			}
		}

		payload.addProperty("symbol_count", symbols.size());
		payload.addProperty("import_count", imports.size());
		payload.addProperty("export_count", exports.size());
		payload.add("symbols", symbols);
		payload.add("imports", imports);
		payload.add("exports", exports);
		payload.add("objc_related", objcRelated);
		payload.add("swift_related", swiftRelated);
		return payload;
	}

	protected JsonObject symbolToJson(Symbol symbol, int xrefLimit) {
		JsonObject object = new JsonObject();
		object.addProperty("name", symbol.getName());
		object.addProperty("address", String.valueOf(symbol.getAddress()));
		object.addProperty("symbol_type", String.valueOf(symbol.getSymbolType()));
		object.addProperty("namespace", namespacePath(symbol.getParentNamespace()));
		object.addProperty("source", String.valueOf(symbol.getSource()));
		object.addProperty("external", symbol.isExternal());
		object.addProperty("external_entry_point", symbol.isExternalEntryPoint());
		object.addProperty("primary", symbol.isPrimary());
		object.addProperty("artifact_type", classifySymbolArtifact(symbol));
		JsonObject refs = sampleReferences(symbol.getAddress(), xrefLimit);
		object.addProperty("xref_count", refs.get("count").getAsInt());
		object.add("sample_xrefs", refs.getAsJsonArray("items"));
		Matcher matcher = OBJC_METHOD_PATTERN.matcher(symbol.getName());
		if (matcher.matches()) {
			JsonObject objcMethod = new JsonObject();
			objcMethod.addProperty("kind", "+".equals(matcher.group(1)) ? "class" : "instance");
			objcMethod.addProperty("class_name", matcher.group(2));
			objcMethod.addProperty("selector", matcher.group(3));
			object.add("objc_method", objcMethod);
		}
		return object;
	}

	protected JsonObject buildStrings(int xrefLimit) {
		JsonObject payload = new JsonObject();
		payload.addProperty("program_name", currentProgram.getName());
		payload.addProperty("xref_sample_limit", xrefLimit);
		JsonArray strings = new JsonArray();
		DefinedStringIterator iterator = DefinedStringIterator.forProgram(currentProgram, currentSelection);
		for (Data data : iterator) {
			if (monitor.isCancelled()) {
				break;
			}
			StringDataInstance stringData = StringDataInstance.getStringDataInstance(data);
			String value = stringData == null ? null : stringData.getStringValue();
			if (value == null) {
				continue;
			}
			strings.add(stringToJson(data, value, xrefLimit));
		}
		payload.addProperty("string_count", strings.size());
		payload.add("strings", strings);
		return payload;
	}

	protected JsonObject stringToJson(Data data, String value, int xrefLimit) {
		JsonObject stringJson = new JsonObject();
		stringJson.addProperty("address", String.valueOf(data.getAddress()));
		stringJson.addProperty("length", value.length());
		stringJson.addProperty("value", value);
		MemoryBlock block = currentProgram.getMemory().getBlock(data.getAddress());
		String blockName = block == null ? "" : empty(block.getName());
		stringJson.addProperty("block", blockName);
		stringJson.addProperty("data_type", String.valueOf(data.getDataType()));
		stringJson.addProperty("artifact_type", classifyStringArtifact(blockName, value));
		stringJson.addProperty("metadata_group", classifyMetadataGroup(blockName, value));
		JsonObject refs = sampleReferences(data.getAddress(), xrefLimit);
		stringJson.addProperty("xref_count", refs.get("count").getAsInt());
		stringJson.add("xrefs", refs.getAsJsonArray("items"));
		return stringJson;
	}

	protected String classifyFunctionArtifact(Function function) {
		String name = function.getName();
		if (OBJC_METHOD_PATTERN.matcher(name).matches()) {
			return "objc_method";
		}
		if (isSwiftSymbol(name)) {
			return "swift_function";
		}
		if (name.startsWith("_OUTLINED_FUNCTION_")) {
			return "outlined_function";
		}
		return "function";
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
		if (isSwiftSymbol(name)) {
			return "swift_symbol";
		}
		return "symbol";
	}

	protected String classifyStringArtifact(String blockName, String value) {
		String lower = blockName == null ? "" : blockName.toLowerCase(Locale.ROOT);
		if (lower.contains("objc_methname")) {
			return "objc_selector";
		}
		if (lower.contains("objc_classname")) {
			return "objc_classname";
		}
		if (lower.contains("cfstring")) {
			return "cfstring";
		}
		if (lower.contains("classref")) {
			return "objc_classref";
		}
		if (lower.contains("selref")) {
			return "objc_selref";
		}
		if (lower.contains("ivar")) {
			return "objc_ivar";
		}
		if (value.startsWith("com.apple.")) {
			return "service_string";
		}
		return "string";
	}

	protected String classifyMetadataGroup(String blockName, String value) {
		String lower = blockName == null ? "" : blockName.toLowerCase(Locale.ROOT);
		if (lower.contains("objc")) {
			return "objc_runtime";
		}
		if (lower.contains("cfstring")) {
			return "corefoundation";
		}
		if (lower.contains("plist") || value.startsWith("<?xml") || value.startsWith("{") ||
			value.startsWith("<plist")) {
			return "plist_like";
		}
		if (isSwiftSymbol(value)) {
			return "swift_runtime";
		}
		return "generic";
	}

}
