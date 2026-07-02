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

abstract class AppleBundleObjcSupport extends AppleBundleCoreSupport {

	protected JsonObject buildObjcMetadata() {
		Set<String> classes = new TreeSet<>();
		Set<String> interfaceClasses = new TreeSet<>();
		Set<String> metaclasses = new TreeSet<>();
		Set<String> protocols = new TreeSet<>();
		Set<String> categories = new TreeSet<>();
		Set<String> selectors = new TreeSet<>();
		Set<String> objcSections = new TreeSet<>();
		Set<String> ivars = new TreeSet<>();
		JsonArray methods = new JsonArray();
		JsonArray selectorRefs = new JsonArray();
		JsonArray classRefs = new JsonArray();
		JsonArray protocolRefs = new JsonArray();
		JsonArray recoveredProtocols = new JsonArray();
		JsonArray classNames = new JsonArray();
		JsonArray selectorStrings = new JsonArray();
		Set<String> seenMethods = new LinkedHashSet<>();
		Set<String> seenRefAddresses = new LinkedHashSet<>();
		Set<String> seenRecoveredProtocols = new LinkedHashSet<>();

		for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
			if (block.getName() != null && block.getName().toLowerCase(Locale.ROOT).contains("objc")) {
				objcSections.add(block.getName());
			}
		}

		for (FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true); iterator
				.hasNext();) {
			Function function = iterator.next();
			addObjcMethod(methods, seenMethods, function.getName(),
				String.valueOf(function.getEntryPoint()), "function", classes, selectors);
		}

		for (SymbolIterator iterator = currentProgram.getSymbolTable().getAllSymbols(true); iterator
				.hasNext();) {
			Symbol symbol = iterator.next();
			String name = symbol.getName();
			String lower = name.toLowerCase(Locale.ROOT);
			if (name.startsWith("_OBJC_CLASS_$_")) {
				String className = name.substring("_OBJC_CLASS_$_".length());
				classes.add(className);
				addLikelyObjcRuntimeName(interfaceClasses, className);
			}
			if (name.startsWith("_OBJC_METACLASS_$_")) {
				String metaclassName = name.substring("_OBJC_METACLASS_$_".length());
				metaclasses.add(metaclassName);
			}
			if (name.startsWith("_OBJC_PROTOCOL_$_")) {
				String protocolName = name.substring("_OBJC_PROTOCOL_$_".length());
				protocols.add(protocolName);
				addRecoveredProtocol(recoveredProtocols, seenRecoveredProtocols, protocols,
					name, String.valueOf(symbol.getAddress()), "explicit_symbol");
			}
			if (name.startsWith("_OBJC_CATEGORY_$_")) {
				categories.add(name.substring("_OBJC_CATEGORY_$_".length()));
			}
			if (name.startsWith("selRef_")) {
				selectors.add(name.substring("selRef_".length()));
				addAddressRef(selectorRefs, seenRefAddresses, symbol.getAddress(), name, "symbol");
			}
			if (lower.contains("classref")) {
				addAddressRef(classRefs, seenRefAddresses, symbol.getAddress(), name, "symbol");
			}
			if (lower.contains("protocol")) {
				addAddressRef(protocolRefs, seenRefAddresses, symbol.getAddress(), name, "symbol");
				addRecoveredProtocol(recoveredProtocols, seenRecoveredProtocols, protocols,
					name, String.valueOf(symbol.getAddress()), "symbol");
			}
			if (lower.contains("ivar")) {
				ivars.add(name);
			}
			addObjcMethod(methods, seenMethods, name, String.valueOf(symbol.getAddress()), "symbol",
				classes, selectors);
		}

		DefinedStringIterator strings = DefinedStringIterator.forProgram(currentProgram, currentSelection);
		for (Data data : strings) {
			if (monitor.isCancelled()) {
				break;
			}
			StringDataInstance stringData = StringDataInstance.getStringDataInstance(data);
			String value = stringData == null ? "" : empty(stringData.getStringValue());
			if (value.isEmpty()) {
				continue;
			}
			MemoryBlock block = currentProgram.getMemory().getBlock(data.getAddress());
			String blockName = block == null ? "" : empty(block.getName()).toLowerCase(Locale.ROOT);
			if (blockName.contains("objc_methname")) {
				selectors.add(value);
				addStringArtifact(selectorStrings, data.getAddress(), value, blockName, "data");
			}
			if (blockName.contains("objc_classname")) {
				classes.add(value);
				addLikelyObjcRuntimeName(interfaceClasses, value);
				addStringArtifact(classNames, data.getAddress(), value, blockName, "data");
			}
			if (blockName.contains("classref")) {
				addAddressRef(classRefs, seenRefAddresses, data.getAddress(), value, "data");
			}
			if (blockName.contains("selref")) {
				addAddressRef(selectorRefs, seenRefAddresses, data.getAddress(), value, "data");
			}
			if (blockName.contains("protocol")) {
				addAddressRef(protocolRefs, seenRefAddresses, data.getAddress(), value, "data");
				addRecoveredProtocol(recoveredProtocols, seenRecoveredProtocols, protocols,
					value, String.valueOf(data.getAddress()), "data");
			}
			if (blockName.contains("ivar")) {
				ivars.add(value);
			}
		}

		Set<String> cleanClasses = filterLikelyObjcRuntimeNames(classes);
		Set<String> cleanMetaclasses = filterLikelyObjcRuntimeNames(metaclasses);
		if (interfaceClasses.isEmpty()) {
			interfaceClasses.addAll(cleanClasses);
		}
		else {
			interfaceClasses.addAll(cleanClasses);
		}

		JsonObject payload = new JsonObject();
		payload.addProperty("program_name", currentProgram.getName());
		payload.add("objc_sections", toJsonArray(objcSections));
		payload.add("classes", toJsonArray(cleanClasses));
		payload.add("interface_classes", toJsonArray(interfaceClasses));
		payload.addProperty("class_source_preference", "interface_classes");
		payload.add("metaclasses", toJsonArray(cleanMetaclasses));
		payload.add("protocols", toJsonArray(protocols));
		payload.add("recovered_protocols", recoveredProtocols);
		payload.addProperty("protocol_source_preference",
			recoveredProtocols.size() > 0 ? "protocols+recovered_protocols" : "protocols");
		payload.add("categories", toJsonArray(categories));
		payload.add("selectors", toJsonArray(selectors));
		payload.add("ivars", toJsonArray(ivars));
		payload.add("methods", methods);
		payload.add("class_refs", classRefs);
		payload.add("selector_refs", selectorRefs);
		payload.add("protocol_refs", protocolRefs);
		payload.add("class_names", classNames);
		payload.add("selector_strings", selectorStrings);
		return payload;
	}

	protected void addObjcMethod(JsonArray methods, Set<String> seenMethods, String name,
			String address, String source, Set<String> classes, Set<String> selectors) {
		Matcher matcher = OBJC_METHOD_PATTERN.matcher(name);
		if (!matcher.matches()) {
			return;
		}
		String key = name + "|" + address;
		if (!seenMethods.add(key)) {
			return;
		}
		JsonObject method = new JsonObject();
		method.addProperty("name", name);
		method.addProperty("address", address);
		method.addProperty("kind", "+".equals(matcher.group(1)) ? "class" : "instance");
		method.addProperty("class_name", matcher.group(2));
		method.addProperty("selector", matcher.group(3));
		method.addProperty("source", source);
		methods.add(method);
		classes.add(matcher.group(2));
		selectors.add(matcher.group(3));
	}

	protected void addAddressRef(JsonArray array, Set<String> seen, Address address, String name,
			String source) {
		String key = String.valueOf(address) + "|" + name;
		if (!seen.add(key)) {
			return;
		}
		JsonObject object = new JsonObject();
		object.addProperty("address", String.valueOf(address));
		object.addProperty("name", name);
		object.addProperty("source", source);
		array.add(object);
	}

	protected void addStringArtifact(JsonArray array, Address address, String value, String blockName,
			String source) {
		JsonObject object = new JsonObject();
		object.addProperty("address", String.valueOf(address));
		object.addProperty("value", value);
		object.addProperty("block", blockName);
		object.addProperty("source", source);
		array.add(object);
	}

	protected void addLikelyObjcRuntimeName(Set<String> values, String rawName) {
		if (isLikelyObjcRuntimeName(rawName)) {
			values.add(rawName);
		}
	}

	protected Set<String> filterLikelyObjcRuntimeNames(Set<String> values) {
		Set<String> filtered = new TreeSet<>();
		for (String value : values) {
			if (isLikelyObjcRuntimeName(value)) {
				filtered.add(value);
			}
		}
		return filtered;
	}

	protected boolean isLikelyObjcRuntimeName(String rawName) {
		if (rawName == null) {
			return false;
		}
		String value = rawName.trim();
		if (value.isEmpty() || value.length() > 256 || value.length() == 1) {
			return false;
		}
		char first = value.charAt(0);
		if (!(Character.isLetter(first) || first == '_' || first == '$')) {
			return false;
		}
		for (int i = 0; i < value.length(); i++) {
			char ch = value.charAt(i);
			if (Character.isISOControl(ch)) {
				return false;
			}
			if (!(Character.isLetterOrDigit(ch) || ch == '_' || ch == '.' || ch == '$' ||
				ch == ':' || ch == '+' || ch == '-')) {
				return false;
			}
		}
		return true;
	}

	protected void addRecoveredProtocol(JsonArray recoveredProtocols, Set<String> seenRecoveredProtocols,
			Set<String> protocols, String rawName, String address, String source) {
		String recoveredName = recoverObjcProtocolName(rawName);
		if (recoveredName.isEmpty()) {
			return;
		}
		String key = recoveredName + "|" + source + "|" + address;
		if (!seenRecoveredProtocols.add(key)) {
			return;
		}
		double confidence = recoveredProtocolConfidence(rawName);
		JsonObject object = new JsonObject();
		object.addProperty("name", recoveredName);
		object.addProperty("raw_name", empty(rawName));
		object.addProperty("address", empty(address));
		object.addProperty("source", source);
		object.addProperty("confidence", confidence);
		recoveredProtocols.add(object);
		if (confidence >= 0.55) {
			protocols.add(recoveredName);
		}
	}

	protected String recoverObjcProtocolName(String rawName) {
		String value = empty(rawName);
		if (value.startsWith("_OBJC_PROTOCOL_$_")) {
			return value.substring("_OBJC_PROTOCOL_$_".length());
		}
		if (value.startsWith("_LNSystemEntityProtocolIdentifier")) {
			return value.substring("_LNSystemEntityProtocolIdentifier".length());
		}
		if (value.startsWith("_LNSystemProtocolIdentifier")) {
			return value.substring("_LNSystemProtocolIdentifier".length());
		}
		if (value.startsWith("_protocol_descriptor_for_")) {
			return value.substring("_protocol_descriptor_for_".length());
		}
		if (isLikelyObjcRuntimeName(value) && value.endsWith("Protocol")) {
			return value;
		}
		return "";
	}

	protected double recoveredProtocolConfidence(String rawName) {
		String value = empty(rawName);
		if (value.startsWith("_OBJC_PROTOCOL_$_")) {
			return 1.0;
		}
		if (value.startsWith("_LNSystemEntityProtocolIdentifier") ||
			value.startsWith("_LNSystemProtocolIdentifier")) {
			return 0.7;
		}
		if (value.startsWith("_protocol_descriptor_for_")) {
			return 0.65;
		}
		if (isLikelyObjcRuntimeName(value) && value.endsWith("Protocol")) {
			return 0.5;
		}
		return 0.0;
	}

}
