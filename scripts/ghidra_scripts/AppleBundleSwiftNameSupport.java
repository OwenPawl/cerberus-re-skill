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

abstract class AppleBundleSwiftNameSupport extends AppleBundleObjcSupport {

	protected String resolveSwiftDemangleTool() {
		if (swiftDemangleToolResolved) {
			return swiftDemangleTool;
		}
		swiftDemangleToolResolved = true;
		List<String> candidates = Arrays.asList(
			System.getenv("SWIFT_DEMANGLE"),
			"/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/swift-demangle",
			"/usr/bin/swift-demangle");
		for (String candidate : candidates) {
			if (candidate == null || candidate.isEmpty()) {
				continue;
			}
			File file = new File(candidate);
			if (file.isFile() && file.canExecute()) {
				swiftDemangleTool = file.getAbsolutePath();
				return swiftDemangleTool;
			}
		}
		return "";
	}

	protected String demangleSwiftName(String name) {
		if (name == null || name.isEmpty()) {
			return "";
		}
		String candidate = name;
		if (candidate.startsWith("_symbolic_$s")) {
			candidate = candidate.substring("_symbolic_".length());
		}
		else if (candidate.startsWith("_symbolic $s")) {
			candidate = candidate.substring("_symbolic ".length()).trim();
		}
		if (!candidate.startsWith("$s") && !candidate.startsWith("_$s") &&
			!candidate.startsWith("So") && !candidate.startsWith("_Tt")) {
			return name;
		}
		if (swiftDemangleCache.containsKey(candidate)) {
			return swiftDemangleCache.get(candidate);
		}
		String tool = resolveSwiftDemangleTool();
		if (tool.isEmpty()) {
			swiftDemangleCache.put(candidate, name);
			return name;
		}
		try {
			Process process = new ProcessBuilder(tool, "-compact", candidate)
				.redirectErrorStream(true)
				.start();
			String output;
			try (InputStream input = process.getInputStream()) {
				output = new String(input.readAllBytes(), StandardCharsets.UTF_8).trim();
			}
			int exitCode = process.waitFor();
			String value = exitCode == 0 && !output.isEmpty() ? normalizeDemangledSwiftOutput(output) :
				name;
			swiftDemangleCache.put(candidate, value);
			return value;
		}
		catch (Exception ignored) {
			swiftDemangleCache.put(candidate, name);
			return name;
		}
	}

	protected String demangleSwiftMetadataString(String value) {
		if (value == null || value.isEmpty()) {
			return "";
		}
		if (value.startsWith("$s") || value.startsWith("_$s") || value.startsWith("So") ||
			value.startsWith("_Tt") || value.startsWith("_symbolic_$s") ||
			value.startsWith("_symbolic $s")) {
			return demangleSwiftName(value);
		}
		return value;
	}

	protected boolean isSwiftDispatchThunk(String name) {
		String lower = name.toLowerCase(Locale.ROOT);
		return lower.contains("dispatch thunk of ") || lower.contains("@objc thunk");
	}

	protected boolean isSwiftProtocolWitness(String name) {
		return name.toLowerCase(Locale.ROOT).contains("protocol witness");
	}

	protected boolean isSwiftOutlinedHelper(String name) {
		String lower = name.toLowerCase(Locale.ROOT);
		return lower.contains("outlined") || lower.contains("partial apply");
	}

	protected boolean isSwiftResumePartial(String name) {
		String lower = name.toLowerCase(Locale.ROOT);
		return lower.contains("resume partial function") || lower.contains("suspend resume");
	}

	protected String normalizeDemangledSwiftOutput(String value) {
		String normalized = empty(value).trim();
		if (normalized.startsWith("_symbolic")) {
			normalized = normalized.substring("_symbolic".length()).trim();
		}
		return normalized;
	}

	protected String buildStableSwiftAlias(String typeName, String memberName, String displayName,
			String rawName) {
		if (!typeName.isEmpty() && !memberName.isEmpty()) {
			return typeName + "." + memberName;
		}
		if (!typeName.isEmpty()) {
			return typeName;
		}
		if (displayName != null && !displayName.isEmpty()) {
			return displayName;
		}
		return empty(rawName);
	}

	protected String extractSwiftTypeName(String displayName, String rawName) {
		String fromDisplay = extractSwiftTypeNameFromDisplay(displayName);
		if (!fromDisplay.isEmpty()) {
			return fromDisplay;
		}
		String fromRaw = extractSwiftTypeNameFromRaw(rawName);
		if (!fromRaw.isEmpty()) {
			return fromRaw;
		}
		String objcBridgeName = extractObjcBridgeNameFromArtifact(rawName);
		if (!objcBridgeName.isEmpty()) {
			return guessSwiftTypeFromObjcBridgeName(objcBridgeName);
		}
		return "";
	}

	protected String extractSwiftTypeNameFromDisplay(String displayName) {
		String normalized = stripSwiftPrefixes(displayName);
		Matcher typeMatcher = SWIFT_TYPE_PATTERN.matcher(normalized);
		if (typeMatcher.find()) {
			return typeMatcher.group(1).trim();
		}
		int witnessIndex = normalized.indexOf(" in conformance ");
		String primary = witnessIndex >= 0 ? normalized.substring(0, witnessIndex) : normalized;
		int parenIndex = primary.indexOf('(');
		int dotIndex = parenIndex >= 0 ? primary.lastIndexOf('.', parenIndex) :
			primary.lastIndexOf('.');
		if (dotIndex > 0) {
			return primary.substring(0, dotIndex).trim();
		}
		if (looksLikeSwiftTypeName(primary)) {
			return primary.trim();
		}
		return "";
	}

	protected String extractSwiftTypeNameFromRaw(String rawName) {
		String value = empty(rawName).trim();
		if (value.isEmpty()) {
			return "";
		}
		String symbolicType = extractLengthEncodedSwiftPathFromAnyOffset(value);
		if (!symbolicType.isEmpty()) {
			return symbolicType;
		}
		String demangled = demangleSwiftMetadataString(value);
		if (!demangled.isEmpty() && !demangled.equals(value)) {
			String fromDemangled = extractSwiftTypeNameFromDisplay(demangled);
			if (!fromDemangled.isEmpty()) {
				return fromDemangled;
			}
			if (looksLikeSwiftTypeName(demangled)) {
				return demangled;
			}
		}
		return "";
	}

	protected String extractSwiftMemberName(String displayName, String typeName, String rawName) {
		String normalized = stripSwiftPrefixes(displayName);
		if (empty(rawName).startsWith("_symbolic")) {
			return "";
		}
		if (typeName.equals(normalized)) {
			return extractRuntimeArtifactMemberName(rawName);
		}
		if (!typeName.isEmpty() && normalized.startsWith(typeName + ".")) {
			return normalized.substring(typeName.length() + 1).trim();
		}
		int witnessIndex = normalized.indexOf(" in conformance ");
		if (witnessIndex > 0) {
			normalized = normalized.substring(0, witnessIndex).trim();
			if (!typeName.isEmpty() && normalized.startsWith(typeName + ".")) {
				return normalized.substring(typeName.length() + 1).trim();
			}
		}
		String runtimeArtifact = extractRuntimeArtifactMemberName(rawName);
		if (!runtimeArtifact.isEmpty()) {
			return runtimeArtifact;
		}
		if (!typeName.isEmpty() && normalized.equals(typeName)) {
			return "";
		}
		return normalized;
	}

	protected String stripSwiftPrefixes(String displayName) {
		if (displayName == null) {
			return "";
		}
		String value = displayName.trim();
		String[] prefixes = {
			"dispatch thunk of ",
			"@objc thunk for ",
			"protocol witness for ",
			"method descriptor for ",
			"type metadata accessor for ",
			"type metadata for ",
			"nominal type descriptor for "
		};
		for (String prefix : prefixes) {
			if (value.startsWith(prefix)) {
				return value.substring(prefix.length()).trim();
			}
		}
		return value;
	}

	protected String extractLengthEncodedSwiftPathFromAnyOffset(String rawValue) {
		String value = empty(rawValue).trim();
		for (int index = 0; index < value.length(); index++) {
			if (!Character.isDigit(value.charAt(index))) {
				continue;
			}
			String candidate = parseSwiftLengthEncodedPath(value.substring(index));
			if (!candidate.isEmpty()) {
				return candidate;
			}
		}
		return "";
	}

	protected String extractObjcBridgeNameFromArtifact(String rawValue) {
		String value = empty(rawValue).trim();
		if (value.isEmpty()) {
			return "";
		}
		for (String prefix : SWIFT_OBJC_RUNTIME_PREFIXES) {
			if (value.startsWith(prefix)) {
				return value.substring(prefix.length());
			}
		}
		if (value.startsWith("So")) {
			String parsed = parseSingleLengthEncodedIdentifier(value.substring(2));
			if (!parsed.isEmpty()) {
				return parsed;
			}
		}
		Matcher literalMatcher = OBJC_CLASS_LITERAL_PATTERN.matcher(value);
		if (literalMatcher.find()) {
			return empty(literalMatcher.group(1));
		}
		return "";
	}

	protected String parseSingleLengthEncodedIdentifier(String rawValue) {
		String value = empty(rawValue);
		int index = 0;
		while (index < value.length() && Character.isDigit(value.charAt(index))) {
			index++;
		}
		if (index == 0) {
			return "";
		}
		try {
			int length = Integer.parseInt(value.substring(0, index));
			if (length <= 0 || index + length > value.length()) {
				return "";
			}
			return value.substring(index, index + length);
		}
		catch (NumberFormatException ignored) {
			return "";
		}
	}

	protected String extractRuntimeArtifactMemberName(String rawName) {
		String value = empty(rawName);
		if (value.startsWith("__INSTANCE_METHODS_")) {
			return "instanceMethods";
		}
		if (value.startsWith("__CLASS_METHODS_")) {
			return "classMethods";
		}
		if (value.startsWith("__PROPERTIES_")) {
			return "properties";
		}
		if (value.startsWith("__IVARS_")) {
			return "ivars";
		}
		if (value.startsWith("__DATA_")) {
			return "classData";
		}
		if (value.startsWith("__METACLASS_DATA_")) {
			return "metaclassData";
		}
		if (value.startsWith("_OBJC_CLASS_$_")) {
			return "objcClass";
		}
		if (value.startsWith("_OBJC_METACLASS_$_")) {
			return "objcMetaclass";
		}
		return "";
	}

	protected void ensureSwiftNameHints() {
		if (swiftNameHintsResolved) {
			return;
		}
		swiftNameHintsResolved = true;
		Set<String> bridgeNames = new LinkedHashSet<>();

		for (SymbolIterator iterator = currentProgram.getSymbolTable().getAllSymbols(true); iterator
				.hasNext();) {
			Symbol symbol = iterator.next();
			harvestSwiftNameHints(symbol.getName(), bridgeNames);
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
			harvestSwiftNameHints(value, bridgeNames);
		}

		for (String bridgeName : bridgeNames) {
			String typeName = correlateSwiftTypeForBridgeName(bridgeName);
			if (!typeName.isEmpty()) {
				swiftBridgeTypeHints.put(bridgeName, typeName);
			}
		}
	}

	protected void harvestSwiftNameHints(String rawValue, Set<String> bridgeNames) {
		String value = empty(rawValue).trim();
		if (value.isEmpty()) {
			return;
		}
		String directType = extractSwiftTypeNameFromDisplay(value);
		if (!directType.isEmpty()) {
			swiftKnownTypeHints.add(directType);
		}
		String rawType = extractSwiftTypeNameFromRaw(value);
		if (!rawType.isEmpty()) {
			swiftKnownTypeHints.add(rawType);
		}
		String bridgeName = extractObjcBridgeNameFromArtifact(value);
		if (!bridgeName.isEmpty()) {
			bridgeNames.add(bridgeName);
		}
	}

	protected String correlateSwiftTypeForBridgeName(String bridgeName) {
		if (bridgeName == null || bridgeName.isEmpty()) {
			return "";
		}
		String best = "";
		String normalizedBridge = normalizeLookupKey(bridgeName);
		String normalizedCore = normalizedBridge.startsWith("swift") ?
			normalizedBridge.substring("swift".length()) : normalizedBridge;
		for (String typeName : swiftKnownTypeHints) {
			String shortName = shortSwiftTypeName(typeName);
			if (shortName.isEmpty()) {
				continue;
			}
			String normalizedShort = normalizeLookupKey(shortName);
			if (normalizedShort.isEmpty()) {
				continue;
			}
			boolean match = normalizedBridge.equals(normalizedShort) ||
				normalizedBridge.equals("swift" + normalizedShort) ||
				normalizedCore.equals(normalizedShort) ||
				normalizedBridge.endsWith(normalizedShort) ||
				normalizedShort.endsWith(normalizedCore);
			if (match && typeName.length() > best.length()) {
				best = typeName;
			}
		}
		return best;
	}

	protected String guessSwiftTypeFromObjcBridgeName(String bridgeName) {
		if (bridgeName == null || bridgeName.isEmpty()) {
			return "";
		}
		ensureSwiftNameHints();
		String direct = swiftBridgeTypeHints.get(bridgeName);
		if (direct != null && !direct.isEmpty()) {
			return direct;
		}
		return correlateSwiftTypeForBridgeName(bridgeName);
	}

	protected String normalizeLookupKey(String value) {
		StringBuilder builder = new StringBuilder();
		for (int i = 0; i < value.length(); i++) {
			char ch = Character.toLowerCase(value.charAt(i));
			if (Character.isLetterOrDigit(ch)) {
				builder.append(ch);
			}
		}
		return builder.toString();
	}

	protected String shortSwiftTypeName(String value) {
		if (value == null || value.isEmpty()) {
			return "";
		}
		int index = value.lastIndexOf('.');
		return index >= 0 ? value.substring(index + 1) : value;
	}

	protected boolean looksLikeSwiftTypeName(String value) {
		if (value == null || value.isEmpty()) {
			return false;
		}
		if (value.contains("(") || value.contains(" ") || value.contains("-[") ||
			value.contains("+[") || value.startsWith("___")) {
			return false;
		}
		if (!value.matches("^[A-Za-z_][A-Za-z0-9_$.<>:]*$")) {
			return false;
		}
		return Character.isUpperCase(value.charAt(0)) || value.startsWith("__C.") ||
			value.contains(".");
	}

	protected boolean looksLikeSwiftProtocolName(String value) {
		if (value == null || value.isEmpty()) {
			return false;
		}
		if (!looksLikeSwiftTypeName(value)) {
			return false;
		}
		String lower = value.toLowerCase(Locale.ROOT);
		return lower.contains("protocol") || value.startsWith("__C.") ||
			Character.isUpperCase(value.charAt(0));
	}

	protected String classifySwiftSymbolKind(String displayName, String memberName, String rawName) {
		String lowerMember = memberName.toLowerCase(Locale.ROOT);
		if (!extractRuntimeArtifactMemberName(rawName).isEmpty()) {
			return "runtime_artifact";
		}
		if (empty(memberName).isEmpty() && empty(rawName).startsWith("_symbolic")) {
			return "symbolic_type_reference";
		}
		if (isSwiftDispatchThunk(displayName)) {
			return "dispatch_thunk";
		}
		if (isSwiftProtocolWitness(displayName)) {
			return "protocol_witness";
		}
		if (isSwiftMetadataAccessor(displayName)) {
			return "metadata_accessor";
		}
		if (isSwiftAsyncLike(displayName)) {
			return "async_method";
		}
		if (lowerMember.startsWith("getter :") || lowerMember.startsWith("setter :") ||
			lowerMember.startsWith("modify") || lowerMember.startsWith("read") ||
			lowerMember.contains("willset") || lowerMember.contains("didset")) {
			return "property_accessor";
		}
		if (lowerMember.startsWith("init(") || lowerMember.startsWith("__allocating_init(")) {
			return "initializer";
		}
		if (lowerMember.startsWith("deinit")) {
			return "deinitializer";
		}
		if (isSwiftOutlinedHelper(displayName)) {
			return "outlined_helper";
		}
		return "method";
	}

	protected boolean looksLikeHighConfidenceSwiftMethod(String displayName, String memberName,
			String kind) {
		if (displayName == null || displayName.isEmpty() || memberName == null ||
			memberName.isEmpty()) {
			return false;
		}
		if ("metadata_accessor".equals(kind) || "outlined_helper".equals(kind)) {
			return false;
		}
		String lowerMember = memberName.toLowerCase(Locale.ROOT);
		if (memberName.contains("(") || lowerMember.startsWith("getter :") ||
			lowerMember.startsWith("setter :") || lowerMember.startsWith("modify") ||
			lowerMember.startsWith("read") || lowerMember.startsWith("init(") ||
			lowerMember.startsWith("__allocating_init(") || lowerMember.startsWith("deinit") ||
			lowerMember.startsWith("start(")) {
			return true;
		}
		return "dispatch_thunk".equals(kind) || "protocol_witness".equals(kind) ||
			"async_method".equals(kind);
	}

	protected boolean isSwiftSymbol(String name) {
		String lower = name.toLowerCase(Locale.ROOT);
		if (name.startsWith("$s") || name.startsWith("_$s") || name.startsWith("_Tt") ||
			name.startsWith("_symbolic") || name.startsWith("So") || lower.contains("swift") ||
			lower.contains("type metadata") || lower.contains("protocol conformance")) {
			return true;
		}
		if (lower.contains("block_invoke") || name.contains("-[") || name.contains("+[") ||
			name.startsWith("___")) {
			return false;
		}
		String stripped = stripSwiftPrefixes(name);
		return stripped.contains(".") &&
			(stripped.contains("(") || stripped.contains("getter :") ||
				stripped.contains("setter :") || stripped.contains("modify") ||
				stripped.contains("read") || stripped.contains("init(") ||
				stripped.contains("deinit"));
	}

	protected boolean isSwiftMetadataAccessor(String name) {
		String lower = name.toLowerCase(Locale.ROOT);
		return lower.contains("type metadata accessor") || lower.contains("nominal type descriptor") ||
			name.endsWith("CMa") || name.endsWith("Mn");
	}

	protected boolean isSwiftProtocolConformanceLike(String name) {
		String lower = name.toLowerCase(Locale.ROOT);
		return lower.contains("protocol conformance") || lower.contains("protocol witness");
	}

	protected boolean isSwiftAsyncLike(String name) {
		String lower = name.toLowerCase(Locale.ROOT);
		return lower.contains("async") || lower.contains("resume partial function") ||
			lower.contains("suspend resume");
	}

	protected boolean looksLikeSwiftProtocolRequirement(String rawValue) {
		return rawValue != null && !rawValue.isEmpty() &&
			(rawValue.startsWith("_symbolic ") || rawValue.startsWith("_symbolic_")) &&
			rawValue.contains("Qz") && rawValue.endsWith("P");
	}

	protected boolean looksLikeSwiftAssociatedConformance(String rawValue) {
		if (rawValue == null || rawValue.isEmpty()) {
			return false;
		}
		return rawValue.startsWith("_associated conformance ") ||
			rawValue.startsWith("_associated_conformance_");
	}

	protected String normalizeAssociatedConformance(String rawValue) {
		if (rawValue == null) {
			return "";
		}
		if (rawValue.startsWith("_associated conformance ")) {
			return rawValue.substring("_associated conformance ".length());
		}
		if (rawValue.startsWith("_associated_conformance_")) {
			return rawValue.substring("_associated_conformance_".length());
		}
		return rawValue;
	}

	protected String extractLeadingSwiftIdentifier(String rawValue) {
		String normalized = normalizeSymbolicMetadata(rawValue);
		if (normalized.isEmpty()) {
			return "";
		}
		int index = 0;
		if (!Character.isDigit(normalized.charAt(index))) {
			return "";
		}
		while (index < normalized.length() && Character.isDigit(normalized.charAt(index))) {
			index++;
		}
		try {
			int length = Integer.parseInt(normalized.substring(0, index));
			if (length <= 0 || index + length > normalized.length()) {
				return "";
			}
			return normalized.substring(index, index + length);
		}
		catch (NumberFormatException ignored) {
			return "";
		}
	}

	protected String extractLeadingSwiftPath(String rawValue) {
		return parseSwiftLengthEncodedPath(normalizeAssociatedConformance(rawValue));
	}

	protected String extractProtocolNameFromAssociatedTypeRef(String rawValue) {
		String value = rawValue;
		int markerIndex = value.indexOf("Qz ");
		if (markerIndex >= 0) {
			value = value.substring(markerIndex + 3);
			return parseSwiftLengthEncodedPath(value);
		}
		markerIndex = value.indexOf("Qz_");
		if (markerIndex >= 0) {
			value = value.substring(markerIndex + 3);
			return parseSwiftLengthEncodedPath(value);
		}
		return "";
	}

	protected String extractAssociatedTypeName(String rawValue) {
		Matcher matcher = Pattern.compile("(\\d+)([A-Za-z_][A-Za-z0-9_]*)").matcher(rawValue);
		while (matcher.find()) {
			try {
				int declaredLength = Integer.parseInt(matcher.group(1));
				String value = matcher.group(2);
				if (declaredLength == value.length() && value.endsWith("Type")) {
					return value;
				}
			}
			catch (NumberFormatException ignored) {
				return "";
			}
		}
		return "";
	}

	protected String normalizeSymbolicMetadata(String rawValue) {
		if (rawValue == null) {
			return "";
		}
		if (rawValue.startsWith("_symbolic ")) {
			return rawValue.substring("_symbolic ".length()).trim();
		}
		if (rawValue.startsWith("_symbolic_")) {
			return rawValue.substring("_symbolic_".length()).trim();
		}
		return rawValue.trim();
	}

	protected String parseSwiftLengthEncodedPath(String rawValue) {
		if (rawValue == null || rawValue.isEmpty()) {
			return "";
		}
		String value = rawValue.trim();
		if (value.startsWith("$s")) {
			value = value.substring(2);
		}
		else if (value.startsWith("_$s")) {
			value = value.substring(3);
		}
		List<String> parts = new ArrayList<>();
		int index = 0;
		while (index < value.length() && Character.isDigit(value.charAt(index))) {
			int start = index;
			while (index < value.length() && Character.isDigit(value.charAt(index))) {
				index++;
			}
			int length;
			try {
				length = Integer.parseInt(value.substring(start, index));
			}
			catch (NumberFormatException ignored) {
				break;
			}
			if (length <= 0 || index + length > value.length()) {
				break;
			}
			String part = value.substring(index, index + length);
			parts.add(part);
			index += length;
		}
		if (parts.isEmpty()) {
			return "";
		}
		return String.join(".", parts);
	}

	protected String demangleLooseSwiftSymbol(String rawValue) {
		String normalized = normalizeAssociatedConformance(rawValue);
		if (normalized.isEmpty()) {
			return "";
		}
		String candidate = "$s" + normalized;
		String demangled = demangleSwiftName(candidate);
		if (!demangled.equals(candidate)) {
			return demangled;
		}
		return "";
	}

	protected String bestKnownTypeMatch(String text, Set<String> knownTypes, String exclude) {
		if (text == null || text.isEmpty()) {
			return "";
		}
		String best = "";
		for (String knownType : knownTypes) {
			if (knownType == null || knownType.isEmpty() || knownType.equals(exclude)) {
				continue;
			}
			String shortName = knownType.contains(".") ?
				knownType.substring(knownType.lastIndexOf('.') + 1) : knownType;
			if (text.contains(knownType) || text.contains(shortName)) {
				if (knownType.length() > best.length()) {
					best = knownType;
				}
			}
		}
		return best;
	}

	protected String extractConcreteTypeFromAssociatedConformanceDemangle(String demangled,
			String protocolName, String conformingType) {
		if (demangled == null || demangled.isEmpty()) {
			return "";
		}
		Pattern pattern = Pattern.compile("([A-Z][A-Za-z0-9_]+)$");
		Matcher matcher = pattern.matcher(demangled);
		if (!matcher.find()) {
			return "";
		}
		String candidate = matcher.group(1);
		if (candidate.equals(shortSwiftTypeName(protocolName)) ||
			candidate.equals(shortSwiftTypeName(conformingType))) {
			return "";
		}
		return candidate;
	}

}
