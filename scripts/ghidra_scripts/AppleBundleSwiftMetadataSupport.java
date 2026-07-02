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

abstract class AppleBundleSwiftMetadataSupport extends AppleBundleSwiftNameSupport {

	protected JsonObject buildSwiftMetadata() {
		Set<String> types = new TreeSet<>();
		Set<String> protocolConformances = new TreeSet<>();
		Set<String> metadataAccessors = new TreeSet<>();
		Set<String> asyncEntrypoints = new TreeSet<>();
		Set<String> typeDescriptors = new TreeSet<>();
		Set<String> dispatchThunks = new TreeSet<>();
		Set<String> protocolWitnesses = new TreeSet<>();
		Set<String> outlinedHelpers = new TreeSet<>();
		JsonArray symbols = new JsonArray();
		JsonArray metadataMethods = new JsonArray();
		JsonArray protocolRequirements = new JsonArray();
		JsonArray associatedConformanceRecords = new JsonArray();
		JsonArray codeCandidates = new JsonArray();
		JsonArray asyncRelationships = new JsonArray();
		JsonArray runtimeArtifacts = new JsonArray();
		JsonArray propertyRecords = new JsonArray();
		JsonArray fieldDescriptors = buildSwiftFieldDescriptors();
		JsonArray captureDescriptors = buildSwiftCaptureDescriptors();
		JsonObject aliasMap = new JsonObject();
		JsonArray aliases = new JsonArray();
		Set<String> seen = new LinkedHashSet<>();
		Set<String> seenMetadataMethodKeys = new LinkedHashSet<>();
		Set<String> seenProtocolRequirementKeys = new LinkedHashSet<>();
		Set<String> seenAssociatedConformanceKeys = new LinkedHashSet<>();
		Set<String> seenCodeCandidateKeys = new LinkedHashSet<>();
		Set<String> seenRuntimeArtifactKeys = new LinkedHashSet<>();
		Set<String> seenPropertyRecordKeys = new LinkedHashSet<>();
		List<JsonObject> swiftRecords = new ArrayList<>();

		for (FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true); iterator
				.hasNext();) {
			Function function = iterator.next();
			String name = function.getName();
			if (!isSwiftSymbol(name)) {
				continue;
			}
			if (!seen.add("function|" + name + "|" + function.getEntryPoint())) {
				continue;
			}
			JsonObject symbolJson = swiftFunctionToJson(function);
			symbols.add(symbolJson);
			swiftRecords.add(symbolJson);
			addSwiftAlias(aliasMap, aliases, symbolJson);
			classifySwiftJson(symbolJson, types, protocolConformances, metadataAccessors,
				asyncEntrypoints, typeDescriptors, dispatchThunks, protocolWitnesses,
				outlinedHelpers);
			if (shouldExposeAsMetadataMethod(symbolJson) &&
				seenMetadataMethodKeys.add(metadataMethodKey(symbolJson))) {
				metadataMethods.add(symbolJson.deepCopy());
			}
			if (shouldExposeAsRuntimeArtifact(symbolJson) &&
				seenRuntimeArtifactKeys.add(runtimeArtifactKey(symbolJson))) {
				runtimeArtifacts.add(symbolJson.deepCopy());
			}
		}

		for (SymbolIterator iterator = currentProgram.getSymbolTable().getAllSymbols(true); iterator
				.hasNext();) {
			Symbol symbol = iterator.next();
			String name = symbol.getName();
			if (!isSwiftSymbol(name)) {
				continue;
			}
			if (!seen.add("symbol|" + name + "|" + symbol.getAddress())) {
				continue;
			}
			JsonObject symbolJson = swiftSymbolToJson(name, String.valueOf(symbol.getAddress()), "symbol",
				null);
			symbols.add(symbolJson);
			swiftRecords.add(symbolJson);
			addSwiftAlias(aliasMap, aliases, symbolJson);
			classifySwiftJson(symbolJson, types, protocolConformances, metadataAccessors,
				asyncEntrypoints, typeDescriptors, dispatchThunks, protocolWitnesses,
				outlinedHelpers);
			if (shouldExposeAsMetadataMethod(symbolJson) &&
				seenMetadataMethodKeys.add(metadataMethodKey(symbolJson))) {
				metadataMethods.add(symbolJson.deepCopy());
			}
			if (shouldExposeAsRuntimeArtifact(symbolJson) &&
				seenRuntimeArtifactKeys.add(runtimeArtifactKey(symbolJson))) {
				runtimeArtifacts.add(symbolJson.deepCopy());
			}
		}

		JsonObject sectionMetadata = buildSwiftMetadataSectionSummary();
		ingestSwiftSectionStrings(sectionMetadata, types, protocolConformances);
		collectSwiftMetadataArtifacts(types, metadataMethods, protocolRequirements,
			associatedConformanceRecords, codeCandidates, seenMetadataMethodKeys,
			seenProtocolRequirementKeys, seenAssociatedConformanceKeys, seenCodeCandidateKeys);
		collectSwiftPropertyArtifacts(propertyRecords, codeCandidates, seenPropertyRecordKeys,
			seenCodeCandidateKeys);
		asyncRelationships = buildSwiftAsyncRelationships(swiftRecords);

		JsonObject payload = new JsonObject();
		payload.addProperty("program_name", currentProgram.getName());
		payload.addProperty("demangle_tool", empty(resolveSwiftDemangleTool()));
		payload.add("symbols", symbols);
		payload.add("metadata_methods", metadataMethods);
		payload.add("protocol_requirements", protocolRequirements);
		payload.add("associated_conformances", associatedConformanceRecords);
		payload.add("code_candidates", codeCandidates);
		payload.add("async_relationships", asyncRelationships);
		payload.add("runtime_artifacts", runtimeArtifacts);
		payload.add("property_records", propertyRecords);
		payload.add("field_descriptors", fieldDescriptors);
		payload.add("capture_descriptors", captureDescriptors);
		payload.add("types", toJsonArray(types));
		payload.add("protocol_conformances", toJsonArray(protocolConformances));
		payload.add("metadata_accessors", toJsonArray(metadataAccessors));
		payload.add("async_entrypoints", toJsonArray(asyncEntrypoints));
		payload.add("type_descriptors", toJsonArray(typeDescriptors));
		payload.add("dispatch_thunks", toJsonArray(dispatchThunks));
		payload.add("protocol_witnesses", toJsonArray(protocolWitnesses));
		payload.add("outlined_helpers", toJsonArray(outlinedHelpers));
		payload.add("alias_map", aliasMap);
		payload.add("aliases", aliases);
		payload.add("metadata_sections", sectionMetadata);
		payload.addProperty("symbol_count", symbols.size());
		return payload;
	}

	protected abstract JsonArray buildSwiftFieldDescriptors();

	protected abstract JsonArray buildSwiftCaptureDescriptors();

	protected boolean shouldExposeAsMetadataMethod(JsonObject symbolJson) {
		String typeName = empty(symbolJson.get("type_name").getAsString());
		String memberName = empty(symbolJson.get("member_name").getAsString());
		String kind = empty(symbolJson.get("symbol_kind").getAsString());
		String displayName = empty(symbolJson.get("display_name").getAsString());
		if (typeName.isEmpty() || memberName.isEmpty()) {
			return false;
		}
		return looksLikeHighConfidenceSwiftMethod(displayName, memberName, kind);
	}

	protected String metadataMethodKey(JsonObject symbolJson) {
		return empty(symbolJson.get("stable_alias").getAsString()) + "|" +
			empty(symbolJson.get("canonical_address").getAsString()) + "|" +
			empty(symbolJson.get("address").getAsString());
	}

	protected boolean shouldExposeAsRuntimeArtifact(JsonObject symbolJson) {
		String typeName = empty(symbolJson.get("type_name").getAsString());
		String kind = empty(symbolJson.get("symbol_kind").getAsString());
		if (typeName.isEmpty()) {
			return false;
		}
		return "runtime_artifact".equals(kind) || "symbolic_type_reference".equals(kind);
	}

	protected String runtimeArtifactKey(JsonObject symbolJson) {
		return empty(symbolJson.get("stable_alias").getAsString()) + "|" +
			empty(symbolJson.get("address").getAsString()) + "|" +
			empty(symbolJson.get("name").getAsString());
	}

	protected void collectSwiftMetadataArtifacts(Set<String> knownTypes, JsonArray metadataMethods,
			JsonArray protocolRequirements, JsonArray associatedConformances,
			JsonArray codeCandidates, Set<String> seenMetadataMethodKeys,
			Set<String> seenProtocolRequirementKeys, Set<String> seenAssociatedConformanceKeys,
			Set<String> seenCodeCandidateKeys) {
		for (SymbolIterator iterator = currentProgram.getSymbolTable().getAllSymbols(true); iterator
				.hasNext();) {
			Symbol symbol = iterator.next();
			ingestSwiftMetadataArtifact(symbol.getName(), symbol.getAddress(), "symbol", knownTypes,
				metadataMethods, protocolRequirements, associatedConformances, codeCandidates,
				seenMetadataMethodKeys, seenProtocolRequirementKeys, seenAssociatedConformanceKeys,
				seenCodeCandidateKeys);
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
			String blockName = block == null ? "" : empty(block.getName());
			if (!isSwiftMetadataArtifactValue(value, blockName)) {
				continue;
			}
			ingestSwiftMetadataArtifact(value, data.getAddress(), "string", knownTypes,
				metadataMethods, protocolRequirements, associatedConformances, codeCandidates,
				seenMetadataMethodKeys, seenProtocolRequirementKeys, seenAssociatedConformanceKeys,
				seenCodeCandidateKeys);
		}
	}

	protected boolean isSwiftMetadataArtifactValue(String value, String blockName) {
		String lowerValue = empty(value).toLowerCase(Locale.ROOT);
		String lowerBlock = empty(blockName).toLowerCase(Locale.ROOT);
		if (lowerBlock.contains("swift5_typeref") || lowerBlock.contains("swift5_proto") ||
			lowerBlock.contains("swift5_assocty") || lowerBlock.contains("swift5_reflstr")) {
			return true;
		}
		return lowerValue.startsWith("_symbolic ") || lowerValue.startsWith("_symbolic_") ||
			lowerValue.startsWith("_associated conformance ") ||
			lowerValue.startsWith("_associated_conformance_");
	}

	protected void ingestSwiftMetadataArtifact(String rawValue, Address sourceAddress, String source,
			Set<String> knownTypes, JsonArray metadataMethods, JsonArray protocolRequirements,
			JsonArray associatedConformances, JsonArray codeCandidates,
			Set<String> seenMetadataMethodKeys, Set<String> seenProtocolRequirementKeys,
			Set<String> seenAssociatedConformanceKeys, Set<String> seenCodeCandidateKeys) {
		if (rawValue == null || rawValue.isEmpty() || sourceAddress == null) {
			return;
		}
		JsonObject protocolRequirement = buildSwiftProtocolRequirementArtifact(rawValue,
			sourceAddress, source);
		if (protocolRequirement != null) {
			String key = empty(protocolRequirement.get("stable_alias").getAsString()) + "|" +
				empty(protocolRequirement.get("address").getAsString()) + "|" +
				empty(protocolRequirement.get("kind").getAsString());
			if (seenProtocolRequirementKeys.add(key)) {
				protocolRequirements.add(protocolRequirement);
			}
			addSwiftCodeCandidates(codeCandidates, seenCodeCandidateKeys,
				empty(protocolRequirement.get("type_name").getAsString()),
				empty(protocolRequirement.get("stable_alias").getAsString()),
				empty(protocolRequirement.get("kind").getAsString()), sourceAddress, rawValue);
		}

		JsonObject associatedConformance = buildSwiftAssociatedConformanceArtifact(rawValue,
			sourceAddress, source, knownTypes);
		if (associatedConformance != null) {
			String key = empty(associatedConformance.get("conforming_type").getAsString()) + "|" +
				empty(associatedConformance.get("type_name").getAsString()) + "|" +
				empty(associatedConformance.get("associated_type").getAsString()) + "|" +
				empty(associatedConformance.get("address").getAsString());
			if (seenAssociatedConformanceKeys.add(key)) {
				associatedConformances.add(associatedConformance);
			}
			addSwiftCodeCandidates(codeCandidates, seenCodeCandidateKeys,
				empty(associatedConformance.get("type_name").getAsString()),
				empty(associatedConformance.get("stable_alias").getAsString()),
				"associated_conformance", sourceAddress, rawValue);
		}

		JsonObject metadataMethod = buildSwiftMetadataMethodArtifact(rawValue, sourceAddress, source);
		if (metadataMethod != null) {
			String key = empty(metadataMethod.get("stable_alias").getAsString()) + "|" +
				empty(metadataMethod.get("canonical_address").getAsString()) + "|" +
				empty(metadataMethod.get("address").getAsString());
			if (seenMetadataMethodKeys.add(key)) {
				metadataMethods.add(metadataMethod);
			}
			addSwiftCodeCandidates(codeCandidates, seenCodeCandidateKeys,
				empty(metadataMethod.get("type_name").getAsString()),
				empty(metadataMethod.get("stable_alias").getAsString()),
				"metadata_method", sourceAddress, rawValue);
		}
	}

	protected void collectSwiftPropertyArtifacts(JsonArray propertyRecords, JsonArray codeCandidates,
			Set<String> seenPropertyRecordKeys, Set<String> seenCodeCandidateKeys) {
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
			JsonObject propertyRecord = buildSwiftPropertyArtifact(value, data.getAddress(), "string");
			if (propertyRecord == null) {
				continue;
			}
			String key = empty(propertyRecord.get("stable_alias").getAsString()) + "|" +
				empty(propertyRecord.get("address").getAsString());
			if (!seenPropertyRecordKeys.add(key)) {
				continue;
			}
			propertyRecords.add(propertyRecord);
			addSwiftCodeCandidates(codeCandidates, seenCodeCandidateKeys,
				empty(propertyRecord.get("type_name").getAsString()),
				empty(propertyRecord.get("stable_alias").getAsString()),
				"property_record", data.getAddress(), value);
		}
	}

	protected JsonObject buildSwiftPropertyArtifact(String rawValue, Address sourceAddress,
			String source) {
		Matcher matcher = SWIFT_PROPERTY_ENCODING_PATTERN.matcher(empty(rawValue));
		if (!matcher.find()) {
			return null;
		}
		String objcBridgeName = empty(matcher.group(1));
		String propertyName = empty(matcher.group(2));
		if (objcBridgeName.isEmpty() || propertyName.isEmpty()) {
			return null;
		}
		String typeName = guessSwiftTypeFromObjcBridgeName(objcBridgeName);
		if (typeName.isEmpty()) {
			return null;
		}
		JsonObject object = new JsonObject();
		object.addProperty("name", rawValue);
		object.addProperty("raw_name", rawValue);
		object.addProperty("display_name", typeName + "." + propertyName);
		object.addProperty("demangled", typeName + "." + propertyName);
		object.addProperty("address", String.valueOf(sourceAddress));
		object.addProperty("source", source);
		object.addProperty("type_name", typeName);
		object.addProperty("member_name", propertyName);
		object.addProperty("stable_alias", typeName + "." + propertyName);
		object.addProperty("symbol_kind", "property_record");
		object.addProperty("artifact_role", "property_record");
		object.addProperty("objc_bridge_name", objcBridgeName);
		object.addProperty("readonly", rawValue.contains(",R,"));
		return object;
	}

	protected JsonObject buildSwiftMetadataMethodArtifact(String rawValue, Address sourceAddress,
			String source) {
		if (!isSwiftSymbol(rawValue)) {
			return null;
		}
		JsonObject artifact = swiftSymbolToJson(rawValue, String.valueOf(sourceAddress), source, null);
		String typeName = empty(artifact.get("type_name").getAsString());
		String memberName = empty(artifact.get("member_name").getAsString());
		String kind = empty(artifact.get("symbol_kind").getAsString());
		String displayName = empty(artifact.get("display_name").getAsString());
		if (typeName.isEmpty() || memberName.isEmpty() ||
			!looksLikeHighConfidenceSwiftMethod(displayName, memberName, kind)) {
			return null;
		}
		artifact.addProperty("artifact_role", "metadata_method");
		return artifact;
	}

	protected JsonObject buildSwiftProtocolRequirementArtifact(String rawValue, Address sourceAddress,
			String source) {
		if (!looksLikeSwiftProtocolRequirement(rawValue)) {
			return null;
		}
		String associatedType = extractLeadingSwiftIdentifier(rawValue);
		String protocolName = extractProtocolNameFromAssociatedTypeRef(rawValue);
		if (associatedType.isEmpty() || protocolName.isEmpty()) {
			return null;
		}
		JsonObject object = new JsonObject();
		object.addProperty("kind", "associated_type");
		object.addProperty("type_name", protocolName);
		object.addProperty("protocol_name", protocolName);
		object.addProperty("associated_type", associatedType);
		object.addProperty("address", String.valueOf(sourceAddress));
		object.addProperty("source", source);
		object.addProperty("raw_name", rawValue);
		object.addProperty("stable_alias",
			protocolName + ".associatedtype." + associatedType);
		return object;
	}

	protected JsonObject buildSwiftAssociatedConformanceArtifact(String rawValue, Address sourceAddress,
			String source, Set<String> knownTypes) {
		if (!looksLikeSwiftAssociatedConformance(rawValue)) {
			return null;
		}
		String normalized = normalizeAssociatedConformance(rawValue);
		String conformingType = extractLeadingSwiftPath(normalized);
		String associatedType = extractAssociatedTypeName(normalized);
		String demangled = demangleLooseSwiftSymbol(normalized);
		String protocolName = bestKnownTypeMatch(demangled, knownTypes, "");
		String concreteType = extractConcreteTypeFromAssociatedConformanceDemangle(demangled,
			protocolName, conformingType);
		JsonObject object = new JsonObject();
		object.addProperty("kind", "associated_conformance");
		object.addProperty("type_name", protocolName);
		object.addProperty("protocol_name", protocolName);
		object.addProperty("conforming_type", conformingType);
		object.addProperty("associated_type", associatedType);
		object.addProperty("concrete_type", concreteType);
		object.addProperty("address", String.valueOf(sourceAddress));
		object.addProperty("source", source);
		object.addProperty("raw_name", rawValue);
		object.addProperty("demangled", demangled);
		String aliasBase = protocolName.isEmpty() ? conformingType : protocolName;
		if (!aliasBase.isEmpty() && !associatedType.isEmpty() && !conformingType.isEmpty()) {
			object.addProperty("stable_alias",
				aliasBase + ".associatedconformance." + conformingType + "." + associatedType);
		}
		else {
			object.addProperty("stable_alias", rawValue);
		}
		return object;
	}

	protected JsonArray buildSwiftAsyncRelationships(List<JsonObject> swiftRecords) {
		JsonArray relationships = new JsonArray();
		Map<String, JsonObject> primaryByAlias = new LinkedHashMap<>();
		for (JsonObject record : swiftRecords) {
			String alias = empty(record.get("stable_alias").getAsString());
			if (alias.isEmpty() || primaryByAlias.containsKey(alias)) {
				continue;
			}
			primaryByAlias.put(alias, record);
		}
		Set<String> seen = new LinkedHashSet<>();
		for (JsonObject record : swiftRecords) {
			boolean asyncLike = record.has("async_like") && record.get("async_like").getAsBoolean();
			boolean outlinedHelper = record.has("outlined_helper") &&
				record.get("outlined_helper").getAsBoolean();
			boolean resumePartial = record.has("resume_partial") &&
				record.get("resume_partial").getAsBoolean();
			if (!asyncLike && !outlinedHelper && !resumePartial) {
				continue;
			}
			String alias = empty(record.get("stable_alias").getAsString());
			String parentAlias = alias;
			if (!parentAlias.isEmpty() && !primaryByAlias.containsKey(parentAlias)) {
				parentAlias = empty(record.get("type_name").getAsString());
			}
			String key = parentAlias + "|" + alias + "|" +
				empty(record.get("canonical_address").getAsString());
			if (!seen.add(key)) {
				continue;
			}
			JsonObject entry = new JsonObject();
			entry.addProperty("type_name", empty(record.get("type_name").getAsString()));
			entry.addProperty("member_name", empty(record.get("member_name").getAsString()));
			entry.addProperty("parent_alias", parentAlias);
			entry.addProperty("child_alias", alias);
			entry.addProperty("address", empty(record.get("address").getAsString()));
			entry.addProperty("canonical_address", empty(record.get("canonical_address").getAsString()));
			entry.addProperty("raw_name", empty(record.get("raw_name").getAsString()));
			entry.addProperty("display_name", empty(record.get("display_name").getAsString()));
			entry.addProperty("relationship",
				resumePartial ? "resume_partial" : (outlinedHelper ? "outlined_helper" : "async_related"));
			relationships.add(entry);
		}
		return relationships;
	}

	protected void addSwiftCodeCandidates(JsonArray codeCandidates, Set<String> seenCodeCandidateKeys,
			String typeName, String stableAlias, String role, Address sourceAddress, String rawName) {
		if (typeName == null || typeName.isEmpty() || sourceAddress == null) {
			return;
		}
		ReferenceIterator iterator = currentProgram.getReferenceManager().getReferencesTo(sourceAddress);
		while (iterator.hasNext()) {
			Reference reference = iterator.next();
			Address fromAddress = reference.getFromAddress();
			Function function = getFunctionContaining(fromAddress);
			Function canonical = function == null ? null : resolveCanonicalFunction(function);
			Instruction instruction = currentProgram.getListing().getInstructionContaining(fromAddress);
			MemoryBlock candidateBlock = currentProgram.getMemory().getBlock(fromAddress);
			boolean executable = candidateBlock != null && candidateBlock.isExecute();
			if (function == null && instruction == null && !executable) {
				continue;
			}
			Address candidate = canonical != null ? canonical.getEntryPoint() :
				instruction != null ? instruction.getAddress() : fromAddress;
			String candidateAddress = String.valueOf(candidate);
			String key = typeName + "|" + role + "|" + stableAlias + "|" + candidateAddress;
			if (!seenCodeCandidateKeys.add(key)) {
				continue;
			}
			JsonObject entry = new JsonObject();
			entry.addProperty("type_name", typeName);
			entry.addProperty("stable_alias", stableAlias);
			entry.addProperty("role", role);
			entry.addProperty("source_address", String.valueOf(sourceAddress));
			entry.addProperty("source_name", rawName);
			entry.addProperty("xref_from", String.valueOf(fromAddress));
			entry.addProperty("ref_type", String.valueOf(reference.getReferenceType()));
			entry.addProperty("candidate_address", candidateAddress);
			entry.addProperty("candidate_block",
				candidateBlock == null ? "" : empty(candidateBlock.getName()));
			entry.addProperty("candidate_executable", executable);
			if (function != null) {
				entry.addProperty("function_address", String.valueOf(function.getEntryPoint()));
				entry.addProperty("function_name", function.getName());
			}
			if (instruction != null) {
				entry.addProperty("instruction_address", String.valueOf(instruction.getAddress()));
				entry.addProperty("instruction", instruction.toString());
			}
			if (canonical != null) {
				entry.addProperty("canonical_address", String.valueOf(canonical.getEntryPoint()));
				entry.addProperty("canonical_name", canonical.getName());
				entry.add("implementation_chain", buildImplementationChain(function));
			}
			codeCandidates.add(entry);
		}
	}

	protected JsonObject swiftFunctionToJson(Function function) {
		JsonObject object = swiftSymbolToJson(function.getName(),
			String.valueOf(function.getEntryPoint()), "function", function);
		object.addProperty("thunk", function.isThunk());
		Function canonical = resolveCanonicalFunction(function);
		JsonArray chain = buildImplementationChain(function);
		object.add("implementation_chain", chain);
		if (canonical != null) {
			object.addProperty("canonical_address", String.valueOf(canonical.getEntryPoint()));
			object.addProperty("canonical_name", canonical.getName());
			String demangledCanonical = demangleSwiftName(canonical.getName());
			if (!demangledCanonical.isEmpty() && !demangledCanonical.equals(canonical.getName())) {
				object.addProperty("canonical_demangled", demangledCanonical);
			}
		}
		else {
			object.addProperty("canonical_address", String.valueOf(function.getEntryPoint()));
			object.addProperty("canonical_name", function.getName());
		}
		if (function.isThunk()) {
			Function thunkTarget = function.getThunkedFunction(true);
			if (thunkTarget != null) {
				object.addProperty("thunk_target_address", String.valueOf(thunkTarget.getEntryPoint()));
				object.addProperty("thunk_target_name", thunkTarget.getName());
				String demangledTarget = demangleSwiftName(thunkTarget.getName());
				if (!demangledTarget.isEmpty() && !demangledTarget.equals(thunkTarget.getName())) {
					object.addProperty("thunk_target_demangled", demangledTarget);
				}
			}
		}
		return object;
	}

	protected JsonObject swiftSymbolToJson(String name, String address, String source,
			Function function) {
		JsonObject object = new JsonObject();
		object.addProperty("name", name);
		object.addProperty("raw_name", name);
		object.addProperty("address", address);
		object.addProperty("source", source);
		String demangled = demangleSwiftName(name);
		String display = demangled.isEmpty() ? name : demangled;
		object.addProperty("demangled", display);
		object.addProperty("display_name", display);
		object.addProperty("mangled", name.startsWith("$s") || name.startsWith("_$s"));
		object.addProperty("async_like", isSwiftAsyncLike(display));
		object.addProperty("metadata_accessor", isSwiftMetadataAccessor(display));
		object.addProperty("protocol_conformance_like", isSwiftProtocolConformanceLike(display));
		object.addProperty("dispatch_thunk", isSwiftDispatchThunk(display));
		object.addProperty("protocol_witness", isSwiftProtocolWitness(display));
		object.addProperty("outlined_helper", isSwiftOutlinedHelper(display));
		object.addProperty("resume_partial", isSwiftResumePartial(display));
		String typeName = extractSwiftTypeName(display, name);
		String memberName = extractSwiftMemberName(display, typeName, name);
		String objcBridgeName = extractObjcBridgeNameFromArtifact(name);
		object.addProperty("type_name", typeName);
		object.addProperty("member_name", memberName);
		object.addProperty("objc_bridge_name", objcBridgeName);
		object.addProperty("stable_alias",
			buildStableSwiftAlias(typeName, memberName, display, name));
		object.addProperty("symbol_kind", classifySwiftSymbolKind(display, memberName, name));
		if (function != null) {
			object.addProperty("signature", function.getPrototypeString(false, false));
			object.addProperty("is_thunk", function.isThunk());
		}
		else {
			Function resolved = findFunctionForAddress(address);
			if (resolved != null) {
				object.addProperty("function_address", String.valueOf(resolved.getEntryPoint()));
				object.addProperty("function_name", resolved.getName());
				object.addProperty("is_thunk", resolved.isThunk());
				Function canonical = resolveCanonicalFunction(resolved);
				object.add("implementation_chain", buildImplementationChain(resolved));
				if (canonical != null) {
					object.addProperty("canonical_address", String.valueOf(canonical.getEntryPoint()));
					object.addProperty("canonical_name", canonical.getName());
					String demangledCanonical = demangleSwiftName(canonical.getName());
					if (!demangledCanonical.isEmpty() &&
						!demangledCanonical.equals(canonical.getName())) {
						object.addProperty("canonical_demangled", demangledCanonical);
					}
				}
			}
		}
		if (!object.has("canonical_address")) {
			object.addProperty("canonical_address", address);
		}
		return object;
	}

	protected void classifySwiftJson(JsonObject symbolJson, Set<String> types,
			Set<String> protocolConformances, Set<String> metadataAccessors,
			Set<String> asyncEntrypoints, Set<String> typeDescriptors, Set<String> dispatchThunks,
			Set<String> protocolWitnesses, Set<String> outlinedHelpers) {
		String display = empty(symbolJson.get("display_name").getAsString());
		String typeName = empty(symbolJson.get("type_name").getAsString());
		String memberName = empty(symbolJson.get("member_name").getAsString());
		if (!typeName.isEmpty()) {
			types.add(typeName);
		}

		Matcher typeMatcher = SWIFT_TYPE_PATTERN.matcher(display);
		if (typeMatcher.find()) {
			String matchedTypeName = typeMatcher.group(1).trim();
			if (!matchedTypeName.isEmpty()) {
				types.add(matchedTypeName);
				metadataAccessors.add(display);
				typeDescriptors.add(matchedTypeName);
			}
		}
		Matcher protocolMatcher = SWIFT_PROTOCOL_PATTERN.matcher(display);
		if (protocolMatcher.find()) {
			String value = protocolMatcher.group(1).trim();
			if (!value.isEmpty()) {
				protocolConformances.add(value);
			}
		}
		if (isSwiftMetadataAccessor(display)) {
			metadataAccessors.add(display);
		}
		if (isSwiftAsyncLike(display)) {
			asyncEntrypoints.add(display);
			if (!memberName.isEmpty()) {
				asyncEntrypoints.add(buildStableSwiftAlias(typeName, memberName, display,
					empty(symbolJson.get("raw_name").getAsString())));
			}
		}
		if (isSwiftDispatchThunk(display)) {
			dispatchThunks.add(display);
		}
		if (isSwiftProtocolWitness(display)) {
			protocolWitnesses.add(display);
		}
		if (isSwiftOutlinedHelper(display)) {
			outlinedHelpers.add(display);
		}
	}

	protected void addSwiftAlias(JsonObject aliasMap, JsonArray aliases, JsonObject symbolJson) {
		String rawName = empty(symbolJson.get("raw_name").getAsString());
		String stableAlias = empty(symbolJson.get("stable_alias").getAsString());
		if (rawName.isEmpty() || stableAlias.isEmpty() || aliasMap.has(rawName)) {
			return;
		}
		aliasMap.addProperty(rawName, stableAlias);
		JsonObject alias = new JsonObject();
		alias.addProperty("raw_name", rawName);
		alias.addProperty("stable_alias", stableAlias);
		alias.addProperty("demangled", empty(symbolJson.get("display_name").getAsString()));
		alias.addProperty("type_name", empty(symbolJson.get("type_name").getAsString()));
		alias.addProperty("member_name", empty(symbolJson.get("member_name").getAsString()));
		aliases.add(alias);
	}

	protected JsonObject buildSwiftMetadataSectionSummary() {
		JsonObject sections = new JsonObject();
		for (String sectionName : SWIFT_METADATA_SECTION_NAMES) {
			MemoryBlock block = findBlockByName(sectionName);
			JsonObject sectionJson = new JsonObject();
			if (block == null) {
				sectionJson.addProperty("present", false);
				sections.add(sectionName, sectionJson);
				continue;
			}
			sectionJson.addProperty("present", true);
			sectionJson.addProperty("start", String.valueOf(block.getStart()));
			sectionJson.addProperty("end", String.valueOf(block.getEnd()));
			sectionJson.addProperty("size", block.getSize());
			JsonArray strings = new JsonArray();
			JsonArray demangledStrings = new JsonArray();
			for (String value : extractPrintableStringsFromBlock(block, 3)) {
				strings.add(value);
				String demangled = demangleSwiftMetadataString(value);
				if (!demangled.isEmpty() && !demangled.equals(value)) {
					demangledStrings.add(demangled);
				}
			}
			sectionJson.addProperty("string_count", strings.size());
			sectionJson.add("strings", strings);
			sectionJson.add("demangled_strings", demangledStrings);
			sections.add(sectionName, sectionJson);
		}
		return sections;
	}

	protected void ingestSwiftSectionStrings(JsonObject sections, Set<String> types,
			Set<String> protocolConformances) {
		ingestSwiftSectionStringsForName(sections, "__swift5_types", types);
		ingestSwiftSectionStringsForName(sections, "__swift5_typeref", types);
		ingestSwiftSectionStringsForName(sections, "__swift5_proto", protocolConformances);
		ingestSwiftSectionStringsForName(sections, "__swift5_assocty", protocolConformances);
	}

	protected void ingestSwiftSectionStringsForName(JsonObject sections, String sectionName,
			Set<String> output) {
		JsonObject section = sections.getAsJsonObject(sectionName);
		if (section == null) {
			return;
		}
		JsonArray values = section.has("demangled_strings") &&
			section.getAsJsonArray("demangled_strings").size() > 0 ?
				section.getAsJsonArray("demangled_strings") : section.getAsJsonArray("strings");
		if (values == null) {
			return;
		}
		for (JsonElement element : values) {
			String value = element.getAsString().trim();
			if (value.isEmpty()) {
				continue;
			}
			if (looksLikeSwiftTypeName(value) || looksLikeSwiftProtocolName(value)) {
				output.add(value);
			}
		}
	}

	protected MemoryBlock findBlockByName(String name) {
		for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
			if (name.equals(empty(block.getName()))) {
				return block;
			}
		}
		return null;
	}

	protected Set<String> extractPrintableStringsFromBlock(MemoryBlock block, int minLength) {
		Set<String> values = new LinkedHashSet<>();
		if (block == null || block.getSize() <= 0) {
			return values;
		}
		long size = Math.min(block.getSize(), 1024L * 1024L * 8L);
		if (size <= 0) {
			return values;
		}
		byte[] bytes = new byte[(int) size];
		try {
			int read = currentProgram.getMemory().getBytes(block.getStart(), bytes);
			if (read <= 0) {
				return values;
			}
			StringBuilder builder = new StringBuilder();
			for (int i = 0; i < read; i++) {
				int value = bytes[i] & 0xff;
				if (value >= 0x20 && value <= 0x7e) {
					builder.append((char) value);
				}
				else {
					if (builder.length() >= minLength) {
						values.add(builder.toString());
					}
					builder.setLength(0);
				}
			}
			if (builder.length() >= minLength) {
				values.add(builder.toString());
			}
		}
		catch (Exception ignored) {
			return values;
		}
		return values;
	}

}
