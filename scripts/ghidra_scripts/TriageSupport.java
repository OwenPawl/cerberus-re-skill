import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.util.DefinedStringIterator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public final class TriageSupport {

	public static final Gson GSON =
		new GsonBuilder().disableHtmlEscaping().setPrettyPrinting().create();

	public static class Manifest {
		List<CategoryRule> entrypoint_categories = new ArrayList<>();
		List<CategoryRule> sink_categories = new ArrayList<>();
		List<String> parser_terms = new ArrayList<>();
	}

	public static class CategoryRule {
		String id;
		String label;
		List<String> function_name_terms = new ArrayList<>();
		List<String> namespace_terms = new ArrayList<>();
		List<String> import_terms = new ArrayList<>();
		List<String> symbol_terms = new ArrayList<>();
		List<String> string_terms = new ArrayList<>();
		List<String> selector_terms = new ArrayList<>();
		boolean exported_only;
		boolean external_entry_only;
		int score_bonus;
	}

	public static class MatchEvidence {
		Set<String> function_name = new TreeSet<>();
		Set<String> namespace = new TreeSet<>();
		Set<String> imports = new TreeSet<>();
		Set<String> symbols = new TreeSet<>();
		Set<String> strings = new TreeSet<>();
		Set<String> selectors = new TreeSet<>();
		boolean exported;
		boolean external_entry_point;

		boolean isEmpty() {
			return function_name.isEmpty() && namespace.isEmpty() && imports.isEmpty() &&
				symbols.isEmpty() && strings.isEmpty() && selectors.isEmpty() && !exported &&
				!external_entry_point;
		}
	}

	public static class CategoryMatch {
		String categoryId;
		String label;
		int score;
		MatchEvidence evidence = new MatchEvidence();
	}

	public static class FunctionFacts {
		Function function;
		String functionKey;
		String name;
		String namespace;
		String signature;
		String address;
		boolean externalEntryPoint;
		boolean exportedSymbol;
		boolean thunk;
		Set<String> symbolNames = new TreeSet<>();
		Set<String> importedApis = new TreeSet<>();
		Set<String> externalCalls = new TreeSet<>();
		Set<String> referencedSymbols = new TreeSet<>();
		Set<String> referencedStrings = new TreeSet<>();
		Set<String> referencedSelectors = new TreeSet<>();
		Set<String> callerKeys = new TreeSet<>();
		Set<String> calleeKeys = new TreeSet<>();
	}

	public static class ProgramIndex {
		Program program;
		Map<String, FunctionFacts> byKey = new LinkedHashMap<>();
		Map<Address, FunctionFacts> byAddress = new LinkedHashMap<>();
	}

	private TriageSupport() {
	}

	public static Manifest loadManifest(String path) throws IOException {
		try (Reader reader =
			new InputStreamReader(new FileInputStream(path), StandardCharsets.UTF_8)) {
			Manifest manifest = GSON.fromJson(reader, Manifest.class);
			if (manifest == null) {
				manifest = new Manifest();
			}
			normalizeManifest(manifest);
			return manifest;
		}
	}

	private static void normalizeManifest(Manifest manifest) {
		manifest.parser_terms = normalizeTerms(manifest.parser_terms);
		manifest.entrypoint_categories = normalizeRules(manifest.entrypoint_categories);
		manifest.sink_categories = normalizeRules(manifest.sink_categories);
	}

	private static List<CategoryRule> normalizeRules(List<CategoryRule> rules) {
		if (rules == null) {
			return new ArrayList<>();
		}
		for (CategoryRule rule : rules) {
			if (rule.id == null) {
				rule.id = "unnamed-category";
			}
			if (rule.label == null || rule.label.isEmpty()) {
				rule.label = rule.id;
			}
			rule.function_name_terms = normalizeTerms(rule.function_name_terms);
			rule.namespace_terms = normalizeTerms(rule.namespace_terms);
			rule.import_terms = normalizeTerms(rule.import_terms);
			rule.symbol_terms = normalizeTerms(rule.symbol_terms);
			rule.string_terms = normalizeTerms(rule.string_terms);
			rule.selector_terms = normalizeTerms(rule.selector_terms);
		}
		return rules;
	}

	private static List<String> normalizeTerms(List<String> source) {
		List<String> normalized = new ArrayList<>();
		if (source == null) {
			return normalized;
		}
		for (String value : source) {
			if (value == null) {
				continue;
			}
			String trimmed = value.trim().toLowerCase();
			if (!trimmed.isEmpty()) {
				normalized.add(trimmed);
			}
		}
		return normalized;
	}

	public static ProgramIndex buildProgramIndex(Program program, TaskMonitor monitor)
			throws CancelledException {
		ProgramIndex index = new ProgramIndex();
		index.program = program;
		SymbolTable symbolTable = program.getSymbolTable();
		for (FunctionIterator iterator = program.getFunctionManager().getFunctions(true); iterator
				.hasNext();) {
			monitor.checkCancelled();
			Function function = iterator.next();
			if (function == null || function.isExternal()) {
				continue;
			}
			FunctionFacts facts = new FunctionFacts();
			facts.function = function;
			facts.functionKey = function.getEntryPoint().toString();
			facts.name = function.getName();
			facts.namespace = namespacePath(function.getParentNamespace());
			facts.signature = function.getPrototypeString(false, false);
			facts.address = function.getEntryPoint().toString();
			facts.thunk = function.isThunk();
			facts.externalEntryPoint = symbolTable.isExternalEntryPoint(function.getEntryPoint());
			facts.exportedSymbol = facts.externalEntryPoint;
			Symbol primary = symbolTable.getPrimarySymbol(function.getEntryPoint());
			if (primary != null) {
				facts.symbolNames.add(primary.getName());
				if (primary.isExternalEntryPoint()) {
					facts.exportedSymbol = true;
				}
			}
			facts.symbolNames.add(function.getName());
			index.byKey.put(facts.functionKey, facts);
			index.byAddress.put(function.getEntryPoint(), facts);
		}

		for (FunctionFacts facts : index.byKey.values()) {
			monitor.checkCancelled();
			for (Function callee : facts.function.getCalledFunctions(monitor)) {
				if (callee == null) {
					continue;
				}
				if (callee.isExternal()) {
					facts.importedApis.add(callee.getName());
					facts.externalCalls.add(callee.getName());
					continue;
				}
				String externalThunkName = externalThunkTargetName(callee);
				if (externalThunkName != null && !externalThunkName.isEmpty()) {
					facts.importedApis.add(externalThunkName);
					facts.externalCalls.add(externalThunkName);
				}
				FunctionFacts calleeFacts = index.byAddress.get(callee.getEntryPoint());
				if (calleeFacts != null) {
					facts.calleeKeys.add(calleeFacts.functionKey);
				}
			}
			for (Function caller : facts.function.getCallingFunctions(monitor)) {
				if (caller == null || caller.isExternal()) {
					continue;
				}
				FunctionFacts callerFacts = index.byAddress.get(caller.getEntryPoint());
				if (callerFacts != null) {
					facts.callerKeys.add(callerFacts.functionKey);
				}
			}
		}

		scanStringReferences(index, monitor);
		scanInstructionReferences(index, monitor);
		return index;
	}

	private static String externalThunkTargetName(Function function) {
		if (function == null || !function.isThunk()) {
			return "";
		}
		Function target = function.getThunkedFunction(true);
		if (target != null && target.isExternal()) {
			return target.getName();
		}
		return "";
	}

	private static void scanStringReferences(ProgramIndex index, TaskMonitor monitor)
			throws CancelledException {
		DefinedStringIterator iterator = DefinedStringIterator.forProgram(index.program, null);
		while (iterator.hasNext()) {
			monitor.checkCancelled();
			Data data = iterator.next();
			StringDataInstance stringData = StringDataInstance.getStringDataInstance(data);
			if (stringData == null) {
				continue;
			}
			String value = stringData.getStringValue();
			if (value == null || value.isEmpty()) {
				continue;
			}
			String trimmedValue = trimEvidence(value);
			MemoryBlock block = index.program.getMemory().getBlock(data.getAddress());
			String blockName = block == null ? "" : block.getName().toLowerCase();
			boolean selectorLike = blockName.contains("objc_methname") || value.contains(":");
			ReferenceIterator refs = index.program.getReferenceManager().getReferencesTo(data.getAddress());
			while (refs.hasNext()) {
				Reference ref = refs.next();
				FunctionFacts facts = functionContaining(index, ref.getFromAddress());
				if (facts == null) {
					continue;
				}
				facts.referencedStrings.add(trimmedValue);
				if (selectorLike) {
					facts.referencedSelectors.add(trimmedValue);
				}
			}
		}
	}

	private static void scanInstructionReferences(ProgramIndex index, TaskMonitor monitor)
			throws CancelledException {
		Listing listing = index.program.getListing();
		SymbolTable symbolTable = index.program.getSymbolTable();
		for (FunctionFacts facts : index.byKey.values()) {
			monitor.checkCancelled();
			InstructionIterator instructions =
				listing.getInstructions(facts.function.getBody(), true);
			while (instructions.hasNext()) {
				Instruction instruction = instructions.next();
				Reference[] refs = instruction.getReferencesFrom();
				for (Reference ref : refs) {
					Address toAddress = ref.getToAddress();
					if (toAddress == null) {
						continue;
					}
					Symbol primary = symbolTable.getPrimarySymbol(toAddress);
					if (primary == null) {
						continue;
					}
					String name = primary.getName();
					if (name == null || name.isEmpty()) {
						continue;
					}
					facts.referencedSymbols.add(name);
					if (name.startsWith("selRef_")) {
						facts.referencedSelectors.add(name.substring("selRef_".length()));
					}
				}
			}
		}
	}

	public static FunctionFacts functionContaining(ProgramIndex index, Address address) {
		if (address == null) {
			return null;
		}
		Function function = index.program.getFunctionManager().getFunctionContaining(address);
		if (function == null) {
			function = index.program.getFunctionManager().getFunctionAt(address);
		}
		if (function == null) {
			return null;
		}
		return index.byAddress.get(function.getEntryPoint());
	}

	public static List<CategoryMatch> findEntrypoints(FunctionFacts facts, Manifest manifest) {
		return matchRules(facts, manifest.entrypoint_categories);
	}

	public static List<CategoryMatch> findSinks(FunctionFacts facts, Manifest manifest) {
		return matchRules(facts, manifest.sink_categories);
	}

	public static List<CategoryMatch> matchRules(FunctionFacts facts, List<CategoryRule> rules) {
		List<CategoryMatch> matches = new ArrayList<>();
		for (CategoryRule rule : rules) {
			CategoryMatch match = matchRule(facts, rule);
			if (match != null) {
				matches.add(match);
			}
		}
		Collections.sort(matches, new Comparator<CategoryMatch>() {
			@Override
			public int compare(CategoryMatch left, CategoryMatch right) {
				return Integer.compare(right.score, left.score);
			}
		});
		return matches;
	}

	private static CategoryMatch matchRule(FunctionFacts facts, CategoryRule rule) {
		MatchEvidence evidence = new MatchEvidence();
		addSingleStringMatches(evidence.function_name, facts.name, rule.function_name_terms);
		addSingleStringMatches(evidence.namespace, facts.namespace, rule.namespace_terms);
		addCollectionMatches(evidence.imports, facts.importedApis, rule.import_terms);
		addCollectionMatches(evidence.symbols, facts.symbolNames, rule.symbol_terms);
		addCollectionMatches(evidence.symbols, facts.referencedSymbols, rule.symbol_terms);
		addCollectionMatches(evidence.strings, facts.referencedStrings, rule.string_terms);
		addCollectionMatches(evidence.selectors, facts.referencedSelectors, rule.selector_terms);

		if (rule.exported_only && facts.exportedSymbol) {
			evidence.exported = true;
		}
		if (rule.external_entry_only && facts.externalEntryPoint) {
			evidence.external_entry_point = true;
		}
		if (!rule.exported_only && facts.exportedSymbol && "framework-exported-api".equals(rule.id)) {
			evidence.exported = true;
		}

		if (evidence.isEmpty()) {
			return null;
		}

		CategoryMatch match = new CategoryMatch();
		match.categoryId = rule.id;
		match.label = rule.label;
		match.evidence = evidence;
		match.score = scoreMatch(evidence, rule.score_bonus);
		return match;
	}

	private static int scoreMatch(MatchEvidence evidence, int bonus) {
		int score = bonus;
		score += evidence.function_name.size() * 10;
		score += evidence.namespace.size() * 8;
		score += evidence.imports.size() * 12;
		score += evidence.symbols.size() * 6;
		score += evidence.strings.size() * 4;
		score += evidence.selectors.size() * 12;
		if (evidence.exported) {
			score += 18;
		}
		if (evidence.external_entry_point) {
			score += 20;
		}
		return score;
	}

	private static void addSingleStringMatches(Set<String> hits, String haystack, List<String> terms) {
		if (haystack == null || haystack.isEmpty()) {
			return;
		}
		String lower = haystack.toLowerCase();
		for (String term : terms) {
			if (lower.contains(term)) {
				hits.add(trimEvidence(haystack));
				return;
			}
		}
	}

	private static void addCollectionMatches(Set<String> hits, Collection<String> values,
			List<String> terms) {
		for (String value : values) {
			if (value == null || value.isEmpty()) {
				continue;
			}
			String lower = value.toLowerCase();
			for (String term : terms) {
				if (lower.contains(term)) {
					hits.add(trimEvidence(value));
					break;
				}
			}
		}
	}

	public static boolean hasParserLikeEvidence(FunctionFacts facts, Manifest manifest) {
		return containsAnyTerm(facts.name, manifest.parser_terms) ||
			containsAnyTerm(facts.namespace, manifest.parser_terms) ||
			containsAnyTerm(facts.importedApis, manifest.parser_terms) ||
			containsAnyTerm(facts.referencedStrings, manifest.parser_terms) ||
			containsAnyTerm(facts.referencedSelectors, manifest.parser_terms) ||
			containsAnyTerm(facts.referencedSymbols, manifest.parser_terms);
	}

	private static boolean containsAnyTerm(String value, List<String> terms) {
		if (value == null || value.isEmpty()) {
			return false;
		}
		String lower = value.toLowerCase();
		for (String term : terms) {
			if (lower.contains(term)) {
				return true;
			}
		}
		return false;
	}

	private static boolean containsAnyTerm(Collection<String> values, List<String> terms) {
		for (String value : values) {
			if (containsAnyTerm(value, terms)) {
				return true;
			}
		}
		return false;
	}

	public static JsonObject functionToJson(ProgramIndex index, FunctionFacts facts, int sampleLimit) {
		JsonObject object = new JsonObject();
		object.addProperty("id", facts.functionKey);
		object.addProperty("kind", "function");
		object.addProperty("name", facts.name);
		object.addProperty("address", facts.address);
		object.addProperty("namespace", facts.namespace);
		object.addProperty("signature", facts.signature);
		object.addProperty("is_external", false);
		object.addProperty("is_thunk", facts.thunk);
		object.addProperty("external_entry_point", facts.externalEntryPoint);
		object.addProperty("exported_symbol", facts.exportedSymbol);
		object.addProperty("caller_count", facts.callerKeys.size());
		object.addProperty("callee_count", facts.calleeKeys.size());
		object.add("callers_sample", functionKeyArray(index, facts.callerKeys, sampleLimit));
		object.add("callees_sample", functionKeyArray(index, facts.calleeKeys, sampleLimit));
		object.add("imports_sample", toJsonArray(facts.importedApis, sampleLimit));
		object.add("external_calls_sample", toJsonArray(facts.externalCalls, sampleLimit));
		object.add("symbols_sample", toJsonArray(facts.referencedSymbols, sampleLimit));
		object.add("strings_sample", toJsonArray(facts.referencedStrings, sampleLimit));
		object.add("selectors_sample", toJsonArray(facts.referencedSelectors, sampleLimit));
		return object;
	}

	public static JsonObject evidenceToJson(MatchEvidence evidence) {
		JsonObject object = new JsonObject();
		object.add("function_name", toJsonArray(evidence.function_name, 20));
		object.add("namespace", toJsonArray(evidence.namespace, 20));
		object.add("imports", toJsonArray(evidence.imports, 20));
		object.add("symbols", toJsonArray(evidence.symbols, 20));
		object.add("strings", toJsonArray(evidence.strings, 20));
		object.add("selectors", toJsonArray(evidence.selectors, 20));
		object.addProperty("exported", evidence.exported);
		object.addProperty("external_entry_point", evidence.external_entry_point);
		return object;
	}

	private static JsonArray functionKeyArray(ProgramIndex index, Collection<String> keys,
			int sampleLimit) {
		JsonArray array = new JsonArray();
		int count = 0;
		for (String key : keys) {
			if (count >= sampleLimit) {
				break;
			}
			FunctionFacts facts = index.byKey.get(key);
			if (facts == null) {
				continue;
			}
			array.add(simpleFunctionLabel(facts));
			count++;
		}
		return array;
	}

	public static JsonArray toJsonArray(Collection<String> values, int limit) {
		JsonArray array = new JsonArray();
		int count = 0;
		for (String value : values) {
			if (count >= limit) {
				break;
			}
			array.add(value);
			count++;
		}
		return array;
	}

	public static String simpleFunctionLabel(FunctionFacts facts) {
		return facts.name + " @ " + facts.address;
	}

	public static String namespacePath(Namespace namespace) {
		if (namespace == null) {
			return "";
		}
		List<String> parts = new ArrayList<>();
		Namespace current = namespace;
		while (current != null && !current.isGlobal()) {
			parts.add(0, current.getName());
			current = current.getParentNamespace();
		}
		StringBuilder builder = new StringBuilder();
		for (int index = 0; index < parts.size(); index++) {
			if (index > 0) {
				builder.append("::");
			}
			builder.append(parts.get(index));
		}
		return builder.toString();
	}

	public static void writeJson(File file, JsonElement payload) throws IOException {
		File parent = file.getParentFile();
		if (parent != null && !parent.exists() && !parent.mkdirs()) {
			throw new IOException("failed to create directory " + parent);
		}
		try (Writer writer =
			new OutputStreamWriter(new FileOutputStream(file), StandardCharsets.UTF_8)) {
			GSON.toJson(payload, writer);
		}
	}

	public static void writeText(File file, String contents) throws IOException {
		File parent = file.getParentFile();
		if (parent != null && !parent.exists() && !parent.mkdirs()) {
			throw new IOException("failed to create directory " + parent);
		}
		try (Writer writer =
			new OutputStreamWriter(new FileOutputStream(file), StandardCharsets.UTF_8)) {
			writer.write(contents);
		}
	}

	public static String trimEvidence(String value) {
		if (value == null) {
			return "";
		}
		String trimmed = value.replace('\n', ' ').replace('\r', ' ').trim();
		if (trimmed.length() > 160) {
			return trimmed.substring(0, 157) + "...";
		}
		return trimmed;
	}

	public static String normalizeFunctionLookupValue(String value) {
		if (value == null) {
			return "";
		}
		String normalized = value.trim().replaceAll("\\s+", " ");
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

	public static boolean matchesFunctionLookup(String candidate, String query, boolean exact) {
		String normalizedCandidate = normalizeFunctionLookupValue(candidate).toLowerCase();
		String normalizedQuery = normalizeFunctionLookupValue(query).toLowerCase();
		if (normalizedCandidate.isEmpty() || normalizedQuery.isEmpty()) {
			return false;
		}
		return exact ? normalizedCandidate.equals(normalizedQuery) :
			normalizedCandidate.contains(normalizedQuery);
	}

	private static List<String> functionLookupCandidates(FunctionFacts facts) {
		List<String> candidates = new ArrayList<>();
		candidates.add(facts.name);
		if (facts.namespace == null || facts.namespace.isEmpty() ||
			facts.name.startsWith("-[") || facts.name.startsWith("+[")) {
			return candidates;
		}
		String owner = facts.namespace;
		int namespaceSeparator = owner.lastIndexOf("::");
		if (namespaceSeparator >= 0) {
			owner = owner.substring(namespaceSeparator + 2);
		}
		if (!owner.isEmpty()) {
			// Owner plus selector is enough for lookup, but does not prove method polarity.
			candidates.add("-[" + owner + " " + facts.name + "]");
			candidates.add("+[" + owner + " " + facts.name + "]");
		}
		return candidates;
	}

	public static Function resolveFunction(ProgramIndex index, String addressArg, String functionArg) {
		if (addressArg != null && !addressArg.isEmpty()) {
			try {
				Address address = index.program.getAddressFactory().getDefaultAddressSpace()
					.getAddress(addressArg.replace("0x", ""));
				FunctionFacts facts = functionContaining(index, address);
				if (facts != null) {
					return facts.function;
				}
				return index.program.getFunctionManager().getFunctionAt(address);
			}
			catch (Exception ignored) {
				// fall through to function name resolution
			}
		}
		if (functionArg == null || functionArg.isEmpty()) {
			return null;
		}
		Function exact = null;
		Function normalizedExact = null;
		Function caseInsensitive = null;
		Function contains = null;
		String target = functionArg.toLowerCase();
		String normalizedTarget = normalizeFunctionLookupValue(functionArg).toLowerCase();
		for (FunctionFacts facts : index.byKey.values()) {
			for (String name : functionLookupCandidates(facts)) {
				if (name.equals(functionArg)) {
					exact = facts.function;
					break;
				}
				if (normalizedExact == null &&
					normalizeFunctionLookupValue(name).toLowerCase().equals(normalizedTarget)) {
					normalizedExact = facts.function;
				}
				if (caseInsensitive == null && name.toLowerCase().equals(target)) {
					caseInsensitive = facts.function;
				}
				if (contains == null && matchesFunctionLookup(name, functionArg, false)) {
					contains = facts.function;
				}
			}
			if (exact != null) {
				break;
			}
		}
		return exact != null ? exact :
			normalizedExact != null ? normalizedExact :
				caseInsensitive != null ? caseInsensitive : contains;
	}

	public static String safeSlug(String raw) {
		if (raw == null || raw.isEmpty()) {
			return "target";
		}
		String value = raw;
		int dotIndex = value.lastIndexOf('.');
		if (dotIndex > 0) {
			value = value.substring(0, dotIndex);
		}
		value = value.replaceAll("[^A-Za-z0-9._-]+", "_");
		value = value.replaceAll("_+", "_");
		value = value.replaceAll("^_+", "");
		value = value.replaceAll("_+$", "");
		if (value.isEmpty()) {
			return "target";
		}
		return value;
	}

	public static String sourceType(SourceType sourceType) {
		return sourceType == null ? "" : sourceType.toString();
	}
}
