/* ###
 * IP: GHIDRA
 */
//@category Analysis

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;

public class ClassifySmallFunctions extends GhidraScript {

	private final Gson gson = new GsonBuilder().disableHtmlEscaping().setPrettyPrinting().create();

	@Override
	protected void run() throws Exception {
		Map<String, String> args = parseArgs();
		String outputPath = requireArg(args, "output");
		int maxBytes = parseIntArg(args, "max_bytes", 64);
		boolean dryRun = parseBoolArg(args, "dry_run", true);
		boolean includeNamed = parseBoolArg(args, "include_named", false);
		boolean inlineArcHelpers = parseBoolArg(args, "inline_arc_helpers", !dryRun);
		Set<String> categories = parseCategories(args.get("categories"));

		JsonObject payload = new JsonObject();
		payload.addProperty("program_name", currentProgram.getName());
		payload.addProperty("max_bytes", maxBytes);
		payload.addProperty("dry_run", dryRun);
		payload.addProperty("include_named", includeNamed);

		JsonObject counts = new JsonObject();
		JsonArray results = new JsonArray();
		int candidates = 0;
		int applied = 0;

		for (FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true); iterator
				.hasNext();) {
			if (monitor.isCancelled()) {
				break;
			}
			Function function = iterator.next();
			if (function.isExternal()) {
				continue;
			}
			long bodySize = function.getBody().getNumAddresses();
			if (bodySize > maxBytes) {
				continue;
			}
			if (!includeNamed && !function.getName().startsWith("FUN_")) {
				continue;
			}
			candidates++;
			Classification classification = classify(function, (int) bodySize);
			if (classification.category == null || !categories.contains(classification.category)) {
				continue;
			}
			increment(counts, classification.category);
			JsonObject item = classification.toJson(function, bodySize);
			if (!dryRun) {
				boolean renamed = applyClassification(function, classification);
				boolean inlined = false;
				if (inlineArcHelpers && "arc_helper".equals(classification.category)) {
					function.setInline(true);
					inlined = true;
				}
				item.addProperty("renamed", renamed);
				item.addProperty("inlined", inlined);
				applied++;
			}
			results.add(item);
		}

		payload.addProperty("candidate_count", candidates);
		payload.addProperty("classified_count", results.size());
		payload.addProperty("applied_count", applied);
		payload.add("category_counts", counts);
		payload.add("functions", results);

		writeJson(new File(outputPath), payload);
		println("Wrote " + outputPath);
	}

	private Classification classify(Function function, int bodySize) {
		Classification c = new Classification();
		InstructionIterator iterator =
			currentProgram.getListing().getInstructions(function.getBody(), true);
		while (iterator.hasNext() && !monitor.isCancelled()) {
			Instruction instruction = iterator.next();
			String mnemonic = instruction.getMnemonicString().toLowerCase(Locale.ROOT);
			c.mnemonics.add(mnemonic);
			if (isReturn(mnemonic)) {
				c.hasReturn = true;
			}
			if (isBranch(mnemonic)) {
				c.branchCount++;
			}
			for (Reference ref : instruction.getReferencesFrom()) {
				if (!ref.getReferenceType().isFlow()) {
					continue;
				}
				Address to = ref.getToAddress();
				if (to == null) {
					continue;
				}
				Function target = currentProgram.getFunctionManager().getFunctionAt(to);
				String targetName = target == null ? "" : target.getName();
				c.flowTargets.add(String.valueOf(to));
				if (isCallMnemonic(mnemonic)) {
					c.callTargets.add(targetName.isEmpty() ? String.valueOf(to) : targetName);
				}
			}
		}

		int callerCount = function.getCallingFunctions(monitor).size();
		c.callerCount = callerCount;
		if (c.mnemonics.isEmpty()) {
			c.category = "empty";
		}
		else if (callerCount == 0 && c.mnemonics.size() <= 2 && c.hasReturn) {
			c.category = "dead_stub";
		}
		else if (!c.callTargets.isEmpty() && allRuntimeMemoryHelpers(c.callTargets)) {
			c.category = "arc_helper";
		}
		else if (c.callTargets.size() == 1 && c.hasReturn) {
			c.category = "callwrap";
		}
		else if (c.callTargets.size() == 1 && !c.hasReturn && c.branchCount > 0) {
			c.category = "authstub_alias";
		}
		else if (containsObjcMsgSend(c.callTargets) && callerCount <= 1) {
			c.category = "objc_trampoline";
		}
		else if (bodySize <= 32 && looksLikeGlobalLoad(c.mnemonics)) {
			c.category = "loadglobal";
		}
		else if (bodySize <= 16) {
			c.category = "tiny_helper";
		}
		else {
			c.category = "small_helper";
		}
		c.suggestedName = suggestedName(function, c);
		return c;
	}

	private boolean applyClassification(Function function, Classification classification) {
		String name = classification.suggestedName;
		try {
			function.setName(name, SourceType.ANALYSIS);
			return true;
		}
		catch (Exception e) {
			println("WARNING: could not rename " + function.getName() + " to " + name + ": " +
				e.getMessage());
			return false;
		}
	}

	private String suggestedName(Function function, Classification classification) {
		String suffix = String.valueOf(function.getEntryPoint()).replace(':', '_');
		String target = classification.callTargets.isEmpty() ? "" : classification.callTargets.get(0);
		target = sanitize(target);
		if (!target.isEmpty() && ("callwrap".equals(classification.category) ||
			"authstub_alias".equals(classification.category))) {
			return "classified$" + classification.category + "$" + target + "$" + suffix;
		}
		return "classified$" + classification.category + "$" + suffix;
	}

	private String sanitize(String value) {
		if (value == null) {
			return "";
		}
		String cleaned = value.replaceAll("[^A-Za-z0-9_$]+", "_");
		if (cleaned.length() > 96) {
			return cleaned.substring(0, 96);
		}
		return cleaned;
	}

	private boolean isReturn(String mnemonic) {
		return mnemonic.equals("ret") || mnemonic.equals("retq") || mnemonic.equals("return");
	}

	private boolean isBranch(String mnemonic) {
		return mnemonic.equals("b") || mnemonic.equals("br") || mnemonic.equals("jmp") ||
			mnemonic.startsWith("b.") || mnemonic.startsWith("j");
	}

	private boolean isCallMnemonic(String mnemonic) {
		return mnemonic.equals("bl") || mnemonic.equals("blr") || mnemonic.equals("call") ||
			mnemonic.equals("callq");
	}

	private boolean allRuntimeMemoryHelpers(List<String> names) {
		for (String name : names) {
			String lower = name.toLowerCase(Locale.ROOT);
			if (!(lower.contains("retain") || lower.contains("release") ||
				lower.contains("autorelease") || lower.contains("swift_bridgeobjectretain"))) {
				return false;
			}
		}
		return !names.isEmpty();
	}

	private boolean containsObjcMsgSend(List<String> names) {
		for (String name : names) {
			if (name.contains("objc_msgSend")) {
				return true;
			}
		}
		return false;
	}

	private boolean looksLikeGlobalLoad(List<String> mnemonics) {
		if (mnemonics.isEmpty() || mnemonics.size() > 6) {
			return false;
		}
		boolean hasLoad = false;
		boolean hasAddress = false;
		for (String mnemonic : mnemonics) {
			if (mnemonic.equals("ldr") || mnemonic.equals("mov") || mnemonic.equals("lea")) {
				hasLoad = true;
			}
			if (mnemonic.equals("adrp") || mnemonic.equals("adr") || mnemonic.equals("add") ||
				mnemonic.equals("lea")) {
				hasAddress = true;
			}
		}
		return hasLoad && hasAddress;
	}

	private Set<String> parseCategories(String value) {
		Set<String> categories = new LinkedHashSet<>();
		if (value == null || value.trim().isEmpty() || "all".equalsIgnoreCase(value.trim())) {
			for (String category : new String[] {
				"empty", "dead_stub", "arc_helper", "callwrap", "authstub_alias",
				"objc_trampoline", "loadglobal", "tiny_helper", "small_helper"
			}) {
				categories.add(category);
			}
			return categories;
		}
		for (String part : value.split(",")) {
			String category = part.trim();
			if (!category.isEmpty()) {
				categories.add(category);
			}
		}
		return categories;
	}

	private Map<String, String> parseArgs() {
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

	private String requireArg(Map<String, String> args, String key) {
		String value = args.get(key);
		if (value == null || value.isEmpty()) {
			throw new IllegalArgumentException("missing required argument: " + key + "=...");
		}
		return value;
	}

	private int parseIntArg(Map<String, String> args, String key, int defaultValue) {
		String value = args.get(key);
		if (value == null || value.isEmpty()) {
			return defaultValue;
		}
		return Integer.decode(value);
	}

	private boolean parseBoolArg(Map<String, String> args, String key, boolean defaultValue) {
		String value = args.get(key);
		if (value == null || value.isEmpty()) {
			return defaultValue;
		}
		return value.equals("1") || value.equalsIgnoreCase("true") ||
			value.equalsIgnoreCase("yes") || value.equalsIgnoreCase("on");
	}

	private void increment(JsonObject counts, String key) {
		int current = counts.has(key) ? counts.get(key).getAsInt() : 0;
		counts.addProperty(key, current + 1);
	}

	private void writeJson(File file, JsonObject payload) throws Exception {
		File parent = file.getParentFile();
		if (parent != null && !parent.exists() && !parent.mkdirs()) {
			throw new IllegalStateException("failed to create " + parent);
		}
		try (Writer writer =
			new OutputStreamWriter(new FileOutputStream(file), StandardCharsets.UTF_8)) {
			gson.toJson(payload, writer);
		}
	}

	private static class Classification {
		String category;
		String suggestedName;
		int callerCount;
		int branchCount;
		boolean hasReturn;
		List<String> mnemonics = new ArrayList<>();
		List<String> callTargets = new ArrayList<>();
		List<String> flowTargets = new ArrayList<>();

		JsonObject toJson(Function function, long bodySize) {
			JsonObject item = new JsonObject();
			item.addProperty("name", function.getName());
			item.addProperty("entry", String.valueOf(function.getEntryPoint()));
			item.addProperty("body_size", bodySize);
			item.addProperty("caller_count", callerCount);
			item.addProperty("category", category);
			item.addProperty("suggested_name", suggestedName);
			JsonArray mnemonicArray = new JsonArray();
			for (String mnemonic : mnemonics) {
				mnemonicArray.add(mnemonic);
			}
			item.add("mnemonics", mnemonicArray);
			JsonArray callArray = new JsonArray();
			for (String call : callTargets) {
				callArray.add(call);
			}
			item.add("call_targets", callArray);
			JsonArray flowArray = new JsonArray();
			for (String flow : flowTargets) {
				flowArray.add(flow);
			}
			item.add("flow_targets", flowArray);
			return item;
		}
	}
}
