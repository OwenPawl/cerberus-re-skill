/* ###
 * IP: GHIDRA
 */
//@category Triage

import java.io.File;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;

public class ExportFunctionDossier extends GhidraScript {
	private static final Pattern ANONYMOUS_FUNCTION_REFERENCE =
		Pattern.compile("\\bFUN_([0-9a-fA-F]+)\\b");

	private static class LinearInstructionWindow {
		JsonObject context = new JsonObject();
		JsonArray warnings = new JsonArray();
		String text = "";
	}

	@Override
	protected void run() throws Exception {
		Map<String, String> args = parseArgs();
		String manifestPath = requireArg(args, "manifest");
		String outputDir = requireArg(args, "output_dir");
		int sampleLimit = parseIntArg(args, "sample_limit", 25);
		int linearInstructionLimit = parseIntArg(args, "linear_instruction_limit", 96);
		int timeout = parseIntArg(args, "timeout", 60);

		TriageSupport.Manifest manifest = TriageSupport.loadManifest(manifestPath);
		TriageSupport.ProgramIndex index =
			TriageSupport.buildProgramIndex(currentProgram, monitor);
		Function function =
			TriageSupport.resolveFunction(index, args.get("address"), args.get("function"));
		if (function == null) {
			throw new IllegalArgumentException("unable to resolve a target function");
		}
		TriageSupport.FunctionFacts facts = index.byAddress.get(function.getEntryPoint());
		if (facts == null) {
			throw new IllegalStateException("resolved function was not indexed");
		}

		File outdir = new File(outputDir);
		if (!outdir.exists() && !outdir.mkdirs()) {
			throw new IllegalStateException("failed to create " + outdir);
		}

		String decompiledText = decompile(function, timeout);
		List<TriageSupport.FunctionFacts> referencedAnonymousFunctions =
			findReferencedAnonymousFunctions(index, facts, decompiledText, sampleLimit);
		List<TriageSupport.FunctionFacts> referencedBlockInvokeFunctions =
			findReferencedBlockInvokeFunctions(index, facts, decompiledText, sampleLimit);
		LinearInstructionWindow linearWindow =
			buildLinearInstructionWindow(index, facts, linearInstructionLimit);
		JsonObject context = buildContext(index, manifest, facts, referencedAnonymousFunctions,
			referencedBlockInvokeFunctions, sampleLimit);
		context.add("linear_instruction_window", linearWindow.context);
		context.add("analysis_warnings", linearWindow.warnings);
		TriageSupport.writeJson(new File(outdir, "context.json"), context);
		TriageSupport.writeText(new File(outdir, "decompile.c"), decompiledText);
		TriageSupport.writeText(new File(outdir, "linear_instructions.txt"), linearWindow.text);
		TriageSupport.writeText(new File(outdir, "summary.md"),
			buildSummary(index, manifest, facts, referencedAnonymousFunctions,
				referencedBlockInvokeFunctions, linearWindow, sampleLimit));
		println("Wrote dossier to " + outdir.getAbsolutePath());
	}

	private JsonObject buildContext(TriageSupport.ProgramIndex index,
			TriageSupport.Manifest manifest, TriageSupport.FunctionFacts facts,
			List<TriageSupport.FunctionFacts> referencedAnonymousFunctions,
			List<TriageSupport.FunctionFacts> referencedBlockInvokeFunctions, int sampleLimit) {
		JsonObject object = new JsonObject();
		object.addProperty("program_name", currentProgram.getName());
		object.add("function", TriageSupport.functionToJson(index, facts, sampleLimit));

		JsonArray callers = new JsonArray();
		for (String callerKey : facts.callerKeys) {
			TriageSupport.FunctionFacts caller = index.byKey.get(callerKey);
			if (caller != null) {
				callers.add(TriageSupport.functionToJson(index, caller, sampleLimit));
			}
		}
		JsonArray callees = new JsonArray();
		for (String calleeKey : facts.calleeKeys) {
			TriageSupport.FunctionFacts callee = index.byKey.get(calleeKey);
			if (callee != null) {
				callees.add(TriageSupport.functionToJson(index, callee, sampleLimit));
			}
		}
		object.add("callers", callers);
		object.add("callees", callees);

		object.add("nearby_strings", TriageSupport.toJsonArray(facts.referencedStrings, sampleLimit));
		object.add("nearby_selectors",
			TriageSupport.toJsonArray(facts.referencedSelectors, sampleLimit));
		object.add("imported_apis", TriageSupport.toJsonArray(facts.importedApis, sampleLimit));
		object.add("referenced_anonymous_functions",
			functionFactsToJson(index, referencedAnonymousFunctions, sampleLimit));
		object.add("referenced_block_invoke_functions",
			functionFactsToJson(index, referencedBlockInvokeFunctions, sampleLimit));
		object.add("triage_tags", buildTagObject(facts, manifest));
		return object;
	}

	private List<TriageSupport.FunctionFacts> findReferencedAnonymousFunctions(
			TriageSupport.ProgramIndex index, TriageSupport.FunctionFacts target,
			String decompiledText, int sampleLimit) {
		List<TriageSupport.FunctionFacts> matches = new ArrayList<>();
		Set<String> seenAddresses = new LinkedHashSet<>();
		Matcher matcher = ANONYMOUS_FUNCTION_REFERENCE.matcher(decompiledText);
		while (matcher.find() && matches.size() < sampleLimit) {
			Function function = TriageSupport.resolveFunction(index, matcher.group(1), null);
			if (function == null) {
				continue;
			}
			TriageSupport.FunctionFacts candidate =
				index.byAddress.get(function.getEntryPoint());
			if (candidate == null || candidate.address.equals(target.address) ||
				!seenAddresses.add(candidate.address)) {
				continue;
			}
			matches.add(candidate);
		}
		return matches;
	}

	private List<TriageSupport.FunctionFacts> findReferencedBlockInvokeFunctions(
			TriageSupport.ProgramIndex index, TriageSupport.FunctionFacts target,
			String decompiledText, int sampleLimit) {
		List<TriageSupport.FunctionFacts> matches = new ArrayList<>();
		Set<String> seenAddresses = new LinkedHashSet<>();
		for (TriageSupport.FunctionFacts candidate : index.byKey.values()) {
			if (matches.size() >= sampleLimit) {
				break;
			}
			if (!candidate.name.contains("block_invoke") ||
				candidate.address.equals(target.address) ||
				!seenAddresses.add(candidate.address)) {
				continue;
			}
			// Ghidra prints symbol-backed block pointers as C-safe identifiers.
			String decompilerIdentifier = candidate.name.replaceAll("[^A-Za-z0-9_]", "_");
			if (decompiledText.contains(decompilerIdentifier)) {
				matches.add(candidate);
			}
		}
		return matches;
	}

	private JsonArray functionFactsToJson(TriageSupport.ProgramIndex index,
			Iterable<TriageSupport.FunctionFacts> functions, int sampleLimit) {
		JsonArray result = new JsonArray();
		int count = 0;
		for (TriageSupport.FunctionFacts facts : functions) {
			if (count >= sampleLimit) {
				break;
			}
			result.add(TriageSupport.functionToJson(index, facts, sampleLimit));
			count++;
		}
		return result;
	}

	private JsonObject buildTagObject(TriageSupport.FunctionFacts facts,
			TriageSupport.Manifest manifest) {
		JsonObject tags = new JsonObject();
		JsonArray entryTags = new JsonArray();
		for (TriageSupport.CategoryMatch match :
				TriageSupport.findEntrypoints(facts, manifest)) {
			entryTags.add(match.categoryId);
		}
		JsonArray sinkTags = new JsonArray();
		for (TriageSupport.CategoryMatch match : TriageSupport.findSinks(facts, manifest)) {
			sinkTags.add(match.categoryId);
		}
		tags.add("entrypoint_categories", entryTags);
		tags.add("sink_categories", sinkTags);
		tags.addProperty("parser_like", TriageSupport.hasParserLikeEvidence(facts, manifest));
		return tags;
	}

	private LinearInstructionWindow buildLinearInstructionWindow(TriageSupport.ProgramIndex index,
			TriageSupport.FunctionFacts facts, int instructionLimit) {
		LinearInstructionWindow window = new LinearInstructionWindow();
		JsonArray instructions = new JsonArray();
		int boundedLimit = Math.max(1, instructionLimit);
		MemoryBlock entryBlock =
			currentProgram.getMemory().getBlock(facts.function.getEntryPoint());
		boolean decodedOutsideBody = false;
		boolean unownedDecodedInstructionAfterBody = false;
		boolean reachedAnotherFunction = false;

		StringBuilder text = new StringBuilder();
		text.append("# Linear Instruction Window\n");
		text.append("# Program: ").append(currentProgram.getName()).append("\n");
		text.append("# Function: ").append(facts.name).append("\n");
		text.append("# Entry: ").append(facts.address).append("\n");
		text.append("# Note: instructions marked outside_body are decoded listing entries only; ");
		text.append("gaps may remain and these entries are not recovered function-body proof.\n\n");

		InstructionIterator iterator =
			currentProgram.getListing().getInstructions(facts.function.getEntryPoint(), true);
		int count = 0;
		while (iterator.hasNext() && count < boundedLimit && !monitor.isCancelled()) {
			Instruction instruction = iterator.next();
			MemoryBlock block = currentProgram.getMemory().getBlock(instruction.getAddress());
			if (entryBlock != null && block != entryBlock) {
				break;
			}
			boolean inBody = facts.function.getBody().contains(instruction.getAddress());
			if (!inBody) {
				decodedOutsideBody = true;
				Function instructionFunction =
					currentProgram.getFunctionManager().getFunctionAt(instruction.getAddress());
				if (instructionFunction != null &&
					!instructionFunction.equals(facts.function)) {
					reachedAnotherFunction = true;
				}
				else if (!reachedAnotherFunction) {
					unownedDecodedInstructionAfterBody = true;
				}
			}
			JsonObject record = new JsonObject();
			record.addProperty("address", instruction.getAddress().toString());
			record.addProperty("mnemonic", instruction.getMnemonicString());
			record.addProperty("text", instruction.toString());
			record.addProperty("in_current_function_body", inBody);
			instructions.add(record);
			text.append(inBody ? "body         " : "outside_body ")
				.append(instruction.getAddress()).append(": ")
				.append(instruction.toString()).append("\n");
			count++;
		}

		boolean suspiciousNoReturnAuthStub = hasNoReturnAuthStubCallee(index, facts);
		boolean possibleTruncation =
			suspiciousNoReturnAuthStub && unownedDecodedInstructionAfterBody;
		window.context.addProperty("instruction_limit", boundedLimit);
		window.context.addProperty("instruction_count", instructions.size());
		window.context.addProperty("decoded_outside_current_body", decodedOutsideBody);
		window.context.addProperty("unowned_decoded_instruction_after_body",
			unownedDecodedInstructionAfterBody);
		window.context.addProperty("has_no_return_authstub_callee", suspiciousNoReturnAuthStub);
		window.context.addProperty("possible_authstub_truncation", possibleTruncation);
		window.context.add("instructions", instructions);
		if (possibleTruncation) {
			window.warnings.add("Analyzed function body may be truncated at a non-returning auth-stub callee; inspect linear_instructions.txt and repair analysis before trusting decompile-only control flow.");
		}
		window.text = text.toString();
		return window;
	}

	private boolean hasNoReturnAuthStubCallee(TriageSupport.ProgramIndex index,
			TriageSupport.FunctionFacts facts) {
		for (String key : facts.calleeKeys) {
			TriageSupport.FunctionFacts callee = index.byKey.get(key);
			if (callee == null || !callee.function.hasNoReturn()) {
				continue;
			}
			MemoryBlock block =
				currentProgram.getMemory().getBlock(callee.function.getEntryPoint());
			String blockName = block == null ? "" : block.getName().toLowerCase();
			if (blockName.contains("auth_stub") || blockName.contains("authstub")) {
				return true;
			}
		}
		return false;
	}

	private String decompile(Function function, int timeout) throws Exception {
		DecompInterface decompiler = new DecompInterface();
		decompiler.openProgram(currentProgram);
		DecompileResults results = decompiler.decompileFunction(function, timeout, monitor);
		if (!results.decompileCompleted()) {
			throw new RuntimeException(
				"decompilation failed for " + function.getName() + ": " + results.getErrorMessage());
		}
		StringBuilder builder = new StringBuilder();
		builder.append("// Program: ").append(currentProgram.getName()).append("\n");
		builder.append("// Function: ").append(function.getName()).append("\n");
		builder.append("// Entry: ").append(function.getEntryPoint()).append("\n\n");
		builder.append(results.getDecompiledFunction().getC()).append("\n");
		return builder.toString();
	}

	private String buildSummary(TriageSupport.ProgramIndex index,
			TriageSupport.Manifest manifest, TriageSupport.FunctionFacts facts,
			List<TriageSupport.FunctionFacts> referencedAnonymousFunctions,
			List<TriageSupport.FunctionFacts> referencedBlockInvokeFunctions,
			LinearInstructionWindow linearWindow, int sampleLimit) {
		StringBuilder builder = new StringBuilder();
		builder.append("# Function Dossier\n\n");
		builder.append("- Program: `").append(currentProgram.getName()).append("`\n");
		builder.append("- Function: `").append(facts.name).append("`\n");
		builder.append("- Address: `").append(facts.address).append("`\n");
		if (!facts.namespace.isEmpty()) {
			builder.append("- Namespace: `").append(facts.namespace).append("`\n");
		}
		builder.append("- Callers: ").append(facts.callerKeys.size()).append("\n");
		builder.append("- Callees: ").append(facts.calleeKeys.size()).append("\n");
		builder.append("- Imported APIs: ").append(facts.importedApis.size()).append("\n\n");

		List<TriageSupport.CategoryMatch> entryMatches =
			TriageSupport.findEntrypoints(facts, manifest);
		List<TriageSupport.CategoryMatch> sinkMatches =
			TriageSupport.findSinks(facts, manifest);
		builder.append("## Triage Tags\n\n");
		builder.append("- Entrypoint tags: ");
		appendCategoryList(builder, entryMatches);
		builder.append("\n");
		builder.append("- Sink tags: ");
		appendCategoryList(builder, sinkMatches);
		builder.append("\n");
		builder.append("- Parser-like: ")
			.append(TriageSupport.hasParserLikeEvidence(facts, manifest) ? "yes" : "no")
			.append("\n\n");

		builder.append("## Imported APIs\n\n");
		appendSampleList(builder, facts.importedApis, sampleLimit);
		builder.append("\n## Nearby Strings\n\n");
		appendSampleList(builder, facts.referencedStrings, sampleLimit);
		builder.append("\n## Nearby Selectors\n\n");
		appendSampleList(builder, facts.referencedSelectors, sampleLimit);
		builder.append("\n## Direct Callers\n\n");
		appendFunctionSample(builder, index, facts.callerKeys, sampleLimit);
		builder.append("\n## Direct Callees\n\n");
		appendFunctionSample(builder, index, facts.calleeKeys, sampleLimit);
		builder.append("\n## Referenced Anonymous Functions\n\n");
		appendFactsSample(builder, referencedAnonymousFunctions, sampleLimit);
		builder.append("\n## Referenced Block Invoke Functions\n\n");
		appendFactsSample(builder, referencedBlockInvokeFunctions, sampleLimit);
		builder.append("\n## Analysis Warnings\n\n");
		if (linearWindow.warnings.size() == 0) {
			builder.append("- none\n");
		}
		else {
			for (int indexValue = 0; indexValue < linearWindow.warnings.size(); indexValue++) {
				builder.append("- ").append(linearWindow.warnings.get(indexValue).getAsString())
					.append("\n");
			}
		}
		builder.append("\n## Linear Instruction Window\n\n");
		builder.append("- Artifact: `linear_instructions.txt`\n");
		builder.append("- Decoded instructions outside current analyzed body: `")
			.append(linearWindow.context.get("decoded_outside_current_body").getAsBoolean())
			.append("`\n");
		builder.append("- Possible auth-stub truncation: `")
			.append(linearWindow.context.get("possible_authstub_truncation").getAsBoolean())
			.append("`\n");
		return builder.toString();
	}

	private void appendCategoryList(StringBuilder builder,
			List<TriageSupport.CategoryMatch> matches) {
		if (matches.isEmpty()) {
			builder.append("none");
			return;
		}
		for (int index = 0; index < matches.size(); index++) {
			if (index > 0) {
				builder.append(", ");
			}
			builder.append("`").append(matches.get(index).categoryId).append("`");
		}
	}

	private void appendSampleList(StringBuilder builder, Iterable<String> values, int limit) {
		int count = 0;
		for (String value : values) {
			if (count >= limit) {
				break;
			}
			builder.append("- `").append(value).append("`\n");
			count++;
		}
		if (count == 0) {
			builder.append("- none\n");
		}
	}

	private void appendFunctionSample(StringBuilder builder, TriageSupport.ProgramIndex index,
			Iterable<String> keys, int limit) {
		int count = 0;
		for (String key : keys) {
			if (count >= limit) {
				break;
			}
			TriageSupport.FunctionFacts facts = index.byKey.get(key);
			if (facts == null) {
				continue;
			}
			builder.append("- `").append(facts.name).append(" @ ").append(facts.address)
				.append("`\n");
			count++;
		}
		if (count == 0) {
			builder.append("- none\n");
		}
	}

	private void appendFactsSample(StringBuilder builder,
			Iterable<TriageSupport.FunctionFacts> functions, int limit) {
		int count = 0;
		for (TriageSupport.FunctionFacts facts : functions) {
			if (count >= limit) {
				break;
			}
			builder.append("- `").append(facts.name).append(" @ ").append(facts.address)
				.append("`\n");
			count++;
		}
		if (count == 0) {
			builder.append("- none\n");
		}
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
}
