/* ###
 * IP: GHIDRA
 */
//@category Triage

import java.io.File;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.app.script.GhidraScript;

public class ExportEntrypoints extends GhidraScript {

	@Override
	protected void run() throws Exception {
		Map<String, String> args = parseArgs();
		String manifestPath = requireArg(args, "manifest");
		String outputPath = requireArg(args, "output");
		int sampleLimit = parseIntArg(args, "sample_limit", 20);

		TriageSupport.Manifest manifest = TriageSupport.loadManifest(manifestPath);
		TriageSupport.ProgramIndex index =
			TriageSupport.buildProgramIndex(currentProgram, monitor);

		JsonArray entrypoints = new JsonArray();
		for (TriageSupport.FunctionFacts facts : index.byKey.values()) {
			monitor.checkCancelled();
			List<TriageSupport.CategoryMatch> matches =
				TriageSupport.findEntrypoints(facts, manifest);
			for (TriageSupport.CategoryMatch match : matches) {
				JsonObject object = new JsonObject();
				object.addProperty("category", match.categoryId);
				object.addProperty("label", match.label);
				object.addProperty("score", match.score);
				object.add("function", TriageSupport.functionToJson(index, facts, sampleLimit));
				object.add("evidence", TriageSupport.evidenceToJson(match.evidence));
				entrypoints.add(object);
			}
		}

		JsonObject payload = new JsonObject();
		payload.addProperty("program_name", currentProgram.getName());
		payload.addProperty("manifest_path", manifestPath);
		payload.addProperty("entrypoint_count", entrypoints.size());
		payload.add("entrypoints", entrypoints);

		TriageSupport.writeJson(new File(outputPath), payload);
		println("Wrote " + outputPath);
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
