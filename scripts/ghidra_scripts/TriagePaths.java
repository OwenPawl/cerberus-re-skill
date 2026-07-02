/* ###
 * IP: GHIDRA
 */
//@category Triage

import java.io.File;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.app.script.GhidraScript;

public class TriagePaths extends GhidraScript {

	private static class Candidate {
		String entryCategory;
		String sinkCategory;
		int score;
		List<String> pathKeys = new ArrayList<>();
		TriageSupport.CategoryMatch entryMatch;
		TriageSupport.CategoryMatch sinkMatch;
		boolean containsExternalCall;
		boolean containsParserStep;
		List<String> parserFunctions = new ArrayList<>();
	}

	@Override
	protected void run() throws Exception {
		Map<String, String> args = parseArgs();
		String manifestPath = requireArg(args, "manifest");
		String outputPath = requireArg(args, "output");
		String summaryPath = requireArg(args, "summary");
		int maxDepth = parseIntArg(args, "max_depth", 4);
		int maxVisited = parseIntArg(args, "max_visited_functions", 1500);
		int topCandidates = parseIntArg(args, "top_candidates", 50);
		int xrefLimit = parseIntArg(args, "xref_limit", 25);
		int entrypointLimit = parseIntArg(args, "entrypoint_limit", 40);

		TriageSupport.Manifest manifest = TriageSupport.loadManifest(manifestPath);
		TriageSupport.ProgramIndex index =
			TriageSupport.buildProgramIndex(currentProgram, monitor);

		Map<String, List<TriageSupport.CategoryMatch>> entryMatches = new LinkedHashMap<>();
		Map<String, List<TriageSupport.CategoryMatch>> sinkMatches = new LinkedHashMap<>();
		for (TriageSupport.FunctionFacts facts : index.byKey.values()) {
			monitor.checkCancelled();
			List<TriageSupport.CategoryMatch> entries =
				TriageSupport.findEntrypoints(facts, manifest);
			if (!entries.isEmpty()) {
				entryMatches.put(facts.functionKey, entries);
			}
			List<TriageSupport.CategoryMatch> sinks =
				TriageSupport.findSinks(facts, manifest);
			if (!sinks.isEmpty()) {
				sinkMatches.put(facts.functionKey, sinks);
			}
		}

		List<String> rankedEntrypoints = new ArrayList<>(entryMatches.keySet());
		Collections.sort(rankedEntrypoints, new Comparator<String>() {
			@Override
			public int compare(String left, String right) {
				return Integer.compare(bestScore(entryMatches.get(right)),
					bestScore(entryMatches.get(left)));
			}
		});
		if (rankedEntrypoints.size() > entrypointLimit) {
			rankedEntrypoints = new ArrayList<>(rankedEntrypoints.subList(0, entrypointLimit));
		}

		List<Candidate> candidates = new ArrayList<>();
		for (String entryKey : rankedEntrypoints) {
			monitor.checkCancelled();
			candidates.addAll(findCandidatesForEntrypoint(index, manifest, entryKey,
				entryMatches.get(entryKey), sinkMatches, maxDepth, maxVisited));
		}

		Collections.sort(candidates, new Comparator<Candidate>() {
			@Override
			public int compare(Candidate left, Candidate right) {
				return Integer.compare(right.score, left.score);
			}
		});
		if (candidates.size() > topCandidates) {
			candidates = new ArrayList<>(candidates.subList(0, topCandidates));
		}

		JsonArray candidateArray = new JsonArray();
		for (Candidate candidate : candidates) {
			candidateArray.add(candidateToJson(index, candidate, xrefLimit));
		}

		JsonObject payload = new JsonObject();
		payload.addProperty("program_name", currentProgram.getName());
		payload.addProperty("manifest_path", manifestPath);
		payload.addProperty("max_depth", maxDepth);
		payload.addProperty("max_visited_functions", maxVisited);
		payload.addProperty("top_candidates", topCandidates);
		payload.addProperty("xref_sample_limit", xrefLimit);
		payload.addProperty("entrypoints_considered", rankedEntrypoints.size());
		payload.addProperty("sink_function_count", sinkMatches.size());
		payload.addProperty("candidate_count", candidateArray.size());
		payload.add("candidates", candidateArray);

		TriageSupport.writeJson(new File(outputPath), payload);
		TriageSupport.writeText(new File(summaryPath),
			buildSummary(index, candidates, rankedEntrypoints.size(), sinkMatches.size()));
		println("Wrote " + outputPath);
		println("Wrote " + summaryPath);
	}

	private List<Candidate> findCandidatesForEntrypoint(TriageSupport.ProgramIndex index,
			TriageSupport.Manifest manifest, String entryKey,
			List<TriageSupport.CategoryMatch> entrypointMatches,
			Map<String, List<TriageSupport.CategoryMatch>> sinkMatches, int maxDepth,
			int maxVisited) throws Exception {
		List<Candidate> candidates = new ArrayList<>();
		Deque<List<String>> queue = new ArrayDeque<>();
		Set<String> visited = new LinkedHashSet<>();
		List<String> seedPath = new ArrayList<>();
		seedPath.add(entryKey);
		queue.add(seedPath);
		visited.add(entryKey);

		while (!queue.isEmpty() && visited.size() <= maxVisited) {
			monitor.checkCancelled();
			List<String> path = queue.removeFirst();
			String currentKey = path.get(path.size() - 1);
			TriageSupport.FunctionFacts currentFacts = index.byKey.get(currentKey);
			if (currentFacts == null) {
				continue;
			}

			List<TriageSupport.CategoryMatch> sinkCategories = sinkMatches.get(currentKey);
			if (sinkCategories != null && !sinkCategories.isEmpty()) {
				for (TriageSupport.CategoryMatch entryMatch : entrypointMatches) {
					for (TriageSupport.CategoryMatch sinkMatch : sinkCategories) {
						candidates.add(makeCandidate(index, manifest, path, entryMatch, sinkMatch));
					}
				}
			}

			if (path.size() > maxDepth) {
				continue;
			}
			for (String calleeKey : currentFacts.calleeKeys) {
				if (path.contains(calleeKey)) {
					continue;
				}
				List<String> nextPath = new ArrayList<>(path);
				nextPath.add(calleeKey);
				queue.addLast(nextPath);
				visited.add(calleeKey);
				if (visited.size() > maxVisited) {
					break;
				}
			}
		}

		return candidates;
	}

	private Candidate makeCandidate(TriageSupport.ProgramIndex index, TriageSupport.Manifest manifest,
			List<String> pathKeys, TriageSupport.CategoryMatch entryMatch,
			TriageSupport.CategoryMatch sinkMatch) {
		Candidate candidate = new Candidate();
		candidate.entryCategory = entryMatch.categoryId;
		candidate.sinkCategory = sinkMatch.categoryId;
		candidate.entryMatch = entryMatch;
		candidate.sinkMatch = sinkMatch;
		candidate.pathKeys = new ArrayList<>(pathKeys);

		int baseScore = entryMatch.score + sinkMatch.score;
		int pathPenalty = Math.max(0, pathKeys.size() - 1) * 6;
		candidate.containsExternalCall = false;
		candidate.containsParserStep = false;
		Set<String> parserLabels = new LinkedHashSet<>();
		for (String key : pathKeys) {
			TriageSupport.FunctionFacts facts = index.byKey.get(key);
			if (facts == null) {
				continue;
			}
			if (!facts.externalCalls.isEmpty()) {
				candidate.containsExternalCall = true;
			}
			if (TriageSupport.hasParserLikeEvidence(facts, manifest)) {
				candidate.containsParserStep = true;
				parserLabels.add(TriageSupport.simpleFunctionLabel(facts));
			}
		}
		candidate.parserFunctions.addAll(parserLabels);

		int score = baseScore - pathPenalty;
		if (candidate.containsExternalCall) {
			score += 10;
		}
		if (candidate.containsParserStep) {
			score += 15;
		}
		candidate.score = Math.max(score, 1);
		return candidate;
	}

	private int bestScore(List<TriageSupport.CategoryMatch> matches) {
		int best = 0;
		for (TriageSupport.CategoryMatch match : matches) {
			best = Math.max(best, match.score);
		}
		return best;
	}

	private JsonObject candidateToJson(TriageSupport.ProgramIndex index, Candidate candidate,
			int xrefLimit) {
		JsonObject object = new JsonObject();
		object.addProperty("entrypoint_category", candidate.entryCategory);
		object.addProperty("sink_category", candidate.sinkCategory);
		object.addProperty("score", candidate.score);
		object.addProperty("path_length", candidate.pathKeys.size());
		object.addProperty("contains_external_call", candidate.containsExternalCall);
		object.addProperty("contains_parser_or_decode_step", candidate.containsParserStep);

		JsonArray path = new JsonArray();
		for (String key : candidate.pathKeys) {
			TriageSupport.FunctionFacts facts = index.byKey.get(key);
			if (facts != null) {
				path.add(TriageSupport.functionToJson(index, facts, xrefLimit));
			}
		}
		object.add("path", path);

		JsonObject evidence = new JsonObject();
		evidence.add("entrypoint", TriageSupport.evidenceToJson(candidate.entryMatch.evidence));
		evidence.add("sink", TriageSupport.evidenceToJson(candidate.sinkMatch.evidence));
		evidence.add("parser_functions", TriageSupport.toJsonArray(candidate.parserFunctions, 25));
		object.add("evidence", evidence);
		return object;
	}

	private String buildSummary(TriageSupport.ProgramIndex index, List<Candidate> candidates,
			int entrypointsConsidered, int sinkCount) {
		StringBuilder builder = new StringBuilder();
		builder.append("# Triage Summary\n\n");
		builder.append("- Program: `").append(currentProgram.getName()).append("`\n");
		builder.append("- Entrypoints considered: ").append(entrypointsConsidered).append("\n");
		builder.append("- Sink functions: ").append(sinkCount).append("\n");
		builder.append("- Ranked candidates: ").append(candidates.size()).append("\n\n");
		if (candidates.isEmpty()) {
			builder.append("No candidate paths were found.\n");
			return builder.toString();
		}
		int rank = 1;
		for (Candidate candidate : candidates) {
			if (rank > 10) {
				break;
			}
			builder.append(rank).append(". `").append(candidate.entryCategory).append("` -> `")
				.append(candidate.sinkCategory).append("` score ")
				.append(candidate.score).append("\n");
			builder.append("   ");
			for (int indexValue = 0; indexValue < candidate.pathKeys.size(); indexValue++) {
				TriageSupport.FunctionFacts facts =
					index.byKey.get(candidate.pathKeys.get(indexValue));
				if (facts == null) {
					continue;
				}
				if (indexValue > 0) {
					builder.append(" -> ");
				}
				builder.append(facts.name);
			}
			builder.append("\n");
			rank++;
		}
		return builder.toString();
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
