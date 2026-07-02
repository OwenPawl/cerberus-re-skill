/* ###
 * IP: GHIDRA
 */
//@category Triage

import java.io.File;
import java.util.LinkedHashMap;
import java.util.Map;

import com.google.gson.JsonObject;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

public class ApplyFinding extends GhidraScript {

	@Override
	protected void run() throws Exception {
		Map<String, String> args = parseArgs();
		String outputPath = requireArg(args, "output");
		String title = requireArg(args, "title");
		String comment = requireArg(args, "comment");
		String bookmarkCategory = args.containsKey("bookmark_category") ?
			args.get("bookmark_category") : "review";
		String rename = args.get("rename");

		TriageSupport.ProgramIndex index =
			TriageSupport.buildProgramIndex(currentProgram, monitor);
		Function function =
			TriageSupport.resolveFunction(index, args.get("address"), args.get("function"));
		Address targetAddress = null;
		if (function != null) {
			targetAddress = function.getEntryPoint();
		}
		else if (args.containsKey("address")) {
			targetAddress = toAddr(args.get("address"));
		}
		if (targetAddress == null) {
			throw new IllegalArgumentException("unable to resolve target address");
		}

		String normalizedBookmarkType = "triage/" + TriageSupport.safeSlug(bookmarkCategory);
		String composedComment = "[" + title + "]\n" + comment;
		createBookmark(targetAddress, normalizedBookmarkType, composedComment);
		setPlateComment(targetAddress, composedComment);

		boolean repeatableCommentApplied = false;
		boolean renameApplied = false;
		String renamedTo = "";

		if (function != null) {
			function.setRepeatableComment(composedComment);
			function.setComment(composedComment);
			repeatableCommentApplied = true;
			if (rename != null && !rename.isEmpty() && !rename.equals(function.getName())) {
				function.setName(rename, SourceType.USER_DEFINED);
				renameApplied = true;
				renamedTo = rename;
			}
		}
		else if (rename != null && !rename.isEmpty()) {
			Symbol symbol = currentProgram.getSymbolTable().getPrimarySymbol(targetAddress);
			if (symbol != null && !rename.equals(symbol.getName())) {
				symbol.setName(rename, SourceType.USER_DEFINED);
				renameApplied = true;
				renamedTo = rename;
			}
		}

		JsonObject payload = new JsonObject();
		payload.addProperty("program_name", currentProgram.getName());
		payload.addProperty("target_address", targetAddress.toString());
		payload.addProperty("target_function", function == null ? "" : function.getName());
		payload.addProperty("bookmark_type", normalizedBookmarkType);
		payload.addProperty("title", title);
		payload.addProperty("comment", comment);
		payload.addProperty("plate_comment_applied", true);
		payload.addProperty("repeatable_comment_applied", repeatableCommentApplied);
		payload.addProperty("rename_applied", renameApplied);
		payload.addProperty("renamed_to", renamedTo);

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
}
