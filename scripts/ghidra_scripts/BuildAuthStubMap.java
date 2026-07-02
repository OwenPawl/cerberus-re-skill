/* ###
 * IP: GHIDRA
 */
//@category Swift

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;

public class BuildAuthStubMap extends GhidraScript {

	@Override
	protected void run() throws Exception {
		Map<String, String> args = parseArgs();
		String outputPath = requireArg(args, "output");
		Listing listing = currentProgram.getListing();
		Memory memory = currentProgram.getMemory();
		FunctionIterator iter = listing.getFunctions(true);

		JsonObject stubs = new JsonObject();
		JsonObject slots = new JsonObject();
		int candidateCount = 0;
		int slotCount = 0;
		int resolvedCount = 0;

		while (iter.hasNext() && !monitor.isCancelled()) {
			Function fn = iter.next();
			String name = fn.getName();
			if (!isAuthStubCandidate(name)) continue;
			List<String> mnems = getMnems(fn, listing);
			if (!isAuthStub(mnems)) continue;
			candidateCount++;

			Address slot = resolveSlot(fn, listing);
			JsonObject stub = new JsonObject();
			String stubAddr = hex(fn.getEntryPoint());
			stub.addProperty("address", stubAddr);
			stub.addProperty("old_name", name);
			stub.addProperty("source", "ghidra-slot-pointer");

			if (slot != null) {
				slotCount++;
				String slotAddr = hex(slot);
				stub.addProperty("slot", slotAddr);
				JsonObject resolved = resolveSlotTarget(slot, memory);
				if (resolved.has("name")) {
					resolvedCount++;
					stub.addProperty("name", resolved.get("name").getAsString());
					stub.addProperty("raw_symbol", resolved.get("raw_symbol").getAsString());
					stub.addProperty("target_address", resolved.get("target_address").getAsString());
					stub.addProperty("raw_pointer", resolved.get("raw_pointer").getAsString());
					JsonObject slotObj = new JsonObject();
					slotObj.addProperty("stub", stubAddr);
					slotObj.addProperty("name", resolved.get("name").getAsString());
					slotObj.addProperty("raw_symbol", resolved.get("raw_symbol").getAsString());
					slotObj.addProperty("target_address", resolved.get("target_address").getAsString());
					slotObj.addProperty("raw_pointer", resolved.get("raw_pointer").getAsString());
					slotObj.addProperty("source", "ghidra-slot-pointer");
					slots.add(slotAddr, slotObj);
				}
			}
			stubs.add(stubAddr, stub);
		}

		JsonObject stats = new JsonObject();
		stats.addProperty("candidate_count", candidateCount);
		stats.addProperty("slot_count", slotCount);
		stats.addProperty("resolved_count", resolvedCount);

		JsonObject report = new JsonObject();
		report.addProperty("schema", "ghidra-re.authstub-slot-probe.v1");
		report.addProperty("program_name", currentProgram.getName());
		report.add("stats", stats);
		report.add("stubs", stubs);
		report.add("slots", slots);

		File outFile = new File(outputPath);
		File parent = outFile.getParentFile();
		if (parent != null && !parent.exists()) parent.mkdirs();
		Gson gson = new GsonBuilder().setPrettyPrinting().create();
		try (Writer w = new OutputStreamWriter(new FileOutputStream(outFile), StandardCharsets.UTF_8)) {
			gson.toJson(report, w);
		}
		println("BuildAuthStubMap: wrote " + outFile.getAbsolutePath()
				+ " (" + resolvedCount + "/" + candidateCount + " resolved)");
	}

	private boolean isAuthStubCandidate(String name) {
		return name.startsWith("_OUTLINED_FUNCTION_")
				|| name.startsWith("outlined$authstub$")
				|| name.startsWith("outlined_authstub_")
				|| name.startsWith("FUN_");
	}

	private boolean isAuthStub(List<String> mnems) {
		if (mnems.isEmpty() || mnems.size() > 6) return false;
		String last = mnems.get(mnems.size() - 1);
		if (last.startsWith("bra") || last.startsWith("blra")) return true;
		return last.equals("br") || last.equals("blr");
	}

	private List<String> getMnems(Function fn, Listing listing) {
		List<String> mnems = new ArrayList<>();
		InstructionIterator insns = listing.getInstructions(fn.getBody(), true);
		while (insns.hasNext()) {
			mnems.add(insns.next().getMnemonicString().toLowerCase());
		}
		return mnems;
	}

	private Address resolveSlot(Function fn, Listing listing) {
		try {
			InstructionIterator insns = listing.getInstructions(fn.getBody(), true);
			while (insns.hasNext()) {
				Instruction insn = insns.next();
				if (!insn.getMnemonicString().toLowerCase().startsWith("ldr")) continue;
				for (Reference ref : insn.getReferencesFrom()) {
					if (ref.getReferenceType().isRead()) return ref.getToAddress();
				}
			}
		}
		catch (Exception e) {
			// best effort
		}
		return null;
	}

	private JsonObject resolveSlotTarget(Address slot, Memory memory) {
		JsonObject obj = new JsonObject();
		try {
			long raw = memory.getLong(slot);
			obj.addProperty("raw_pointer", "0x" + Long.toUnsignedString(raw, 16));
			for (long candidate : pointerCandidates(raw)) {
				Address target = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(candidate);
				String symbol = symbolName(target);
				if (symbol == null || symbol.isEmpty()) continue;
				obj.addProperty("target_address", hex(target));
				obj.addProperty("raw_symbol", symbol);
				obj.addProperty("name", cleanName(symbol));
				return obj;
			}
		}
		catch (Exception e) {
			obj.addProperty("error", e.getMessage());
		}
		return obj;
	}

	private long[] pointerCandidates(long raw) {
		return new long[] {
			raw,
			raw & 0x00ffffffffffffffL,
			raw & 0x0000ffffffffffffL,
			raw & 0x000000ffffffffffL,
			raw & 0x0000000fffffffffL
		};
	}

	private String symbolName(Address target) {
		try {
			Function exact = currentProgram.getFunctionManager().getFunctionAt(target);
			if (exact != null) return exact.getName();
			Symbol sym = currentProgram.getSymbolTable().getPrimarySymbol(target);
			if (sym != null) return sym.getName();
			Function containing = currentProgram.getFunctionManager().getFunctionContaining(target);
			if (containing != null) return containing.getName();
		}
		catch (Exception e) {
			// best effort
		}
		return null;
	}

	private String cleanName(String value) {
		String safe = value;
		while (safe.startsWith("_")) {
			safe = safe.substring(1);
		}
		return safe;
	}

	private String hex(Address address) {
		return "0x" + address.toString().toLowerCase();
	}

	private Map<String, String> parseArgs() {
		Map<String, String> args = new LinkedHashMap<>();
		for (String arg : getScriptArgs()) {
			int idx = arg.indexOf('=');
			if (idx > 0) {
				args.put(arg.substring(0, idx).trim().toLowerCase().replace('-', '_'),
					arg.substring(idx + 1));
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
