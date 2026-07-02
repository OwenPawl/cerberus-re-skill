/* ###
 * IP: GHIDRA
 */
//@category Apple.Export

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;

/**
 * ExportSwiftTypeLayout — dump Swift 5 type/field/conformance metadata to JSON.
 *
 * Reads the following sections (all use Swift's compact relative-pointer ABI):
 *
 *   __swift5_fieldmd  — FieldDescriptor array (type → fields → field records)
 *   __swift5_types    — 32-bit relative pointers to TypeContextDescriptors
 *   __swift5_protos   — 32-bit relative pointers to ProtocolConformanceDescriptors
 *   __swift5_proto    — 32-bit relative pointers to ProtocolDescriptors (if present)
 *
 * Each descriptor uses 32-bit signed relative offsets rather than absolute
 * pointers.  Resolving a relative pointer: target = fieldAddr + (int32)value.
 * Indirect relative pointers (bit 0 set in the int32) dereference one extra
 * 8-byte pointer: target = *(fieldAddr + (int32 & ~1)).
 *
 * Outputs: swift_layout.json
 *
 * Schema:
 * {
 *   "program_name": "...",
 *   "image_base": "0x...",
 *   "types": [
 *     {
 *       "kind": "class|struct|enum|protocol",
 *       "mangled": "_$s...",
 *       "demangled": "ModuleName.TypeName",
 *       "metadata_addr": "0x...",      -- from __swift5_types (best effort)
 *       "fields": [
 *         {
 *           "name": "propName",
 *           "mangled_type": "_$s...",
 *           "type": "Swift.Int",
 *           "is_var": true             -- true=var, false=let
 *         }
 *       ],
 *       "enum_cases": [               -- populated for enum kinds
 *         { "name": "...", "payload_type": "..." }
 *       ],
 *       "conformances": [
 *         {
 *           "protocol": "...",
 *           "witness_table_addr": "0x..."
 *         }
 *       ]
 *     }
 *   ]
 * }
 *
 * Args:
 *   output=<path>   Required. Destination JSON file.
 */
public class ExportSwiftTypeLayout extends GhidraScript {

	private Memory memory;
	private AddressSpace addrSpace;
	private long imageBase;

	// PAC mask for absolute pointer reads
	private static final long PAC_MASK = 0x0000FFFFFFFFFFF8L;

	// All mangled names encountered — demangled in one batch before output
	private final Set<String>         demangleQueue = new LinkedHashSet<>();
	private final Map<String, String> demangleCache = new LinkedHashMap<>();

	// Per-mangled-name accumulated data (may be updated by multiple sections)
	private final Map<String, JsonObject> typeByMangled = new LinkedHashMap<>();

	@Override
	protected void run() throws Exception {
		Map<String, String> args = parseArgs();
		String outputPath = requireArg(args, "output");

		memory    = currentProgram.getMemory();
		addrSpace = currentProgram.getAddressFactory().getDefaultAddressSpace();
		imageBase = currentProgram.getImageBase().getOffset();

		// ---------------------------------------------------------------
		// 1. Walk __swift5_fieldmd → FieldDescriptors
		//    (packed consecutively; no pointer-to-descriptor indirection)
		// ---------------------------------------------------------------
		walkFieldmd();

		// ---------------------------------------------------------------
		// 2. Walk __swift5_types → relative pointers to TypeContextDescriptors
		//    Used to pick up metadata_addr and catch types without field sections
		// ---------------------------------------------------------------
		walkTypes();

		// ---------------------------------------------------------------
		// 3. Walk __swift5_protos → relative pointers to
		//    ProtocolConformanceDescriptors
		// ---------------------------------------------------------------
		walkConformances();

		// ---------------------------------------------------------------
		// 4. Batch-demangle all queued names
		// ---------------------------------------------------------------
		flushDemangle();

		// ---------------------------------------------------------------
		// 5. Build output
		// ---------------------------------------------------------------
		JsonObject payload = new JsonObject();
		payload.addProperty("program_name", currentProgram.getName());
		payload.addProperty("image_base", hex(imageBase));

		JsonArray types = new JsonArray();
		for (JsonObject obj : typeByMangled.values()) {
			// Resolve demangled names in-place
			String mangled = obj.has("mangled")
				? obj.get("mangled").getAsString() : null;
			if (mangled != null) {
				obj.addProperty("demangled", demangled(mangled));
			}
			// Resolve demangled type names inside field list
			if (obj.has("fields")) {
				for (com.google.gson.JsonElement fe : obj.getAsJsonArray("fields")) {
					JsonObject fobj = fe.getAsJsonObject();
					String mt = fobj.has("mangled_type")
						? fobj.get("mangled_type").getAsString() : null;
					if (mt != null && !mt.isEmpty()) {
						fobj.addProperty("type", demangled(mt));
					}
				}
			}
			if (obj.has("enum_cases")) {
				for (com.google.gson.JsonElement ce : obj.getAsJsonArray("enum_cases")) {
					JsonObject cobj = ce.getAsJsonObject();
					String pt = cobj.has("payload_type")
						? cobj.get("payload_type").getAsString() : null;
					if (pt != null && !pt.isEmpty()) {
						cobj.addProperty("payload_type", demangled(pt));
					}
				}
			}
			if (obj.has("conformances")) {
				for (com.google.gson.JsonElement confe : obj.getAsJsonArray("conformances")) {
					JsonObject cobj = confe.getAsJsonObject();
					String proto = cobj.has("protocol")
						? cobj.get("protocol").getAsString() : null;
					if (proto != null && !proto.isEmpty()) {
						String d = demangled(proto);
						if (!d.equals(proto)) cobj.addProperty("protocol", d);
					}
				}
			}
			types.add(obj);
		}
		payload.add("types", types);

		TriageSupport.writeJson(new File(outputPath), payload);
		println("Wrote " + outputPath + " (" + types.size() + " types)");
	}

	// -----------------------------------------------------------------------
	// Section walkers
	// -----------------------------------------------------------------------

	/**
	 * Walk __swift5_fieldmd — FieldDescriptors packed end-to-end.
	 *
	 * FieldDescriptor layout:
	 *   +0x00: int32 MangledTypeName (relative direct ptr to C string)
	 *   +0x04: int32 Superclass      (relative direct ptr to C string, nullable)
	 *   +0x08: uint16 Kind
	 *   +0x0A: uint16 FieldRecordSize
	 *   +0x0C: uint32 NumFields
	 *   +0x10: FieldRecord[NumFields]
	 *
	 * FieldRecord:
	 *   +0x00: uint32 Flags (bit 1=isVar, bit 2=isIndirectCase)
	 *   +0x04: int32 MangledTypeName (relative, nullable)
	 *   +0x08: int32 FieldName       (relative to C string)
	 *   sizeof = FieldRecordSize (typically 12)
	 */
	private void walkFieldmd() {
		MemoryBlock block = findBlock("__swift5_fieldmd");
		if (block == null) {
			println("NOTE: __swift5_fieldmd not found.");
			return;
		}
		long ptr = block.getStart().getOffset();
		long end = block.getEnd().getOffset();

		while (ptr + 15 <= end) {
			long descBase = ptr;
			try {
				// MangledTypeName
				String mangledTypeName = mangledFromRelPtr(descBase);
				if (mangledTypeName == null || mangledTypeName.isEmpty()) {
					ptr += 16; // skip minimal header, re-sync on next
					continue;
				}
				queueDemangle(mangledTypeName);

				// Superclass (nullable)
				String superclass = mangledFromRelPtr(descBase + 4);
				queueDemangle(superclass);

				int kind          = uint16(descBase + 8);
				int fieldRecordSz = uint16(descBase + 10);
				long numFields    = uint32(descBase + 12);

				if (fieldRecordSz == 0) fieldRecordSz = 12; // fallback
				if (numFields > 4096)   numFields = 0;      // sanity

				JsonObject typeObj = getOrCreate(mangledTypeName);
				typeObj.addProperty("kind", fieldKind(kind));
				if (superclass != null && !superclass.isEmpty()) {
					typeObj.addProperty("superclass_mangled", superclass);
				}

				boolean isEnum = (kind == 2 || kind == 3); // Enum | MultiPayloadEnum
				JsonArray fields    = new JsonArray();
				JsonArray enumCases = new JsonArray();

				long fieldBase = descBase + 16;
				for (long i = 0; i < numFields; i++) {
					long recBase = fieldBase + i * fieldRecordSz;
					try {
						long flags     = uint32(recBase);
						boolean isVar  = (flags & 0x2) != 0;
						boolean isIndirect = (flags & 0x4) != 0;
						// field MangledTypeName (nullable for enum cases without payload)
						String fieldTypeMangled = mangledFromRelPtr(recBase + 4);
						queueDemangle(fieldTypeMangled);
						// field name
						String fieldName = cstringFromRelPtr(recBase + 8);

						if (isEnum) {
							JsonObject cas = new JsonObject();
							cas.addProperty("name",         fieldName   != null ? fieldName : "");
							cas.addProperty("payload_type", fieldTypeMangled != null ? fieldTypeMangled : "");
							cas.addProperty("is_indirect",  isIndirect);
							enumCases.add(cas);
						}
						else {
							JsonObject f = new JsonObject();
							f.addProperty("name",         fieldName != null ? fieldName : "");
							f.addProperty("mangled_type", fieldTypeMangled != null ? fieldTypeMangled : "");
							f.addProperty("type",         fieldTypeMangled != null ? fieldTypeMangled : ""); // placeholder until demangle
							f.addProperty("is_var",       isVar);
							fields.add(f);
						}
					}
					catch (Exception e) {
						println("WARNING: skipping field record at " + hex(recBase) + ": " + e.getMessage());
					}
				}

				if (!typeObj.has("fields"))      typeObj.add("fields",      fields);
				if (!typeObj.has("enum_cases"))   typeObj.add("enum_cases",  enumCases);
				if (!typeObj.has("conformances")) typeObj.add("conformances", new JsonArray());

				// Advance past this descriptor
				ptr = fieldBase + numFields * fieldRecordSz;
			}
			catch (Exception e) {
				println("WARNING: skipping FieldDescriptor at " + hex(descBase) + ": " + e.getMessage());
				ptr += 16; // advance minimally to avoid infinite loop
			}
		}
	}

	/**
	 * Walk __swift5_types — 32-bit relative pointers to TypeContextDescriptors.
	 *
	 * TypeContextDescriptor header (all kinds):
	 *   +0x00: uint32 Flags      (bits 0-3 = Kind: 16=Class, 17=Struct, 18=Enum, 19=Protocol)
	 *   +0x04: int32  Parent     (relative, nullable)
	 *   +0x08: int32  Name       (relative to C string)
	 *   +0x0C: int32  AccessFunction (relative, nullable)
	 *   +0x10: int32  Fields     (relative to FieldDescriptor, nullable)
	 *
	 * We read Kind and Name; for classes also read SuperclassType at +0x14.
	 * metadata_addr is the address of the descriptor itself (not the metadata).
	 */
	private void walkTypes() {
		MemoryBlock block = findBlock("__swift5_types");
		if (block == null) return;

		long start = block.getStart().getOffset();
		long end   = block.getEnd().getOffset();

		for (long ptr = start; ptr + 3 <= end; ptr += 4) {
			try {
				long descAddr = resolveRelPtr(ptr);
				if (descAddr == 0) continue;

				long flags = uint32(descAddr);
				int  kind  = (int)(flags & 0x1F); // bits 0-4

				// Only handle concrete type kinds
				if (kind != 16 && kind != 17 && kind != 18 && kind != 19) continue;

				String name = cstringFromRelPtr(descAddr + 8);
				if (name == null || name.isEmpty()) continue;

				// Build a pseudo-mangled name from the descriptor name
				// Real mangled name comes from __swift5_fieldmd; here we just use name as key
				// if no fieldmd entry exists yet, create one keyed by the bare name
				// The $s prefix makes it look like a mangled name for queue/merge purposes.
				// We prefer the __swift5_fieldmd mangled name, so only create if missing.

				// Find an existing entry that matches by checking if any key ends with the name
				JsonObject typeObj = findByName(name);
				if (typeObj == null) {
					// Create a new entry keyed by a synthetic mangled name placeholder
					String syntheticKey = "$types:" + name;
					typeObj = getOrCreate(syntheticKey);
					typeObj.addProperty("mangled", syntheticKey);
					typeObj.addProperty("demangled", name);
					typeObj.addProperty("kind", typeKind(kind));
					if (!typeObj.has("fields"))      typeObj.add("fields",      new JsonArray());
					if (!typeObj.has("enum_cases"))  typeObj.add("enum_cases",  new JsonArray());
					if (!typeObj.has("conformances"))typeObj.add("conformances", new JsonArray());
				}
				typeObj.addProperty("metadata_addr", hex(descAddr));
				if (!typeObj.has("kind") || typeObj.get("kind").getAsString().isEmpty()) {
					typeObj.addProperty("kind", typeKind(kind));
				}
			}
			catch (Exception e) {
				println("WARNING: skipping type entry at " + hex(ptr) + ": " + e.getMessage());
			}
		}
	}

	/**
	 * Walk __swift5_protos — 32-bit relative pointers to
	 * ProtocolConformanceDescriptors.
	 *
	 * ProtocolConformanceDescriptor:
	 *   +0x00: int32 ProtocolDescriptor (relative indirect ptr to ProtocolDescriptor)
	 *   +0x04: int32 TypeRef            (relative indirect ptr to TypeContextDescriptor)
	 *   +0x08: int32 WitnessTablePattern (relative to witness table, nullable)
	 *   +0x0C: uint32 Flags
	 *
	 * ProtocolDescriptor.Name is at +0x08 (relative ptr to C string).
	 */
	private void walkConformances() {
		MemoryBlock block = findBlock("__swift5_protos");
		if (block == null) return;

		long start = block.getStart().getOffset();
		long end   = block.getEnd().getOffset();

		for (long ptr = start; ptr + 3 <= end; ptr += 4) {
			try {
				long confAddr = resolveRelPtr(ptr);
				if (confAddr == 0) continue;

				// Protocol descriptor pointer (indirect relative)
				String protoName = null;
				try {
					long protoPtrField = confAddr; // +0x00
					long protoDescAddr = resolveRelPtrIndirect(protoPtrField);
					if (protoDescAddr != 0) {
						// ProtocolDescriptor.Name at +0x08
						protoName = cstringFromRelPtr(protoDescAddr + 8);
						queueDemangle(protoName);
					}
				}
				catch (Exception ignored) {}

				// Type ref (indirect relative pointer)
				String typeMangled = null;
				try {
					long typeRefField = confAddr + 4;
					long typeDescAddr = resolveRelPtrIndirect(typeRefField);
					if (typeDescAddr != 0) {
						// Try reading name from the type descriptor
						typeMangled = cstringFromRelPtr(typeDescAddr + 8);
						queueDemangle(typeMangled);
					}
				}
				catch (Exception ignored) {}

				// Witness table pattern
				long witnessTableAddr = 0;
				try {
					int wtOff = sint32(confAddr + 8);
					if (wtOff != 0) {
						witnessTableAddr = confAddr + 8 + wtOff;
					}
				}
				catch (Exception ignored) {}

				if (typeMangled == null || typeMangled.isEmpty()) continue;

				// Attach conformance to the matching type entry
				JsonObject typeObj = findByName(typeMangled);
				if (typeObj == null) {
					typeObj = getOrCreate(typeMangled);
					if (!typeObj.has("kind"))       typeObj.addProperty("kind", "");
					if (!typeObj.has("mangled"))    typeObj.addProperty("mangled", typeMangled);
					if (!typeObj.has("fields"))     typeObj.add("fields",      new JsonArray());
					if (!typeObj.has("enum_cases")) typeObj.add("enum_cases",  new JsonArray());
					typeObj.add("conformances", new JsonArray());
					queueDemangle(typeMangled);
				}

				JsonArray conformances = typeObj.getAsJsonArray("conformances");
				if (conformances == null) {
					conformances = new JsonArray();
					typeObj.add("conformances", conformances);
				}

				JsonObject conf = new JsonObject();
				conf.addProperty("protocol",           protoName != null ? protoName : "");
				conf.addProperty("witness_table_addr", witnessTableAddr != 0
					? hex(witnessTableAddr) : "");
				conformances.add(conf);
			}
			catch (Exception e) {
				println("WARNING: skipping conformance at " + hex(ptr) + ": " + e.getMessage());
			}
		}
	}

	// -----------------------------------------------------------------------
	// Type map helpers
	// -----------------------------------------------------------------------

	private JsonObject getOrCreate(String key) {
		return typeByMangled.computeIfAbsent(key, k -> {
			JsonObject obj = new JsonObject();
			obj.addProperty("mangled", k);
			return obj;
		});
	}

	/** Find a type entry whose mangled name or demangled name contains the given name. */
	private JsonObject findByName(String name) {
		if (name == null || name.isEmpty()) return null;
		// Exact key match first
		if (typeByMangled.containsKey(name)) return typeByMangled.get(name);
		// Check if any existing entry's mangled name ends with the bare name
		for (Map.Entry<String, JsonObject> entry : typeByMangled.entrySet()) {
			String k = entry.getKey();
			if (k.endsWith(name) || k.endsWith("." + name)) return entry.getValue();
			JsonObject obj = entry.getValue();
			if (obj.has("demangled") && obj.get("demangled").getAsString().endsWith(name)) {
				return obj;
			}
		}
		return null;
	}

	// -----------------------------------------------------------------------
	// Relative pointer helpers (Swift ABI)
	// -----------------------------------------------------------------------

	/**
	 * Resolve a direct (non-indirect) relative pointer.
	 * At {@code fieldAddr}, there is an int32 offset.
	 * Result = fieldAddr + offset.  0 offset = null pointer.
	 */
	private long resolveRelPtr(long fieldAddr) throws MemoryAccessException {
		int rel = sint32(fieldAddr);
		if (rel == 0) return 0;
		return fieldAddr + rel;
	}

	/**
	 * Resolve a potentially-indirect relative pointer.
	 * If bit 0 of the int32 is set, the result address from direct resolution
	 * is itself an 8-byte pointer that must be dereferenced.
	 */
	private long resolveRelPtrIndirect(long fieldAddr) throws MemoryAccessException {
		int rel = sint32(fieldAddr);
		if (rel == 0) return 0;
		boolean indirect = (rel & 1) != 0;
		long target = fieldAddr + (rel & ~1);
		if (indirect) {
			target = rawLong(target) & PAC_MASK;
		}
		return target;
	}

	/** Read a mangled type name via a relative pointer. Returns null on failure. */
	private String mangledFromRelPtr(long fieldAddr) {
		try {
			long strAddr = resolveRelPtr(fieldAddr);
			if (strAddr == 0) return null;
			String s = cstring(strAddr);
			if (s == null || s.isEmpty()) return null;
			// Trim leading special bytes used by some ABI versions
			while (!s.isEmpty() && (s.charAt(0) == '\001' || s.charAt(0) == '\002')) {
				s = s.substring(1);
			}
			return s.isEmpty() ? null : s;
		}
		catch (Exception e) { return null; }
	}

	/** Read a C string via a relative pointer. Returns null on failure. */
	private String cstringFromRelPtr(long fieldAddr) {
		try {
			long strAddr = resolveRelPtr(fieldAddr);
			return strAddr != 0 ? cstring(strAddr) : null;
		}
		catch (Exception e) { return null; }
	}

	// -----------------------------------------------------------------------
	// Demangling
	// -----------------------------------------------------------------------

	private void queueDemangle(String mangled) {
		if (mangled == null || mangled.isEmpty()) return;
		if (!demangleCache.containsKey(mangled)) {
			demangleQueue.add(mangled);
		}
	}

	private void flushDemangle() {
		if (demangleQueue.isEmpty()) return;
		List<String> names = new ArrayList<>(demangleQueue);
		demangleQueue.clear();
		try {
			List<String> cmd = new ArrayList<>();
			cmd.add("swift");
			cmd.add("demangle");
			cmd.addAll(names);
			ProcessBuilder pb = new ProcessBuilder(cmd);
			pb.redirectErrorStream(false);
			Process proc = pb.start();
			byte[] output = proc.getInputStream().readAllBytes();
			int exit = proc.waitFor();
			if (exit == 0 && output.length > 0) {
				String[] lines = new String(output, StandardCharsets.UTF_8).split("\n");
				for (int i = 0; i < names.size() && i < lines.length; i++) {
					String demangled = lines[i].trim();
					// swift demangle outputs "mangled ---> demangled"
					int arrowIdx = demangled.indexOf(" ---> ");
					if (arrowIdx >= 0) {
						demangled = demangled.substring(arrowIdx + 6).trim();
					}
					if (!demangled.isEmpty()) {
						demangleCache.put(names.get(i), demangled);
					}
				}
			}
		}
		catch (Exception e) {
			println("NOTE: swift demangle unavailable; using mangled names as-is.");
		}
	}

	private String demangled(String mangled) {
		if (mangled == null || mangled.isEmpty()) return mangled;
		return demangleCache.getOrDefault(mangled, mangled);
	}

	// -----------------------------------------------------------------------
	// Memory helpers
	// -----------------------------------------------------------------------

	private MemoryBlock findBlock(String sectionName) {
		String lower = sectionName.toLowerCase();
		String token = lower.replaceAll("^__", "");
		for (MemoryBlock block : memory.getBlocks()) {
			String name = block.getName();
			if (name == null) continue;
			String nl = name.toLowerCase();
			if (nl.equals(lower)
				|| nl.endsWith("." + lower) || nl.endsWith("," + lower)
				|| nl.equals(token)
				|| nl.endsWith("." + token) || nl.endsWith("," + token)) {
				return block;
			}
		}
		return null;
	}

	private long rawLong(long offset) throws MemoryAccessException {
		return memory.getLong(addrSpace.getAddress(offset), false);
	}

	private long uint32(long offset) throws MemoryAccessException {
		return memory.getInt(addrSpace.getAddress(offset), false) & 0xFFFFFFFFL;
	}

	private int sint32(long offset) throws MemoryAccessException {
		return memory.getInt(addrSpace.getAddress(offset), false);
	}

	private int uint16(long offset) throws MemoryAccessException {
		return memory.getShort(addrSpace.getAddress(offset), false) & 0xFFFF;
	}

	private String cstring(long offset) {
		if (offset == 0) return null;
		StringBuilder sb = new StringBuilder();
		try {
			for (int i = 0; i < 1024; i++) {
				byte b = memory.getByte(addrSpace.getAddress(offset + i));
				if (b == 0) break;
				sb.append((char)(b & 0xFF));
			}
		}
		catch (MemoryAccessException ignored) {}
		return sb.toString();
	}

	// -----------------------------------------------------------------------
	// Kind helpers
	// -----------------------------------------------------------------------

	private static String fieldKind(int kind) {
		switch (kind) {
			case 0: return "struct";
			case 1: return "class";
			case 2: return "enum";
			case 3: return "enum"; // MultiPayloadEnum
			case 4: return "protocol";
			case 5: return "protocol"; // ClassProtocol
			case 6: return "protocol"; // ObjCProtocol
			case 7: return "class";    // ObjCClass
			default: return "struct";
		}
	}

	private static String typeKind(int kind) {
		switch (kind) {
			case 16: return "class";
			case 17: return "struct";
			case 18: return "enum";
			case 19: return "protocol";
			default: return "type_" + kind;
		}
	}

	private static String hex(long value) {
		return "0x" + Long.toHexString(value);
	}

	// -----------------------------------------------------------------------
	// Arg parsing
	// -----------------------------------------------------------------------

	private Map<String, String> parseArgs() {
		Map<String, String> args = new LinkedHashMap<>();
		for (String arg : getScriptArgs()) {
			int idx = arg.indexOf('=');
			if (idx > 0) {
				args.put(
					arg.substring(0, idx).trim().toLowerCase().replace('-', '_'),
					arg.substring(idx + 1));
			}
		}
		return args;
	}

	private String requireArg(Map<String, String> args, String key) {
		String v = args.get(key);
		if (v == null || v.isEmpty()) {
			throw new IllegalArgumentException("Missing required argument: " + key + "=...");
		}
		return v;
	}
}
