/* ###
 * IP: GHIDRA
 */
//@category Apple.Export

import java.io.File;
import java.util.LinkedHashMap;
import java.util.Map;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;

/**
 * ExportObjCTypeLayout — dump per-class ObjC ivar/method layout to JSON.
 *
 * Walks __objc_classlist and __objc_catlist, following class_t → class_ro_t →
 * ivar_list_t / method_list_t / protocol_list_t to produce a complete
 * structural picture of every ObjC class defined in the binary.
 *
 * Supports both "big" (pointer-based) and "small" (relative-offset)
 * method_t formats, including direct selector references in modern runtimes.
 *
 * Outputs: objc_layout.json
 *
 * Schema:
 * {
 *   "program_name": "...",
 *   "image_base": "0x...",
 *   "classes": [
 *     {
 *       "class": "ClassName",
 *       "class_addr": "0x...",
 *       "image_base_offset": N,
 *       "flags": N,
 *       "instance_start": N,
 *       "instance_size": N,
 *       "superclass": "SuperclassName",
 *       "superclass_chain": ["Super", "NSObject"],
 *       "protocols": ["Proto1", ...],
 *       "ivars": [
 *         { "name": "_foo", "type_encoding": "@\"NSString\"",
 *           "offset": 16, "size": 8, "alignment": 3 }
 *       ],
 *       "instance_methods": [
 *         { "sel": "initWithFoo:", "imp_addr": "0x...", "types": "@24@0:8@16" }
 *       ],
 *       "class_methods": [...]
 *     }
 *   ],
 *   "categories": [
 *     {
 *       "name": "ClassName+CategoryName",
 *       "class": "ClassName",
 *       "category": "CategoryName",
 *       "instance_methods": [...],
 *       "class_methods": [...],
 *       "protocols": [...]
 *     }
 *   ]
 * }
 *
 * Args:
 *   output=<path>   Required. Destination JSON file.
 */
public class ExportObjCTypeLayout extends GhidraScript {

	private Memory memory;
	private AddressSpace addrSpace;
	private long imageBase;

	// PAC mask: strip only authentication/tag bits. C-string and IMP pointers
	// are not required to be 8-byte aligned, so preserving low bits is critical.
	private static final long PAC_MASK = 0x0000FFFFFFFFFFFFL;
	private static final long METHOD_LIST_IS_RELATIVE = 0x80000000L;
	private static final long METHOD_LIST_HAS_DIRECT_SELECTORS = 0x40000000L;

	@Override
	protected void run() throws Exception {
		Map<String, String> args = parseArgs();
		String outputPath = requireArg(args, "output");

		memory = currentProgram.getMemory();
		addrSpace = currentProgram.getAddressFactory().getDefaultAddressSpace();
		imageBase = currentProgram.getImageBase().getOffset();

		JsonObject payload = new JsonObject();
		payload.addProperty("program_name", currentProgram.getName());
		payload.addProperty("image_base", hex(imageBase));

		// ---------------------------------------------------------------
		// Pass 1: collect classAddr → className for superclass resolution
		// ---------------------------------------------------------------
		Map<Long, String> classAddrToName = new LinkedHashMap<>();
		MemoryBlock classListBlock = findBlock("__objc_classlist");
		if (classListBlock != null) {
			long start = classListBlock.getStart().getOffset();
			long end   = classListBlock.getEnd().getOffset();
			for (long ptr = start; ptr + 7 <= end; ptr += 8) {
				try {
					long classAddr = readPtr(ptr);
					if (classAddr == 0) continue;
					long classRoAddr = classRoFrom(classAddr);
					if (classRoAddr == 0) continue;
					String name = className(classRoAddr);
					if (name != null && !name.isEmpty()) {
						classAddrToName.put(classAddr, name);
					}
				}
				catch (Exception ignored) {}
			}
		}

		// ---------------------------------------------------------------
		// Pass 2: full class parse
		// ---------------------------------------------------------------
		JsonArray classes = new JsonArray();
		if (classListBlock != null) {
			long start = classListBlock.getStart().getOffset();
			long end   = classListBlock.getEnd().getOffset();
			for (long ptr = start; ptr + 7 <= end; ptr += 8) {
				try {
					long classAddr = readPtr(ptr);
					if (classAddr == 0) continue;
					JsonObject cls = parseClass(classAddr, classAddrToName);
					if (cls != null) classes.add(cls);
				}
				catch (Exception e) {
					println("WARNING: skipping class at @" + hex(ptr) + ": " + e.getMessage());
				}
			}
		}
		else {
			println("NOTE: __objc_classlist not found — binary may not contain ObjC classes.");
		}
		payload.add("classes", classes);

		// ---------------------------------------------------------------
		// Categories
		// ---------------------------------------------------------------
		JsonArray cats = new JsonArray();
		MemoryBlock catListBlock = findBlock("__objc_catlist");
		if (catListBlock != null) {
			long start = catListBlock.getStart().getOffset();
			long end   = catListBlock.getEnd().getOffset();
			for (long ptr = start; ptr + 7 <= end; ptr += 8) {
				try {
					long catAddr = readPtr(ptr);
					if (catAddr == 0) continue;
					JsonObject cat = parseCategory(catAddr, classAddrToName);
					if (cat != null) cats.add(cat);
				}
				catch (Exception e) {
					println("WARNING: skipping category at @" + hex(ptr) + ": " + e.getMessage());
				}
			}
		}
		payload.add("categories", cats);

		TriageSupport.writeJson(new File(outputPath), payload);
		println("Wrote " + outputPath + " (" + classes.size() + " classes, " +
			cats.size() + " categories)");
	}

	// -----------------------------------------------------------------------
	// class_t → class_ro_t navigation
	// -----------------------------------------------------------------------

	/**
	 * Read the class_ro_t address from a class_t.
	 * class_t.data is at offset 0x20; strip low 3 flag bits.
	 */
	private long classRoFrom(long classAddr) throws MemoryAccessException {
		long dataRaw = rawLong(classAddr + 0x20);
		return (dataRaw & PAC_MASK) & ~3L; // strip PAC and Swift/ObjC flags
	}

	/**
	 * Read the class name string from class_ro_t.name (offset 0x18).
	 */
	private String className(long classRoAddr) throws MemoryAccessException {
		long namePtr = readPtr(classRoAddr + 0x18);
		return namePtr != 0 ? cstring(namePtr) : null;
	}

	// -----------------------------------------------------------------------
	// Class parsing
	// -----------------------------------------------------------------------

	private JsonObject parseClass(long classAddr, Map<Long, String> knownClasses)
		throws MemoryAccessException {
		long classRoAddr = classRoFrom(classAddr);
		if (classRoAddr == 0) return null;

		String name = className(classRoAddr);
		if (name == null || name.isEmpty()) return null;

		JsonObject obj = new JsonObject();
		obj.addProperty("class", name);
		obj.addProperty("class_addr", hex(classAddr));
		obj.addProperty("image_base_offset", classRoAddr - imageBase);

		// class_ro_t fields
		long flags         = uint32(classRoAddr);          // +0x00
		long instanceStart = uint32(classRoAddr + 4);      // +0x04
		long instanceSize  = uint32(classRoAddr + 8);      // +0x08
		obj.addProperty("flags", flags);
		obj.addProperty("instance_start", instanceStart);
		obj.addProperty("instance_size", instanceSize);

		// Superclass (class_t.superclass at +0x08)
		long superclassPtr = readPtr(classAddr + 8);
		String superclassName = resolveClassName(superclassPtr, knownClasses);
		obj.addProperty("superclass", superclassName != null ? superclassName : "");
		obj.add("superclass_chain", superclassChain(classAddr, knownClasses, 30));

		// Protocols (class_ro_t.baseProtocols at +0x28)
		obj.add("protocols", parseProtocolList(readPtr(classRoAddr + 0x28)));

		// Ivars (class_ro_t.ivars at +0x30)
		obj.add("ivars", parseIvarList(readPtr(classRoAddr + 0x30)));

		// Instance methods (class_ro_t.baseMethods at +0x20)
		obj.add("instance_methods", parseMethodList(readPtr(classRoAddr + 0x20)));

		// Class methods — metaclass is class_t.isa at +0x00
		JsonArray classMethods = new JsonArray();
		try {
			long metaclassPtr = readPtr(classAddr);  // +0x00: isa → metaclass
			if (metaclassPtr != 0) {
				long metaRoAddr = classRoFrom(metaclassPtr);
				if (metaRoAddr != 0) {
					classMethods = parseMethodList(readPtr(metaRoAddr + 0x20));
				}
			}
		}
		catch (Exception ignored) {}
		obj.add("class_methods", classMethods);

		return obj;
	}

	private JsonArray superclassChain(long classAddr, Map<Long, String> known, int maxDepth) {
		JsonArray chain = new JsonArray();
		long cur = classAddr;
		for (int i = 0; i < maxDepth; i++) {
			long superPtr;
			try { superPtr = readPtr(cur + 8); }
			catch (Exception e) { break; }
			if (superPtr == 0) break;

			String name = resolveClassName(superPtr, known);
			if (name == null || name.isEmpty()) break;
			chain.add(name);
			cur = superPtr;
		}
		return chain;
	}

	private String resolveClassName(long classPtr, Map<Long, String> known) {
		if (classPtr == 0) return null;
		String name = known.get(classPtr);
		if (name != null) return name;
		// Not a local class — try reading name from class_ro_t anyway
		try {
			long roAddr = classRoFrom(classPtr);
			if (roAddr != 0) return className(roAddr);
		}
		catch (Exception ignored) {}
		return null;
	}

	// -----------------------------------------------------------------------
	// Method list parsing — supports big (24-byte) and small (12-byte) formats
	// -----------------------------------------------------------------------

	private JsonArray parseMethodList(long listPtr) {
		JsonArray arr = new JsonArray();
		if (listPtr == 0) return arr;
		try {
			long entsizeAndFlags = uint32(listPtr);      // +0x00
			long count           = uint32(listPtr + 4);  // +0x04
			if (count > 8192) return arr; // sanity cap

			// Relative entries can point either through a selref or directly at
			// selector bytes, depending on the direct-selector list flag.
			boolean small = (entsizeAndFlags & METHOD_LIST_IS_RELATIVE) != 0;
			boolean directSelectors =
				small && (entsizeAndFlags & METHOD_LIST_HAS_DIRECT_SELECTORS) != 0;
			long    entsize = small ? 12L : 24L;
			long    base    = listPtr + 8;

			for (long i = 0; i < count; i++) {
				long methodBase = base + i * entsize;
				JsonObject m = new JsonObject();
				try {
					if (small) {
						// Small method: 3 x int32 relative offsets. In direct
						// lists, name is selector text; otherwise it is a selref.
						int nameOff = sint32(methodBase);
						long nameRefAddr = methodBase + nameOff;
						String sel;
						if (directSelectors) {
							sel = cstring(nameRefAddr);
						}
						else {
							long namePtr = readPtr(nameRefAddr);
							sel = namePtr != 0 ? cstring(namePtr) : null;
						}

						// types: relative to the type encoding C string
						int typesOff = sint32(methodBase + 4);
						long typesAddr = methodBase + 4 + typesOff;
						String types = cstring(typesAddr);

						// imp: relative to the implementation
						int impOff = sint32(methodBase + 8);
						long impAddr = methodBase + 8 + impOff;

						m.addProperty("sel",      sel   != null ? sel   : "");
						m.addProperty("types",    types != null ? types : "");
						m.addProperty("imp_addr", hex(impAddr));
					}
					else {
						// Big method: 3 × 8-byte pointers
						long namePtr  = readPtr(methodBase);
						long typesPtr = readPtr(methodBase + 8);
						long impRaw   = rawLong(methodBase + 16);

						String sel   = namePtr  != 0 ? cstring(namePtr)  : null;
						String types = typesPtr != 0 ? cstring(typesPtr) : null;

						m.addProperty("sel",      sel   != null ? sel   : "");
						m.addProperty("types",    types != null ? types : "");
						m.addProperty("imp_addr", hex(impRaw & PAC_MASK));
					}
					arr.add(m);
				}
				catch (Exception e) {
					println("WARNING: skipping method at " + hex(methodBase) + ": " + e.getMessage());
				}
			}
		}
		catch (Exception ignored) {}
		return arr;
	}

	// -----------------------------------------------------------------------
	// Ivar list parsing
	// -----------------------------------------------------------------------

	private JsonArray parseIvarList(long listPtr) {
		JsonArray arr = new JsonArray();
		if (listPtr == 0) return arr;
		try {
			// ivar_list_t: entsize_and_flags (4), count (4), ivar_t[]
			long count = uint32(listPtr + 4);
			if (count > 4096) return arr; // sanity cap
			long base = listPtr + 8;
			// ivar_t size = 32 bytes
			//   +0x00: int32_t *offset (pointer to the ivar's byte offset)
			//   +0x08: const char *name
			//   +0x10: const char *type (type encoding)
			//   +0x18: uint32_t alignment_raw
			//   +0x1C: uint32_t size
			for (long i = 0; i < count; i++) {
				long ivarBase = base + i * 32;
				JsonObject iv = new JsonObject();
				try {
					long offsetPtr  = readPtr(ivarBase);
					long byteOffset = (offsetPtr != 0) ? uint32(offsetPtr) : 0;

					long namePtr = readPtr(ivarBase + 8);
					String ivarName = (namePtr != 0) ? cstring(namePtr) : null;

					long typePtr = readPtr(ivarBase + 16);
					String typeEnc = (typePtr != 0) ? cstring(typePtr) : null;

					long alignment = uint32(ivarBase + 24);
					long size      = uint32(ivarBase + 28);

					iv.addProperty("name",          ivarName != null ? ivarName : "");
					iv.addProperty("type_encoding", typeEnc  != null ? typeEnc  : "");
					iv.addProperty("offset",        byteOffset);
					iv.addProperty("size",          size);
					iv.addProperty("alignment",     alignment);
					arr.add(iv);
				}
				catch (Exception e) {
					println("WARNING: skipping ivar at " + hex(ivarBase) + ": " + e.getMessage());
				}
			}
		}
		catch (Exception ignored) {}
		return arr;
	}

	// -----------------------------------------------------------------------
	// Protocol list parsing
	// -----------------------------------------------------------------------

	private JsonArray parseProtocolList(long listPtr) {
		JsonArray arr = new JsonArray();
		if (listPtr == 0) return arr;
		try {
			// protocol_list_t: count (uintptr_t = 8 bytes), protocol_t*[]
			long count = rawLong(listPtr);
			if (count > 1024) return arr; // sanity cap
			for (long i = 0; i < count; i++) {
				long protoPtr = readPtr(listPtr + 8 + i * 8);
				if (protoPtr == 0) continue;
				try {
					// protocol_t.name is at offset +0x08
					long namePtr = readPtr(protoPtr + 8);
					if (namePtr != 0) {
						String name = cstring(namePtr);
						if (name != null && !name.isEmpty()) arr.add(name);
					}
				}
				catch (Exception ignored) {}
			}
		}
		catch (Exception ignored) {}
		return arr;
	}

	// -----------------------------------------------------------------------
	// Category parsing
	// -----------------------------------------------------------------------

	private JsonObject parseCategory(long catAddr, Map<Long, String> classAddrToName)
		throws MemoryAccessException {
		// category_t:
		//   +0x00: const char *name
		//   +0x08: class_t *cls
		//   +0x10: method_list_t *instanceMethods
		//   +0x18: method_list_t *classMethods
		//   +0x20: protocol_list_t *protocols
		//   +0x28: property_list_t *instanceProperties (unused here)
		long namePtr = readPtr(catAddr);
		String catName = (namePtr != 0) ? cstring(namePtr) : "?";

		long clsPtr = readPtr(catAddr + 8);
		String clsName = resolveClassName(clsPtr, classAddrToName);

		JsonObject obj = new JsonObject();
		String displayName = (clsName != null && !clsName.isEmpty())
			? clsName + "+" + catName : catName;
		obj.addProperty("name",     displayName);
		obj.addProperty("class",    clsName   != null ? clsName   : "");
		obj.addProperty("category", catName   != null ? catName   : "");

		obj.add("instance_methods", parseMethodList(readPtr(catAddr + 0x10)));
		obj.add("class_methods",    parseMethodList(readPtr(catAddr + 0x18)));
		obj.add("protocols",        parseProtocolList(readPtr(catAddr + 0x20)));
		return obj;
	}

	// -----------------------------------------------------------------------
	// Memory / address helpers
	// -----------------------------------------------------------------------

	/** Find a MemoryBlock whose name matches the ObjC section name (flexible). */
	private MemoryBlock findBlock(String sectionName) {
		String lower = sectionName.toLowerCase();
		// Strip leading underscores for a variant-agnostic search token
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

	/**
	 * Read an 8-byte pointer from a raw memory offset while masking PAC bits.
	 * Low address bits must be retained for unaligned strings and valid IMPs.
	 */
	private long readPtr(long offset) throws MemoryAccessException {
		long raw = rawLong(offset);
		long masked = raw & PAC_MASK;
		return masked;
	}

	/** Read 8 bytes little-endian with no masking. */
	private long rawLong(long offset) throws MemoryAccessException {
		return memory.getLong(addrSpace.getAddress(offset), false);
	}

	/** Read 4 bytes as unsigned integer. */
	private long uint32(long offset) throws MemoryAccessException {
		return memory.getInt(addrSpace.getAddress(offset), false) & 0xFFFFFFFFL;
	}

	/** Read 4 bytes as signed integer. */
	private int sint32(long offset) throws MemoryAccessException {
		return memory.getInt(addrSpace.getAddress(offset), false);
	}

	/** Read null-terminated C string, capped at 512 bytes. */
	private String cstring(long offset) {
		if (offset == 0) return null;
		StringBuilder sb = new StringBuilder();
		try {
			for (int i = 0; i < 512; i++) {
				byte b = memory.getByte(addrSpace.getAddress(offset + i));
				if (b == 0) break;
				sb.append((char)(b & 0xFF));
			}
		}
		catch (MemoryAccessException ignored) {}
		return sb.toString();
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
