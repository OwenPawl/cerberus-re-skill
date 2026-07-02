/* ###
 * IP: GHIDRA
 */
//@category Apple.Export

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.bin.format.macho.CpuTypes;
import ghidra.app.util.bin.format.macho.MachHeader;
import ghidra.app.util.bin.format.macho.Section;
import ghidra.app.util.bin.format.macho.commands.BuildVersionCommand;
import ghidra.app.util.bin.format.macho.commands.DyldInfoCommand;
import ghidra.app.util.bin.format.macho.commands.DynamicLibraryCommand;
import ghidra.app.util.bin.format.macho.commands.EncryptedInformationCommand;
import ghidra.app.util.bin.format.macho.commands.LinkEditDataCommand;
import ghidra.app.util.bin.format.macho.commands.LoadCommand;
import ghidra.app.util.bin.format.macho.commands.LoadCommandTypes;
import ghidra.app.util.bin.format.macho.commands.LoadCommandString;
import ghidra.app.util.bin.format.macho.commands.RunPathCommand;
import ghidra.app.util.bin.format.macho.commands.SegmentCommand;
import ghidra.app.util.bin.format.macho.commands.SourceVersionCommand;
import ghidra.app.util.bin.format.macho.commands.SubFrameworkCommand;
import ghidra.app.util.bin.format.macho.commands.UuidCommand;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

/**
 * ExportMachOStructure — dump Mach-O structural metadata to JSON.
 *
 * Outputs: macho_structure.json
 *
 * Schema:
 * {
 *   "program_name": "...",
 *   "executable_format": "...",
 *   "image_base": "0x...",
 *   "arch": "...",
 *   "cpu_subtype": N,
 *   "filetype": "...",
 *   "flags": N,
 *   "uuid": "...",
 *   "build_version": { "platform": "...", "minos": "...", "sdk": "..." },
 *   "source_version": "...",
 *   "encryption": { "offset": N, "size": N, "id": N },
 *   "segments": [ { "name", "vm_addr", "vm_size", "file_off", "file_size",
 *                    "max_prot", "init_prot", "sections": [...] } ],
 *   "dylibs": [ { "ordinal", "name", "compatibility_version", "current_version",
 *                  "kind": "load|weak|reexport|lazy" } ],
 *   "rpaths": [ "..." ],
 *   "sub_framework": "...",
 *   "code_signature_offset": N,
 *   "code_signature_size": N,
 *   "memory_blocks": [ { "name", "start", "end", "size", "read", "write",
 *                         "execute", "overlay", "volatile", "type" } ]
 * }
 *
 * Args:
 *   output=<path>        Required. Destination JSON file.
 *   use_memory_parse=1   Default 1. Parse MachHeader from mapped memory.
 *                        Set to 0 to skip and emit only memory-block info.
 */
public class ExportMachOStructure extends GhidraScript {

	@Override
	protected void run() throws Exception {
		Map<String, String> args = parseArgs();
		String outputPath = requireArg(args, "output");
		boolean useMemoryParse =
			!"0".equals(args.getOrDefault("use_memory_parse", "1"));

		JsonObject payload = new JsonObject();
		payload.addProperty("program_name", currentProgram.getName());
		payload.addProperty("executable_format",
			currentProgram.getExecutableFormat());
		payload.addProperty("image_base",
			hex(currentProgram.getImageBase().getOffset()));

		// Memory blocks — always available
		payload.add("memory_blocks", buildMemoryBlocks());

		// External libraries — always available via Ghidra's external manager
		payload.add("dylibs_from_ext_manager", buildExternalLibraries());

		// Mach-O header parsing from mapped memory
		if (useMemoryParse) {
			try {
				parseMachHeader(payload);
			}
			catch (Exception e) {
				payload.addProperty("macho_parse_error", e.getMessage());
				println("WARNING: Mach-O header parse failed: " + e.getMessage() +
					" — falling back to memory-block info only.");
			}
		}

		// Entitlements via codesign subprocess
		String entitlements = extractEntitlements();
		if (entitlements != null) {
			payload.addProperty("entitlements_plist", entitlements);
		}

		TriageSupport.writeJson(new File(outputPath), payload);
		println("Wrote " + outputPath);
	}

	// ---------------------------------------------------------------------------
	// Mach-O header via MemoryByteProvider
	// ---------------------------------------------------------------------------

	private void parseMachHeader(JsonObject out) throws Exception {
		Memory memory = currentProgram.getMemory();
		ByteProvider provider =
			new MemoryByteProvider(memory, currentProgram.getImageBase());
		MachHeader header = new MachHeader(provider);
		header.parse();

		out.addProperty("arch", cpuTypeString(header.getCpuType()));
		out.addProperty("cpu_subtype", header.getCpuSubType());
		out.addProperty("filetype", filetypeString(header.getFileType()));
		out.addProperty("flags", header.getFlags());

		// Load commands
		JsonArray segments = new JsonArray();
		JsonArray dylibs = new JsonArray();
		JsonArray rpaths = new JsonArray();
		String uuid = null;
		JsonObject buildVersion = null;
		String sourceVersion = null;
		JsonObject encryption = null;
		String subFramework = null;
		long csOffset = -1, csSize = -1;

		int dylibOrdinal = 1;
		for (LoadCommand cmd : header.getLoadCommands()) {
			int type = cmd.getCommandType();

			if (cmd instanceof SegmentCommand) {
				segments.add(segmentToJson((SegmentCommand) cmd));
			}
			else if (cmd instanceof UuidCommand) {
				uuid = ((UuidCommand) cmd).getUUID().toString().toUpperCase();
			}
			else if (cmd instanceof BuildVersionCommand) {
				BuildVersionCommand bvc = (BuildVersionCommand) cmd;
				buildVersion = new JsonObject();
				buildVersion.addProperty("platform",
					platformString(bvc.getPlatform()));
				buildVersion.addProperty("minos",
					versionString(bvc.getMinOS()));
				buildVersion.addProperty("sdk",
					versionString(bvc.getSdk()));
			}
			else if (cmd instanceof SourceVersionCommand) {
				sourceVersion =
					sourceVersionString(((SourceVersionCommand) cmd).getVersion());
			}
			else if (cmd instanceof EncryptedInformationCommand) {
				EncryptedInformationCommand enc = (EncryptedInformationCommand) cmd;
				encryption = new JsonObject();
				encryption.addProperty("offset", enc.getCryptOffset());
				encryption.addProperty("size", enc.getCryptSize());
				encryption.addProperty("id", enc.getCryptID());
			}
			else if (cmd instanceof DynamicLibraryCommand) {
				DynamicLibraryCommand dc = (DynamicLibraryCommand) cmd;
				JsonObject dylib = new JsonObject();
				dylib.addProperty("ordinal", dylibOrdinal++);
				dylib.addProperty("name", loadCommandString(dc.getDynamicLibrary().getName()));
				dylib.addProperty("compatibility_version",
					versionString(dc.getDynamicLibrary().getCompatibilityVersion()));
				dylib.addProperty("current_version",
					versionString(dc.getDynamicLibrary().getCurrentVersion()));
				dylib.addProperty("kind", dylibKind(type));
				dylibs.add(dylib);
			}
			else if (cmd instanceof RunPathCommand) {
				rpaths.add(loadCommandString(((RunPathCommand) cmd).getPath()));
			}
			else if (cmd instanceof SubFrameworkCommand) {
				subFramework =
					loadCommandString(((SubFrameworkCommand) cmd).getUmbrellaFrameworkName());
			}
			else if (type == LoadCommandTypes.LC_CODE_SIGNATURE) {
				if (cmd instanceof LinkEditDataCommand) {
					csOffset = cmd.getLinkerDataOffset();
					csSize = cmd.getLinkerDataSize();
				}
			}
		}

		out.add("segments", segments);
		out.add("dylibs", dylibs);
		out.add("rpaths", rpaths);
		if (uuid != null) {
			out.addProperty("uuid", uuid);
		}
		if (buildVersion != null) {
			out.add("build_version", buildVersion);
		}
		if (sourceVersion != null) {
			out.addProperty("source_version", sourceVersion);
		}
		if (encryption != null) {
			out.add("encryption", encryption);
		}
		if (subFramework != null) {
			out.addProperty("sub_framework", subFramework);
		}
		if (csOffset >= 0) {
			out.addProperty("code_signature_offset", csOffset);
			out.addProperty("code_signature_size", csSize);
		}
	}

	private JsonObject segmentToJson(SegmentCommand seg) {
		JsonObject obj = new JsonObject();
		obj.addProperty("name", seg.getSegmentName());
		obj.addProperty("vm_addr", hex(seg.getVMaddress()));
		obj.addProperty("vm_size", seg.getVMsize());
		obj.addProperty("file_off", seg.getFileOffset());
		obj.addProperty("file_size", seg.getFileSize());
		obj.addProperty("max_prot", seg.getMaxProtection());
		obj.addProperty("init_prot", seg.getInitProtection());
		JsonArray sections = new JsonArray();
		for (Section s : seg.getSections()) {
			JsonObject sec = new JsonObject();
			sec.addProperty("name",
				s.getSegmentName() + "," + s.getSectionName());
			sec.addProperty("addr", hex(s.getAddress()));
			sec.addProperty("size", s.getSize());
			sec.addProperty("offset", s.getOffset());
			sec.addProperty("align", s.getAlign());
			sec.addProperty("flags", s.getFlags());
			sections.add(sec);
		}
		obj.add("sections", sections);
		return obj;
	}

	// ---------------------------------------------------------------------------
	// Memory blocks — always available
	// ---------------------------------------------------------------------------

	private JsonArray buildMemoryBlocks() {
		JsonArray arr = new JsonArray();
		for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
			JsonObject obj = new JsonObject();
			obj.addProperty("name", block.getName());
			obj.addProperty("start", block.getStart().toString());
			obj.addProperty("end", block.getEnd().toString());
			obj.addProperty("size", block.getSize());
			obj.addProperty("read", block.isRead());
			obj.addProperty("write", block.isWrite());
			obj.addProperty("execute", block.isExecute());
			obj.addProperty("overlay", block.isOverlay());
			obj.addProperty("volatile", block.isVolatile());
			obj.addProperty("type", block.getType().toString());
			arr.add(obj);
		}
		return arr;
	}

	// ---------------------------------------------------------------------------
	// External libraries via Ghidra's external manager
	// ---------------------------------------------------------------------------

	private JsonArray buildExternalLibraries() {
		JsonArray arr = new JsonArray();
		for (String name : currentProgram.getExternalManager().getExternalLibraryNames()) {
			arr.add(name);
		}
		return arr;
	}

	// ---------------------------------------------------------------------------
	// Entitlements via codesign subprocess
	// ---------------------------------------------------------------------------

	private String extractEntitlements() {
		String execPath = currentProgram.getExecutablePath();
		if (execPath == null || execPath.isEmpty()) {
			return null;
		}
		java.io.File f = new java.io.File(execPath);
		if (!f.exists()) {
			return null;
		}
		try {
			ProcessBuilder pb = new ProcessBuilder(
				"codesign", "-d", "--entitlements", ":-", execPath);
			pb.redirectErrorStream(true);
			Process proc = pb.start();
			byte[] output = proc.getInputStream().readAllBytes();
			int exit = proc.waitFor();
			if (exit == 0 && output.length > 0) {
				String text = new String(output, java.nio.charset.StandardCharsets.UTF_8).trim();
				if (text.contains("<?xml") || text.contains("<plist")) {
					return text;
				}
			}
		}
		catch (Exception ignored) {
			// codesign not available or binary not on local filesystem
		}
		return null;
	}

	// ---------------------------------------------------------------------------
	// String helpers
	// ---------------------------------------------------------------------------

	private static String hex(long value) {
		return "0x" + Long.toHexString(value);
	}

	private static String loadCommandString(LoadCommandString value) {
		if (value == null) {
			return "";
		}
		try {
			return value.getString();
		}
		catch (Exception e) {
			return String.valueOf(value);
		}
	}

	private static String cpuTypeString(int cpuType) {
		switch (cpuType) {
			case CpuTypes.CPU_TYPE_ARM_64:  return "arm64";
			case CpuTypes.CPU_TYPE_ARM:     return "arm";
			case CpuTypes.CPU_TYPE_X86_64:  return "x86_64";
			case CpuTypes.CPU_TYPE_X86:     return "x86";
			default: return "cpu_" + cpuType;
		}
	}

	private static String filetypeString(int ft) {
		switch (ft) {
			case 0x1:  return "object";
			case 0x2:  return "execute";
			case 0x6:  return "dylib";
			case 0x7:  return "dylinker";
			case 0x8:  return "bundle";
			case 0x9:  return "dylib_stub";
			case 0xa:  return "dsym";
			case 0xb:  return "kext_bundle";
			default:   return "filetype_" + ft;
		}
	}

	private static String platformString(int p) {
		switch (p) {
			case 1:  return "macOS";
			case 2:  return "iOS";
			case 3:  return "tvOS";
			case 4:  return "watchOS";
			case 5:  return "bridgeOS";
			case 6:  return "macCatalyst";
			case 7:  return "iOSSimulator";
			case 8:  return "tvOSSimulator";
			case 9:  return "watchOSSimulator";
			case 10: return "driverKit";
			default: return "platform_" + p;
		}
	}

	private static String versionString(int packed) {
		int major = (packed >> 16) & 0xFFFF;
		int minor = (packed >> 8) & 0xFF;
		int patch = packed & 0xFF;
		return major + "." + minor + "." + patch;
	}

	private static String sourceVersionString(long packed) {
		// A.B.C.D.E encoding from LC_SOURCE_VERSION
		long a = (packed >> 40) & 0xFFFFFF;
		long b = (packed >> 30) & 0x3FF;
		long c = (packed >> 20) & 0x3FF;
		long d = (packed >> 10) & 0x3FF;
		long e = packed & 0x3FF;
		return a + "." + b + "." + c + "." + d + "." + e;
	}

	private static String dylibKind(int cmdType) {
		switch (cmdType) {
			case LoadCommandTypes.LC_LOAD_DYLIB:         return "load";
			case LoadCommandTypes.LC_LOAD_WEAK_DYLIB:    return "weak";
			case LoadCommandTypes.LC_REEXPORT_DYLIB:     return "reexport";
			case LoadCommandTypes.LC_LAZY_LOAD_DYLIB:    return "lazy";
			case LoadCommandTypes.LC_LOAD_UPWARD_DYLIB:  return "upward";
			default: return "load";
		}
	}

	// ---------------------------------------------------------------------------
	// Arg parsing (shared pattern with other scripts)
	// ---------------------------------------------------------------------------

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
			throw new IllegalArgumentException(
				"Missing required argument: " + key + "=...");
		}
		return v;
	}
}
