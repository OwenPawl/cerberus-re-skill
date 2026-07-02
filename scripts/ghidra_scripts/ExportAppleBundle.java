/* ###
 * IP: GHIDRA
 */
//@category Export

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.util.DefinedStringIterator;

public class ExportAppleBundle extends AppleBundleInventorySupport {

	@Override
	protected void run() throws Exception {
		Map<String, String> args = parseArgs();
		String outdirValue = requireArg(args, "outdir");
		File outdir = new File(outdirValue);
		if (!outdir.exists() && !outdir.mkdirs()) {
			throw new IOException("failed to create output directory: " + outdir);
		}

		writeJson(new File(outdir, "program_summary.json"), buildProgramSummary());
		writeJson(new File(outdir, "objc_metadata.json"), buildObjcMetadata());
		writeJson(new File(outdir, "swift_metadata.json"), buildSwiftMetadata());
		writeJson(new File(outdir, "function_inventory.json"), buildFunctionInventory());
		writeJson(new File(outdir, "function_fingerprints.json"), buildFunctionFingerprints());
		writeJson(new File(outdir, "symbols.json"), buildSymbols());
		writeJson(new File(outdir, "strings.json"), buildStrings(16));
		println("Wrote export bundle to " + outdir.getAbsolutePath());
	}
}
