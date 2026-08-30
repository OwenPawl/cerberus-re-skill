/* ###
 * IP: GHIDRA
 */
package codexghidrabridge;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.WeakHashMap;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.app.services.ProgramManager;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectLocator;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

final class CodexBridgeIdentity {

	static final String SCHEMA_VERSION = "cerberus.bridge.v2";
	private static final Gson GSON =
		new GsonBuilder().disableHtmlEscaping().setPrettyPrinting().create();
	private static final String APPLICATION_ID = UUID.randomUUID().toString();
	private static final Map<PluginTool, String> TOOL_IDS = new WeakHashMap<>();

	private CodexBridgeIdentity() {
	}

	static String applicationId() {
		return APPLICATION_ID;
	}

	static synchronized String toolId(PluginTool tool) {
		return TOOL_IDS.computeIfAbsent(tool, ignored -> UUID.randomUUID().toString());
	}

	static String projectId(DomainFile domainFile) {
		return stableId("project", projectMarkerPath(domainFile));
	}

	static String programId(PluginTool tool, Program program) {
		if (program == null) {
			return "";
		}
		return stableId("program", APPLICATION_ID, toolId(tool), projectMarkerPath(program.getDomainFile()),
			domainPath(program));
	}

	static JsonObject programToJson(PluginTool tool, Program program, boolean current) {
		JsonObject object = new JsonObject();
		DomainFile domainFile = program == null ? null : program.getDomainFile();
		object.addProperty("program_id", programId(tool, program));
		object.addProperty("project_id", projectId(domainFile));
		object.addProperty("program_name", program == null ? "" : program.getName());
		object.addProperty("program_path", domainPath(program));
		object.addProperty("project_path", projectMarkerPath(domainFile));
		object.addProperty("current", current);
		object.addProperty("program_version", program == null ? 0L : program.getModificationNumber());
		object.addProperty("changed", domainFile != null && domainFile.isChanged());
		object.addProperty("read_only", domainFile != null && domainFile.isReadOnly());
		object.addProperty("executable_path", program == null ? "" : empty(program.getExecutablePath()));
		object.addProperty("executable_sha256", program == null ? "" : empty(program.getExecutableSHA256()));
		object.addProperty("executable_md5", program == null ? "" : empty(program.getExecutableMD5()));
		object.addProperty("language_id", program == null ? "" : program.getLanguageID().toString());
		return object;
	}

	static JsonArray openProgramsToJson(PluginTool tool) {
		JsonArray output = new JsonArray();
		ProgramManager manager = tool.getService(ProgramManager.class);
		if (manager == null) {
			return output;
		}
		Program current = manager.getCurrentProgram();
		List<Program> programs = new ArrayList<>();
		Program[] open = manager.getAllOpenPrograms();
		if (open != null) {
			for (Program program : open) {
				if (program != null) {
					programs.add(program);
				}
			}
		}
		programs.sort(Comparator.comparing(CodexBridgeIdentity::domainPath));
		for (Program program : programs) {
			output.add(programToJson(tool, program, program == current));
		}
		return output;
	}

	static JsonObject applicationInventory(Project project) {
		JsonObject inventory = new JsonObject();
		inventory.addProperty("version", 2);
		inventory.addProperty("schema_version", "cerberus.bridge.application.v2");
		inventory.addProperty("application_id", APPLICATION_ID);
		inventory.addProperty("pid", ProcessHandle.current().pid());
		inventory.addProperty("last_heartbeat", DateTimeFormatter.ISO_INSTANT.format(Instant.now()));
		inventory.addProperty("project_name", project == null ? "" : project.getName());
		ProjectLocator locator = project == null ? null : project.getProjectLocator();
		File marker = locator == null ? null : locator.getMarkerFile();
		inventory.addProperty("project_path", marker == null ? "" : marker.getAbsolutePath());
		JsonArray tools = new JsonArray();
		if (project != null && project.getToolServices() != null) {
			PluginTool[] running = project.getToolServices().getRunningTools();
			List<PluginTool> sorted = new ArrayList<>();
			if (running != null) {
				for (PluginTool runningTool : running) {
					if (runningTool != null) {
						sorted.add(runningTool);
					}
				}
			}
			sorted.sort(Comparator.comparing(PluginTool::getToolName).thenComparing(CodexBridgeIdentity::toolId));
			for (PluginTool runningTool : sorted) {
				tools.add(toolToJson(runningTool));
			}
		}
		inventory.add("tools", tools);
		return inventory;
	}

	static File applicationFile(File configDir) {
		return new File(new File(configDir, "bridge-applications"), APPLICATION_ID + ".json");
	}

	static void writeApplicationInventory(File configDir, Project project) throws IOException {
		writeJson(applicationFile(configDir), applicationInventory(project));
	}

	static void writeJson(File output, JsonObject payload) throws IOException {
		File parent = output.getParentFile();
		if (!parent.exists() && !parent.mkdirs()) {
			throw new IOException("failed to create " + parent);
		}
		File temporary = new File(parent, output.getName() + "." + UUID.randomUUID() + ".tmp");
		Files.writeString(temporary.toPath(), GSON.toJson(payload) + "\n", StandardCharsets.UTF_8);
		try {
			Files.move(temporary.toPath(), output.toPath(), StandardCopyOption.REPLACE_EXISTING,
				StandardCopyOption.ATOMIC_MOVE);
		}
		catch (AtomicMoveNotSupportedException e) {
			Files.move(temporary.toPath(), output.toPath(), StandardCopyOption.REPLACE_EXISTING);
		}
	}

	private static JsonObject toolToJson(PluginTool tool) {
		JsonObject object = new JsonObject();
		object.addProperty("tool_id", toolId(tool));
		object.addProperty("tool_name", tool.getToolName());
		object.add("open_programs", openProgramsToJson(tool));
		CodexBridgePlugin bridge = bridgePlugin(tool);
		object.addProperty("bridge_armed", bridge != null && bridge.isBridgeArmed());
		object.addProperty("bridge_session_id", bridge == null ? "" : bridge.getSessionId());
		object.addProperty("bridge_url", bridge == null ? "" : bridge.getBridgeUrl());
		return object;
	}

	private static CodexBridgePlugin bridgePlugin(PluginTool tool) {
		for (Plugin plugin : tool.getManagedPlugins()) {
			if (plugin instanceof CodexBridgePlugin bridge) {
				return bridge;
			}
		}
		return null;
	}

	private static String projectMarkerPath(DomainFile domainFile) {
		ProjectLocator locator = domainFile == null ? null : domainFile.getProjectLocator();
		File marker = locator == null ? null : locator.getMarkerFile();
		return marker == null ? "" : marker.getAbsolutePath();
	}

	private static String domainPath(Program program) {
		DomainFile domainFile = program == null ? null : program.getDomainFile();
		return domainFile == null ? "" : domainFile.getPathname();
	}

	private static String stableId(String kind, String... values) {
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			digest.update((kind + "\n").getBytes(StandardCharsets.UTF_8));
			for (String value : values) {
				digest.update(empty(value).getBytes(StandardCharsets.UTF_8));
				digest.update((byte) '\n');
			}
			StringBuilder output = new StringBuilder(kind).append('-');
			for (byte value : digest.digest()) {
				output.append(String.format("%02x", value));
			}
			return output.substring(0, Math.min(output.length(), kind.length() + 1 + 32));
		}
		catch (Exception e) {
			throw new IllegalStateException("SHA-256 unavailable", e);
		}
	}

	private static String empty(String value) {
		return value == null ? "" : value;
	}
}
