/* ###
 * IP: GHIDRA
 */
package codexghidrabridge;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Comparator;

import javax.swing.Timer;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.CorePluginPackage;
import ghidra.framework.main.ApplicationLevelOnlyPlugin;
import ghidra.framework.main.FrontEndPlugin;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginException;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;

//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = CorePluginPackage.NAME,
	category = "Codex",
	shortDescription = "Codex front-end bridge helper.",
	description = "Opens the requested project domain file in a live tool so the Codex bridge can arm against a real CodeBrowser session."
)
//@formatter:on
public class CodexBridgeFrontEndPlugin extends Plugin implements ApplicationLevelOnlyPlugin {

	private static final long OPEN_RETRY_INTERVAL_MS = 5000L;

	private final File requestsDir;
	private final File legacyControlFile;
	private Timer controlTimer;
	private String lastOpenRequestKey = "";
	private long lastOpenAttemptAt = 0L;

	public CodexBridgeFrontEndPlugin(PluginTool tool) {
		super(tool);
		File configDir = new File(new File(System.getProperty("user.home"), ".config"), "ghidra-re");
		this.requestsDir = new File(configDir, "bridge-requests");
		this.legacyControlFile = new File(configDir, "bridge-control.json");
	}

	@Override
	protected void init() {
		super.init();
		if (controlTimer != null) {
			return;
		}
		controlTimer = new Timer(1000, event -> pollControlRequests());
		controlTimer.setRepeats(true);
		controlTimer.start();
		Msg.info(this, "Codex front-end bridge helper ready");
	}

	@Override
	protected void dispose() {
		if (controlTimer != null) {
			controlTimer.stop();
			controlTimer = null;
		}
		super.dispose();
	}

	private void pollControlRequests() {
		try {
			pollLegacyControlFile();
			if (!requestsDir.exists()) {
				return;
			}
			File[] requestFiles =
				requestsDir.listFiles((dir, name) -> name != null && name.endsWith(".json"));
			if (requestFiles == null || requestFiles.length == 0) {
				return;
			}
			Arrays.sort(requestFiles, Comparator.comparing(File::getName));
			for (File requestFile : requestFiles) {
				processRequestFile(requestFile);
			}
		}
		catch (Exception e) {
			Msg.warn(this, "Codex front-end bridge helper will retry control file: " +
				e.getMessage());
		}
	}

	private void pollLegacyControlFile() throws IOException {
		if (!legacyControlFile.exists()) {
			return;
		}
		JsonObject request = readJsonObject(legacyControlFile);
		if (processRequest(request)) {
			legacyControlFile.delete();
		}
	}

	private void processRequestFile(File requestFile) {
		try {
			JsonObject request = readJsonObject(requestFile);
			if (processRequest(request)) {
				requestFile.delete();
			}
		}
		catch (Exception e) {
			Msg.warn(this, "Codex front-end helper will retry request file " +
				requestFile.getName() + ": " + e.getMessage());
		}
	}

	private boolean processRequest(JsonObject request) {
		String command = optString(request, "command");
		if (!"arm".equalsIgnoreCase(command)) {
			return false;
		}
		return handleArmRequest(request);
	}

	private boolean handleArmRequest(JsonObject request) {
		Project project = tool.getProject();
		if (project == null) {
			Msg.info(this, "Codex front-end helper saw arm request before project was available");
			return false;
		}

		String requestedProject = optString(request, "project_name");
		if (!requestedProject.isEmpty() && !requestedProject.equals(project.getName())) {
			Msg.info(this, "Codex front-end helper ignoring arm request for project " + requestedProject +
				" while " + project.getName() + " is active");
			return false;
		}

		String requestedProgram = optString(request, "program_name");
		if (requestedProgram.isEmpty()) {
			Msg.info(this, "Codex front-end helper saw arm request without a program name");
			return false;
		}

		Msg.info(this, "Codex front-end helper processing arm request for " + requestedProgram +
			" in project " + project.getName());

		PluginTool runningTool = findRunningToolForProgram(project, requestedProgram);
		if (runningTool != null) {
			Msg.info(this, "Codex front-end helper found running tool " + runningTool.getToolName() +
				" for " + requestedProgram);
			CodexBridgePlugin bridgePlugin = ensureBridgePlugin(runningTool);
			if (bridgePlugin == null) {
				return false;
			}
			if (!bridgePlugin.isBridgeArmed()) {
				try {
					bridgePlugin.armBridge("front-end-handoff");
				}
				catch (IOException e) {
					Msg.error(this, "Codex front-end helper could not arm bridge plugin", e);
					return false;
				}
			}
			if (bridgePlugin.isBridgeArmed()) {
				Msg.info(this, "Codex front-end helper armed bridge through " +
					runningTool.getToolName());
				lastOpenRequestKey = "";
				lastOpenAttemptAt = 0L;
				return true;
			}
			return false;
		}

		DomainFile domainFile = resolveDomainFile(project, requestedProgram);
		if (domainFile == null) {
			Msg.error(this, "Codex front-end helper could not resolve program " + requestedProgram +
				" in project " + project.getName(), null);
			return false;
		}

		FrontEndPlugin frontEndPlugin = findFrontEndPlugin();
		if (frontEndPlugin == null) {
			Msg.error(this, "Codex front-end helper could not find FrontEndPlugin", null);
			return false;
		}

		if (shouldSkipOpenAttempt(requestedProject, requestedProgram)) {
			return false;
		}

		Msg.info(this, "Codex front-end helper opening " + domainFile.getPathname());
		recordOpenAttempt(requestedProject, requestedProgram);
		frontEndPlugin.openDomainFile(domainFile);
		return false;
	}

	private void recordOpenAttempt(String requestedProject, String requestedProgram) {
		lastOpenRequestKey = requestKey(requestedProject, requestedProgram);
		lastOpenAttemptAt = System.currentTimeMillis();
	}

	private boolean shouldSkipOpenAttempt(String requestedProject, String requestedProgram) {
		String requestKey = requestKey(requestedProject, requestedProgram);
		if (!requestKey.equals(lastOpenRequestKey)) {
			return false;
		}
		return System.currentTimeMillis() - lastOpenAttemptAt < OPEN_RETRY_INTERVAL_MS;
	}

	private String requestKey(String requestedProject, String requestedProgram) {
		return requestedProject + "\n" + requestedProgram;
	}

	private PluginTool findRunningToolForProgram(Project project, String requestedProgram) {
		if (project == null || project.getToolServices() == null) {
			return null;
		}
		PluginTool[] runningTools = project.getToolServices().getRunningTools();
		Msg.info(this, "Codex front-end helper sees " + runningTools.length +
			" running tool(s) while looking for " + requestedProgram);
		for (PluginTool runningTool : runningTools) {
			if (runningTool == null || runningTool == tool) {
				continue;
			}
			for (DomainFile domainFile : runningTool.getDomainFiles()) {
				if (matchesRequestedProgram(domainFile, requestedProgram)) {
					return runningTool;
				}
			}
		}
		return null;
	}

	private CodexBridgePlugin ensureBridgePlugin(PluginTool targetTool) {
		for (Plugin plugin : targetTool.getManagedPlugins()) {
			if (plugin instanceof CodexBridgePlugin bridgePlugin) {
				return bridgePlugin;
			}
		}
		try {
			targetTool.addPlugin(CodexBridgePlugin.class.getName());
		}
		catch (PluginException e) {
			Msg.error(this, "Codex front-end helper could not add CodexBridgePlugin to " +
				targetTool.getToolName(), e);
			return null;
		}
		for (Plugin plugin : targetTool.getManagedPlugins()) {
			if (plugin instanceof CodexBridgePlugin bridgePlugin) {
				return bridgePlugin;
			}
		}
		Msg.error(this, "Codex front-end helper added CodexBridgePlugin but could not find it in " +
			targetTool.getToolName(), null);
		return null;
	}

	private FrontEndPlugin findFrontEndPlugin() {
		for (Plugin plugin : tool.getManagedPlugins()) {
			if (plugin instanceof FrontEndPlugin frontEndPlugin) {
				return frontEndPlugin;
			}
		}
		return null;
	}

	private DomainFile resolveDomainFile(Project project, String requestedProgram) {
		ProjectData projectData = project.getProjectData();
		String normalizedPath = normalizeProjectPath(requestedProgram);
		DomainFile direct = projectData.getFile(normalizedPath);
		if (direct != null) {
			return direct;
		}

		String bareName = requestedProgram;
		int slashIndex = bareName.lastIndexOf('/');
		if (slashIndex >= 0 && slashIndex + 1 < bareName.length()) {
			bareName = bareName.substring(slashIndex + 1);
		}

		for (DomainFile domainFile : projectData) {
			if (domainFile == null) {
				continue;
			}
			if (matchesRequestedProgram(domainFile, requestedProgram) ||
				domainFile.getName().equals(bareName)) {
				return domainFile;
			}
		}
		return null;
	}

	private boolean matchesRequestedProgram(DomainFile domainFile, String requestedProgram) {
		if (domainFile == null) {
			return false;
		}
		String normalizedPath = normalizeProjectPath(requestedProgram);
		String pathname = domainFile.getPathname();
		return domainFile.getName().equals(requestedProgram) ||
			(normalizedPath != null && normalizedPath.equals(pathname));
	}

	private String normalizeProjectPath(String requestedProgram) {
		if (requestedProgram == null || requestedProgram.isEmpty()) {
			return "/";
		}
		if (requestedProgram.startsWith("/")) {
			return requestedProgram;
		}
		return "/" + requestedProgram;
	}

	private JsonObject readJsonObject(File file) throws IOException {
		try (InputStream input = new FileInputStream(file);
				Reader reader = new BufferedReader(
					new InputStreamReader(input, StandardCharsets.UTF_8))) {
			return JsonParser.parseReader(reader).getAsJsonObject();
		}
	}

	private String optString(JsonObject object, String key) {
		if (object == null || !object.has(key) || object.get(key).isJsonNull()) {
			return "";
		}
		return object.get(key).getAsString();
	}
}
