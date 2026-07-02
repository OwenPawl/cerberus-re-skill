/* ###
 * IP: GHIDRA
 */
package codexghidrabridge;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.io.Writer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.swing.Timer;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.ProjectLocator;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.QWordDataType;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.UnicodeDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.LocalVariable;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;


class CodexBridgeService extends CodexBridgeReadSupport {


	private static final List<String> CAPABILITIES = Collections.unmodifiableList(Arrays.asList(
		"/health",
		"/session",
		"/context",
		"/analyze/target",
		"/functions/search",
		"/function",
		"/decompile",
		"/references",
		"/data/get",
		"/strings/search",
		"/symbols/get",
		"/symbols/xrefs",
		"/memory/range",
		"/variables",
		"/datatypes/search",
		"/objc/selector-trace",
		"/navigate",
		"/program/save",
		"/edit/rename",
		"/edit/comment",
		"/edit/bookmark",
		"/edit/function-signature",
		"/edit/variable",
		"/edit/datatype",
		"/patch/bytes",
		"/patch/instruction",
		"/listing/clear",
		"/listing/disassemble",
		"/function/create",
		"/function/delete",
		"/function/fixup",
		"/data/create",
		"/data/delete"));


	private final File configDir;
	private final File sessionsDir;
	private final File requestsDir;
	private final File legacyControlFile;

	private HttpServer server;
	private ExecutorService executor;
	private Timer controlTimer;

	CodexBridgeService(CodexBridgePlugin plugin, CodexBridgeProvider provider) {
		super(plugin, provider);
		this.configDir = new File(new File(System.getProperty("user.home"), ".config"), "ghidra-re");
		this.sessionsDir = new File(configDir, "bridge-sessions");
		this.requestsDir = new File(configDir, "bridge-requests");
		this.legacyControlFile = new File(configDir, "bridge-control.json");
	}

	void start() {
		if (controlTimer != null) {
			return;
		}
		controlTimer = new Timer(1000, event -> pollControlRequests());
		controlTimer.setRepeats(true);
		controlTimer.start();
	}

	void dispose() {
		if (controlTimer != null) {
			controlTimer.stop();
			controlTimer = null;
		}
		disarm("dispose");
	}

	synchronized void arm(String reason) throws IOException {
		ensureConfigDir();
		if (armed && server != null) {
			writeSessionFile();
			log("bridge already armed (" + reason + ")");
			return;
		}
		server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
		server.createContext("/", this::handleExchange);
		executor = Executors.newCachedThreadPool();
		server.setExecutor(executor);
		server.start();
		armed = true;
		token = UUID.randomUUID().toString().replace("-", "") + UUID.randomUUID().toString().replace("-", "");
		bridgeUrl = "http://127.0.0.1:" + server.getAddress().getPort();
		startedAt = DateTimeFormatter.ISO_INSTANT.format(Instant.now());
		lastHeartbeatMillis = System.currentTimeMillis();
		writeSessionFile();
		log("bridge armed (" + reason + ") at " + bridgeUrl);
	}

	synchronized void disarm(String reason) {
		if (server != null) {
			server.stop(0);
			server = null;
		}
		if (executor != null) {
			executor.shutdownNow();
			executor = null;
		}
		if (armed) {
			log("bridge disarmed (" + reason + ")");
		}
		armed = false;
		bridgeUrl = "";
		token = "";
		startedAt = "";
		lastHeartbeatMillis = 0L;
		File sessionFile = sessionFile();
		if (sessionFile.exists()) {
			sessionFile.delete();
		}
	}

	boolean isArmed() {
		return armed;
	}

	String getBridgeUrl() {
		return bridgeUrl;
	}

	void onProgramOpened(Program program) {
		updateSessionIfArmed();
	}

	void onProgramActivated(Program program) {
		updateSessionIfArmed();
		pollControlRequests();
	}

	void onProgramDeactivated(Program program) {
		updateSessionIfArmed();
	}

	void onProgramClosed(Program program) {
		updateSessionIfArmed();
	}

	void onContextChanged() {
		updateSessionIfArmed();
	}

	void onProgramMutated() {
		updateSessionIfArmed();
	}

	String describeProgram(Program program) {
		if (program == null) {
			return "";
		}
		DomainFile domainFile = program.getDomainFile();
		if (domainFile == null) {
			return program.getName();
		}
		return program.getName() + " [" + domainFile.getPathname() + "]";
	}

	private void ensureConfigDir() throws IOException {
		if (!configDir.exists() && !configDir.mkdirs()) {
			throw new IOException("failed to create " + configDir);
		}
		if (!sessionsDir.exists() && !sessionsDir.mkdirs()) {
			throw new IOException("failed to create " + sessionsDir);
		}
		if (!requestsDir.exists() && !requestsDir.mkdirs()) {
			throw new IOException("failed to create " + requestsDir);
		}
	}

	@Override
	protected void writeSessionFile() throws IOException {
		ensureConfigDir();
		RepositoryState repository = repositoryStateFor(plugin.getCurrentProgram());
		JsonObject session = new JsonObject();
		session.addProperty("version", 1);
		session.addProperty("session_id", sessionId);
		session.addProperty("bridge_url", bridgeUrl);
		session.addProperty("token", token);
		session.addProperty("pid", ProcessHandle.current().pid());
		session.addProperty("tool_name", plugin.getTool().getToolName());
		session.addProperty("project_name", repository.projectName);
		session.addProperty("project_path", repository.projectMarkerPath);
		session.addProperty("program_name", repository.programName);
		session.addProperty("program_path", repository.domainPath);
		session.addProperty("started_at", startedAt);
		session.addProperty("last_heartbeat", DateTimeFormatter.ISO_INSTANT.format(Instant.now()));
		session.addProperty("armed", armed);
		JsonArray capabilities = new JsonArray();
		for (String capability : CAPABILITIES) {
			capabilities.add(capability);
		}
		session.add("capabilities", capabilities);
		session.add("repository", repositoryToJson(repository));
		writeJson(sessionFile(), session);
	}

	private File sessionFile() {
		return new File(sessionsDir, sessionId + ".json");
	}

	private void pollLegacyControlFile() throws Exception {
		if (!legacyControlFile.exists()) {
			return;
		}
		JsonObject request = readJsonObject(legacyControlFile);
		if (requestMatches(request)) {
			processRequest(request, "legacy-control");
			legacyControlFile.delete();
		}
	}

	private void processRequestFile(File requestFile) throws Exception {
		JsonObject request = readJsonObject(requestFile);
		if (!requestMatches(request)) {
			return;
		}
		processRequest(request, requestFile.getName());
		requestFile.delete();
	}

	private void processRequest(JsonObject request, String source) throws Exception {
		String command = optString(request, "command");
		if (command.isEmpty()) {
			return;
		}
		if ("arm".equalsIgnoreCase(command)) {
			arm("request:" + source);
			return;
		}
		if ("disarm".equalsIgnoreCase(command)) {
			disarm("request:" + source);
		}
	}

	private boolean requestMatches(JsonObject request) {
		String requestedSession = optString(request, "session_id");
		String requestedProject = optString(request, "project_name");
		String requestedProgram = optString(request, "program_name");
		if (!requestedSession.isEmpty() && !sessionId.equals(requestedSession)) {
			return false;
		}
		String activeProject = activeProjectName();
		if (!requestedProject.isEmpty() && !requestedProject.equals(activeProject)) {
			return false;
		}
		if (requestedProgram.isEmpty()) {
			return true;
		}
		Program program = plugin.getCurrentProgram();
		if (program == null) {
			return !requestedProject.isEmpty() && requestedProject.equals(activeProject);
		}
		String activeProgramName = program.getName();
		String activeProgramPath = programPath(program);
		return requestedProgram.equals(activeProgramName) ||
			requestedProgram.equals(activeProgramPath) ||
			activeProgramPath.endsWith("/" + requestedProgram);
	}

	private void pollControlRequests() {
		try {
			pollLegacyControlFile();
			File[] requestFiles =
				requestsDir.listFiles((dir, name) -> name != null && name.endsWith(".json"));
			if (requestFiles != null) {
				Arrays.sort(requestFiles, Comparator.comparing(File::getName));
				for (File requestFile : requestFiles) {
					processRequestFile(requestFile);
				}
			}
			if (armed && (System.currentTimeMillis() - lastHeartbeatMillis) >= 1000L) {
				lastHeartbeatMillis = System.currentTimeMillis();
				writeSessionFile();
			}
		}
		catch (Exception e) {
			log("request processing error: " + e.getMessage());
		}
	}

	private void handleExchange(HttpExchange exchange) throws IOException {
		String path = exchange.getRequestURI().getPath();
		JsonObject body = new JsonObject();
		try {
			if (!armed) {
				sendJson(exchange, 503, null, "bridge is not armed");
				return;
			}
			if (!isAuthorized(exchange.getRequestHeaders())) {
				sendJson(exchange, 401, null, "missing or invalid bearer token");
				return;
			}
			body = readBody(exchange);
			JsonElement result = dispatch(path, body);
			sendJson(exchange, 200, result, null);
		}
		catch (BridgeException e) {
			sendJson(exchange, e.statusCode, null, e.getMessage());
		}
		catch (Exception e) {
			log("request failed " + path + ": " + e.getMessage());
			sendJson(exchange, 500, null, e.toString());
		}
	}

	private JsonElement dispatch(String path, JsonObject body) throws Exception {
		switch (path) {
			case "/health":
				return handleHealth();
			case "/session":
				return handleSession();
			case "/context":
				return handleContext();
			case "/analyze/target":
				return handleAnalyzeTarget(body);
			case "/functions/search":
				return handleFunctionSearch(body);
			case "/function":
				return handleFunction(body);
			case "/decompile":
				return handleDecompile(body);
			case "/references":
				return handleReferences(body);
			case "/data/get":
				return handleDataGet(body);
			case "/strings/search":
				return handleStringsSearch(body);
			case "/symbols/get":
				return handleSymbolsGet(body);
			case "/symbols/xrefs":
				return handleSymbolXrefs(body);
			case "/memory/range":
				return handleMemoryRange(body);
			case "/variables":
				return handleVariables(body);
			case "/datatypes/search":
				return handleDatatypeSearch(body);
			case "/objc/selector-trace":
				return handleObjcSelectorTrace(body);
			case "/navigate":
				return handleNavigate(body);
			case "/program/save":
				return handleProgramSave(body);
			case "/edit/rename":
				return handleEditRename(body);
			case "/edit/comment":
				return handleEditComment(body);
			case "/edit/bookmark":
				return handleEditBookmark(body);
			case "/edit/function-signature":
				return handleEditFunctionSignature(body);
			case "/edit/variable":
				return handleEditVariable(body);
			case "/edit/datatype":
				return handleEditDatatype(body);
			case "/patch/bytes":
				return handlePatchBytes(body);
			case "/patch/instruction":
				return handlePatchInstruction(body);
			case "/listing/clear":
				return handleListingClear(body);
			case "/listing/disassemble":
				return handleListingDisassemble(body);
			case "/function/create":
				return handleFunctionCreate(body);
			case "/function/delete":
				return handleFunctionDelete(body);
			case "/function/fixup":
				return handleFunctionFixup(body);
			case "/data/create":
				return handleDataCreate(body);
			case "/data/delete":
				return handleDataDelete(body);
			default:
				throw new BridgeException(404, "unknown endpoint: " + path);
		}
	}

	private String activeProjectName() {
		if (plugin.getCurrentProgram() != null) {
			RepositoryState repository = repositoryStateFor(plugin.getCurrentProgram());
			if (repository.projectName != null && !repository.projectName.isEmpty()) {
				return repository.projectName;
			}
		}
		if (plugin.getTool().getProject() != null && plugin.getTool().getProject().getName() != null) {
			return plugin.getTool().getProject().getName();
		}
		return "";
	}
}
