/* ###
 * IP: GHIDRA
 */
package codexghidrabridge;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicLong;

import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;

//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = CorePluginPackage.NAME,
	category = "Codex",
	shortDescription = "Codex localhost bridge for live reverse engineering.",
	description = "Exposes live Ghidra GUI state and controlled editing over a localhost HTTP bridge for Codex."
)
//@formatter:on
public class CodexBridgePlugin extends ProgramPlugin implements DomainObjectListener {

	private final CodexBridgeProvider provider;
	private final CodexBridgeService service;
	private final AtomicLong stateVersion = new AtomicLong(1);

	private Program observedProgram;

	public CodexBridgePlugin(PluginTool tool) {
		super(tool, true, true, true);
		provider = new CodexBridgeProvider(this, getName());
		service = new CodexBridgeService(this, provider);
	}

	@Override
	public void init() {
		super.init();
		if (!provider.isInTool()) {
			provider.addToTool();
		}
		provider.setVisible(true);
		service.start();
		refreshProvider();
	}

	@Override
	protected void dispose() {
		detachObservedProgram(observedProgram);
		service.dispose();
		if (provider.isInTool()) {
			provider.removeFromTool();
		}
		super.dispose();
	}

	@Override
	protected void programOpened(Program program) {
		super.programOpened(program);
		incrementState("program-opened");
		service.onProgramOpened(program);
		refreshProvider();
	}

	@Override
	protected void programActivated(Program program) {
		super.programActivated(program);
		attachObservedProgram(program);
		incrementState("program-activated");
		service.onProgramActivated(program);
		refreshProvider();
	}

	@Override
	protected void programDeactivated(Program program) {
		super.programDeactivated(program);
		detachObservedProgram(program);
		incrementState("program-deactivated");
		service.onProgramDeactivated(program);
		refreshProvider();
	}

	@Override
	protected void programClosed(Program program) {
		super.programClosed(program);
		detachObservedProgram(program);
		incrementState("program-closed");
		service.onProgramClosed(program);
		refreshProvider();
	}

	@Override
	protected void locationChanged(ProgramLocation location) {
		super.locationChanged(location);
		incrementState("location");
		service.onContextChanged();
		refreshProvider();
	}

	@Override
	protected void selectionChanged(ProgramSelection selection) {
		super.selectionChanged(selection);
		incrementState("selection");
		service.onContextChanged();
		refreshProvider();
	}

	@Override
	protected void highlightChanged(ProgramSelection highlight) {
		super.highlightChanged(highlight);
		incrementState("highlight");
		service.onContextChanged();
		refreshProvider();
	}

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		if (currentProgram != null && ev.getSource() == currentProgram) {
			incrementState("domain-change");
			service.onProgramMutated();
			refreshProvider();
		}
	}

	long getStateVersion() {
		return stateVersion.get();
	}

	long incrementState(String reason) {
		long value = stateVersion.incrementAndGet();
		service.log("state " + value + " (" + reason + ")");
		return value;
	}

	CodexBridgeService getService() {
		return service;
	}

	CodexBridgeProvider getProvider() {
		return provider;
	}

	String getBridgeUrl() {
		return service.getBridgeUrl();
	}

	public boolean isBridgeArmed() {
		return service.isArmed();
	}

	public void armBridge(String reason) throws IOException {
		service.arm(reason);
		refreshProvider();
	}

	public void disarmBridge(String reason) {
		service.disarm(reason);
		refreshProvider();
	}

	Address getCurrentAddress() {
		if (currentLocation == null) {
			return null;
		}
		return currentLocation.getAddress();
	}

	Function getCurrentFunction() {
		if (currentProgram == null || currentLocation == null || currentLocation.getAddress() == null) {
			return null;
		}
		return currentProgram.getFunctionManager().getFunctionContaining(currentLocation.getAddress());
	}

	boolean navigateTo(Address address) {
		if (address == null) {
			return false;
		}
		boolean result = goTo(address);
		refreshProvider();
		return result;
	}

	void refreshProvider() {
		String program = currentProgram == null ? "" : service.describeProgram(currentProgram);
		String location = "";
		Address address = getCurrentAddress();
		Function function = getCurrentFunction();
		if (address != null) {
			location = address.toString();
			if (function != null) {
				location = location + " (" + function.getName() + ")";
			}
		}
		provider.updateSnapshot(isBridgeArmed(), getBridgeUrl(), program, location,
			service.describeRepository(service.repositoryStateFor(currentProgram)), getStateVersion());
	}

	private void attachObservedProgram(Program program) {
		if (program == observedProgram) {
			return;
		}
		detachObservedProgram(observedProgram);
		observedProgram = program;
		if (observedProgram != null) {
			observedProgram.addListener(this);
		}
	}

	private void detachObservedProgram(Program program) {
		if (program == null) {
			return;
		}
		program.removeListener(this);
		if (observedProgram == program) {
			observedProgram = null;
		}
	}
}
