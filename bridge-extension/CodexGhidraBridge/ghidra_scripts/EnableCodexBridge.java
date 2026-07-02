/* ###
 * IP: GHIDRA
 */
//@category Codex

import codexghidrabridge.CodexBridgePlugin;
import ghidra.app.script.GhidraScript;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;

public class EnableCodexBridge extends GhidraScript {

	@Override
	protected void run() throws Exception {
		PluginTool tool = state.getTool();
		if (tool == null) {
			throw new IllegalStateException("no active PluginTool");
		}

		CodexBridgePlugin bridgePlugin = null;
		for (Plugin plugin : tool.getManagedPlugins()) {
			if (plugin instanceof CodexBridgePlugin) {
				bridgePlugin = (CodexBridgePlugin) plugin;
				break;
			}
		}

		if (bridgePlugin == null) {
			tool.addPlugin("codexghidrabridge.CodexBridgePlugin");
			for (Plugin plugin : tool.getManagedPlugins()) {
				if (plugin instanceof CodexBridgePlugin) {
					bridgePlugin = (CodexBridgePlugin) plugin;
					break;
				}
			}
		}

		if (bridgePlugin == null) {
			throw new IllegalStateException("CodexBridgePlugin is not available after addPlugin()");
		}

		bridgePlugin.armBridge("EnableCodexBridge.java");
		tool.saveTool();

		println("Codex bridge enabled and tool configuration saved.");
	}
}
