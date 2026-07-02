/* ###
 * IP: GHIDRA
 */
package codexghidrabridge;

import java.awt.BorderLayout;
import java.awt.GridLayout;

import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;

import docking.ComponentProvider;
import docking.WindowPosition;
import ghidra.framework.plugintool.Plugin;
import ghidra.util.HelpLocation;

class CodexBridgeProvider extends ComponentProvider {

	private final JPanel panel;
	private final JLabel armedValue;
	private final JLabel urlValue;
	private final JLabel programValue;
	private final JLabel locationValue;
	private final JLabel repoValue;
	private final JLabel stateValue;
	private final JTextArea logArea;

	CodexBridgeProvider(Plugin plugin, String owner) {
		super(plugin.getTool(), "Codex Bridge", owner);

		panel = new JPanel(new BorderLayout(8, 8));
		JPanel summary = new JPanel(new GridLayout(0, 2, 8, 4));
		summary.add(new JLabel("Armed"));
		armedValue = new JLabel("no");
		summary.add(armedValue);

		summary.add(new JLabel("Bridge URL"));
		urlValue = new JLabel("-");
		summary.add(urlValue);

		summary.add(new JLabel("Program"));
		programValue = new JLabel("-");
		summary.add(programValue);

		summary.add(new JLabel("Location"));
		locationValue = new JLabel("-");
		summary.add(locationValue);

		summary.add(new JLabel("Repository"));
		repoValue = new JLabel("-");
		summary.add(repoValue);

		summary.add(new JLabel("State Version"));
		stateValue = new JLabel("0");
		summary.add(stateValue);

		panel.add(summary, BorderLayout.NORTH);

		logArea = new JTextArea(12, 48);
		logArea.setEditable(false);
		logArea.setLineWrap(true);
		logArea.setWrapStyleWord(true);
		panel.add(new JScrollPane(logArea), BorderLayout.CENTER);

		setDefaultWindowPosition(WindowPosition.BOTTOM);
		setHelpLocation(new HelpLocation("CodexGhidraBridge", "BridgePanel"));
		setVisible(true);
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}

	void updateSnapshot(boolean armed, String url, String program, String location,
			String repository, long stateVersion) {
		SwingUtilities.invokeLater(() -> {
			armedValue.setText(armed ? "yes" : "no");
			urlValue.setText(emptyToDash(url));
			programValue.setText(emptyToDash(program));
			locationValue.setText(emptyToDash(location));
			repoValue.setText(emptyToDash(repository));
			stateValue.setText(Long.toString(stateVersion));
		});
	}

	void appendLog(String message) {
		if (message == null || message.isEmpty()) {
			return;
		}
		SwingUtilities.invokeLater(() -> {
			if (logArea.getText().length() > 12000) {
				logArea.setText(logArea.getText().substring(logArea.getText().length() - 8000));
			}
			if (!logArea.getText().isEmpty()) {
				logArea.append("\n");
			}
			logArea.append(message);
			logArea.setCaretPosition(logArea.getDocument().getLength());
		});
	}

	private String emptyToDash(String value) {
		if (value == null || value.isEmpty()) {
			return "-";
		}
		return value;
	}
}
