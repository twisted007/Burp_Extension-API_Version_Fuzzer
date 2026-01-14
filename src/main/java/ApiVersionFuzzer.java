import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.text.BadLocationException;
import java.awt.*;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.*;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

public class ApiVersionFuzzer implements BurpExtension {

    private MontoyaApi api;
    private ExecutorService threadPool;
    private ResultsTableModel tableModel;
    private JLabel statusLabel;
    private JCheckBox enablePassiveScan;
    private JTextArea versionEditor;

    // Default list
    private static final String DEFAULT_VERSIONS =
            "v1\nv2\nv3\nv1beta1\nv1beta2\nv1alpha1\nv1alpha2\n" +
                    "v2beta1\nv2beta2\nv2alpha1\nv2alpha2\n" +
                    "v3beta1\nv3beta2\nv3alpha1\nv3alpha2";

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("API Version Fuzzer");
        this.threadPool = Executors.newCachedThreadPool();

        SwingUtilities.invokeLater(this::setupUI);

        api.http().registerHttpHandler(new PassiveScanner());
        api.userInterface().registerContextMenuItemsProvider(new ManualContextMenu());

        api.logging().logToOutput("API Version Fuzzer loaded successfully.");
    }

    private void setupUI() {
        // --- 1. Top Panel: Configuration & Controls ---
        JPanel topPanel = new JPanel(new BorderLayout());

        // A. The Version List Editor
        versionEditor = new JTextArea(DEFAULT_VERSIONS);
        JScrollPane editorScroll = new JScrollPane(versionEditor);
        editorScroll.setBorder(BorderFactory.createTitledBorder("Target Version Strings (One per line)"));

        // B. List Tools (Right of Editor)
        JPanel listToolsPanel = new JPanel(new GridLayout(5, 1, 5, 5));
        JButton btnLoad = new JButton("Load File");
        JButton btnPaste = new JButton("Paste");
        JButton btnRemove = new JButton("Remove Item");
        JButton btnDedup = new JButton("Deduplicate");
        JButton btnClearList = new JButton("Clear List");

        btnLoad.addActionListener(e -> loadFile());
        btnPaste.addActionListener(e -> pasteClipboard());
        btnRemove.addActionListener(e -> removeSelectedLines());
        btnDedup.addActionListener(e -> deduplicateList());
        btnClearList.addActionListener(e -> versionEditor.setText(""));

        listToolsPanel.add(btnLoad);
        listToolsPanel.add(btnPaste);
        listToolsPanel.add(btnRemove);
        listToolsPanel.add(btnDedup);
        listToolsPanel.add(btnClearList);

        // Container for Editor + Tools
        JPanel editorContainer = new JPanel(new BorderLayout());
        editorContainer.add(editorScroll, BorderLayout.CENTER);
        editorContainer.add(listToolsPanel, BorderLayout.EAST);
        editorContainer.setPreferredSize(new Dimension(800, 160));

        // C. Execution Controls
        JPanel executionPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        enablePassiveScan = new JCheckBox("Enable Passive Scanning (In-Scope Only)");
        JButton btnClearResults = new JButton("Clear Results Table");
        statusLabel = new JLabel(" | Requests Sent: 0");

        btnClearResults.addActionListener(e -> {
            tableModel.clear();
            statusLabel.setText(" | Requests Sent: 0");
        });

        executionPanel.add(enablePassiveScan);
        executionPanel.add(btnClearResults);
        executionPanel.add(statusLabel);

        topPanel.add(editorContainer, BorderLayout.CENTER);
        topPanel.add(executionPanel, BorderLayout.SOUTH);


        // --- 2. Bottom Panel: Results Table ---
        tableModel = new ResultsTableModel();
        JTable table = new JTable(tableModel);
        table.setAutoCreateRowSorter(true);

        JPopupMenu tablePopup = new JPopupMenu();
        JMenuItem sendToRepeater = new JMenuItem("Send to Repeater");
        sendToRepeater.addActionListener(e -> {
            int row = table.getSelectedRow();
            if (row != -1) {
                int modelRow = table.convertRowIndexToModel(row);
                LogEntry entry = tableModel.getLogEntry(modelRow);
                api.repeater().sendToRepeater(entry.httpRequestResponse.request(), "Fuzzed: " + entry.modifiedPath);
            }
        });
        tablePopup.add(sendToRepeater);
        table.setComponentPopupMenu(tablePopup);

        JScrollPane tableScroll = new JScrollPane(table);


        // --- 3. Main Split Pane ---
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, topPanel, tableScroll);
        splitPane.setDividerLocation(200);

        api.userInterface().registerSuiteTab("API Fuzzer", splitPane);
    }

    // --- Helper Methods ---
    private void loadFile() {
        JFileChooser fileChooser = new JFileChooser();
        if (fileChooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
                versionEditor.read(reader, null);
            } catch (IOException ex) {
                api.logging().logToError("Error loading file: " + ex.getMessage());
            }
        }
    }

    private void pasteClipboard() {
        try {
            String data = (String) Toolkit.getDefaultToolkit().getSystemClipboard().getData(DataFlavor.stringFlavor);
            if (!data.startsWith("\n") && !versionEditor.getText().endsWith("\n") && !versionEditor.getText().isEmpty()) {
                versionEditor.append("\n");
            }
            versionEditor.append(data);
        } catch (IOException | UnsupportedFlavorException e) {
            api.logging().logToError("Clipboard error: " + e.getMessage());
        }
    }

    private void removeSelectedLines() {
        try {
            int start = versionEditor.getSelectionStart();
            int end = versionEditor.getSelectionEnd();

            if (start == end) {
                // No selection: Remove the line the caret is currently on
                int caretPos = versionEditor.getCaretPosition();
                int lineNum = versionEditor.getLineOfOffset(caretPos);
                int lineStart = versionEditor.getLineStartOffset(lineNum);
                int lineEnd = versionEditor.getLineEndOffset(lineNum);
                versionEditor.replaceRange("", lineStart, lineEnd);
            } else {
                // Remove the actual highlighted selection
                versionEditor.replaceRange("", start, end);
            }
        } catch (BadLocationException e) {
            // Ignore UI errors
        }
    }

    private void deduplicateList() {
        String text = versionEditor.getText();
        if (text.isEmpty()) return;

        // Corrected Lambda Logic
        Set<String> lines = new LinkedHashSet<>(Arrays.asList(text.split("\\R")));
        lines.removeIf(s -> s.trim().isEmpty());

        versionEditor.setText(String.join("\n", lines));
    }

    private List<String> getTargetVersions() {
        String text = versionEditor.getText();
        if (text == null || text.trim().isEmpty()) {
            return Collections.emptyList();
        }
        return Arrays.stream(text.split("\\R"))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toList());
    }

    // --- Fuzzing Logic ---
    private void runFuzzer(HttpRequest baseRequest, boolean checkScope) {
        HttpService service = baseRequest.httpService();
        String url = baseRequest.url();

        if (baseRequest.hasHeader("X-Api-Fuzzer")) return;
        if (checkScope && !api.scope().isInScope(url)) return;

        List<String> versionList = getTargetVersions();
        if (versionList.isEmpty()) return;

        String foundVersion = null;
        for (String v : versionList) {
            if (url.contains("/" + v + "/") || url.endsWith("/" + v)) {
                foundVersion = v;
                break;
            }
        }

        if (foundVersion == null) return;

        final String originalVersion = foundVersion;

        threadPool.submit(() -> {
            for (String targetVersion : versionList) {
                if (targetVersion.equals(originalVersion)) continue;

                String newPath = baseRequest.path().replace("/" + originalVersion, "/" + targetVersion);

                HttpRequest newRequest = baseRequest.withPath(newPath)
                        .withHeader("X-Api-Fuzzer", "true");

                HttpRequestResponse response = api.http().sendRequest(newRequest);

                SwingUtilities.invokeLater(() -> {
                    tableModel.addLogEntry(new LogEntry(
                            tableModel.getRowCount() + 1,
                            newRequest.method(),
                            service.host(),
                            baseRequest.path(),
                            newPath,
                            response.response().statusCode(),
                            response.response().body().length(),
                            response
                    ));
                    updateStatus();
                });
            }
        });
    }

    private void updateStatus() {
        statusLabel.setText(" | Requests Sent: " + tableModel.getRowCount());
    }

    // --- Handlers ---
    private class PassiveScanner implements HttpHandler {
        @Override
        public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
            if (enablePassiveScan.isSelected()) {
                runFuzzer(requestToBeSent, true);
            }
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }

        @Override
        public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }
    }

    private class ManualContextMenu implements ContextMenuItemsProvider {
        @Override
        public List<Component> provideMenuItems(ContextMenuEvent event) {
            List<Component> menuList = new ArrayList<>();
            JMenuItem item = new JMenuItem("Scan API Versions");

            item.addActionListener(e -> {
                if (event.messageEditorRequestResponse().isPresent()) {
                    MessageEditorHttpRequestResponse editorItem = event.messageEditorRequestResponse().get();
                    runFuzzer(editorItem.requestResponse().request(), false);
                }

                List<HttpRequestResponse> historyItems = event.selectedRequestResponses();
                if (historyItems != null) {
                    for (HttpRequestResponse req : historyItems) {
                        runFuzzer(req.request(), false);
                    }
                }
            });

            menuList.add(item);
            return menuList;
        }
    }

    // --- Table Model ---
    private static class LogEntry {
        final int id;
        final String method;
        final String host;
        final String originalPath;
        final String modifiedPath;
        final int status;
        final int length;
        final HttpRequestResponse httpRequestResponse;

        LogEntry(int id, String method, String host, String originalPath, String modifiedPath, int status, int length, HttpRequestResponse httpRequestResponse) {
            this.id = id;
            this.method = method;
            this.host = host;
            this.originalPath = originalPath;
            this.modifiedPath = modifiedPath;
            this.status = status;
            this.length = length;
            this.httpRequestResponse = httpRequestResponse;
        }
    }

    private static class ResultsTableModel extends AbstractTableModel {
        private final List<LogEntry> log = new ArrayList<>();
        private final String[] columns = {"#", "Method", "Host", "Original", "Modified", "Status", "Length"};

        @Override
        public int getRowCount() { return log.size(); }
        @Override
        public int getColumnCount() { return columns.length; }
        @Override
        public String getColumnName(int column) { return columns[column]; }
        @Override
        public Class<?> getColumnClass(int columnIndex) {
            switch (columnIndex) {
                case 0: return Integer.class;
                case 5: return Integer.class;
                case 6: return Integer.class;
                default: return String.class;
            }
        }
        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            LogEntry entry = log.get(rowIndex);
            switch (columnIndex) {
                case 0: return entry.id;
                case 1: return entry.method;
                case 2: return entry.host;
                case 3: return entry.originalPath;
                case 4: return entry.modifiedPath;
                case 5: return entry.status;
                case 6: return entry.length;
                default: return "";
            }
        }
        public void addLogEntry(LogEntry entry) {
            log.add(entry);
            fireTableRowsInserted(log.size() - 1, log.size() - 1);
        }
        public LogEntry getLogEntry(int row) { return log.get(row); }
        public void clear() {
            log.clear();
            fireTableDataChanged();
        }
    }
}
