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
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class ApiVersionFuzzer implements BurpExtension {

    private MontoyaApi api;
    private ExecutorService threadPool;
    private ResultsTableModel tableModel;
    private JLabel statusLabel;
    private JCheckBox enablePassiveScan;

    // The list of versions we want to inject
    private static final String[] VERSION_STRINGS = {
            "v1", "v2", "v3", "v1beta1", "v1beta2", "v1alpha1", "v1alpha2",
            "v2beta1", "v2beta2", "v2alpha1", "v2alpha2",
            "v3beta1", "v3beta2", "v3alpha1", "v3alpha2"
    };

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
        tableModel = new ResultsTableModel();
        JTable table = new JTable(tableModel);

        JPopupMenu tablePopup = new JPopupMenu();
        JMenuItem sendToRepeater = new JMenuItem("Send to Repeater");
        sendToRepeater.addActionListener(e -> {
            int row = table.getSelectedRow();
            if (row != -1) {
                LogEntry entry = tableModel.getLogEntry(row);
                // Send the original request to Repeater with a tab name
                api.repeater().sendToRepeater(entry.httpRequestResponse.request(), "Fuzzed: " + entry.modifiedPath);
            }
        });
        tablePopup.add(sendToRepeater);
        table.setComponentPopupMenu(tablePopup);

        JScrollPane scrollPane = new JScrollPane(table);

        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        enablePassiveScan = new JCheckBox("Enable Passive Scanning (In-Scope Only)");
        JButton clearButton = new JButton("Clear History");
        statusLabel = new JLabel(" | Requests Sent: 0");

        clearButton.addActionListener(e -> {
            tableModel.clear();
            statusLabel.setText(" | Requests Sent: 0");
        });

        controlPanel.add(enablePassiveScan);
        controlPanel.add(clearButton);
        controlPanel.add(statusLabel);

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, controlPanel, scrollPane);
        splitPane.setDividerLocation(40);

        api.userInterface().registerSuiteTab("API Fuzzer", splitPane);
    }

    private void runFuzzer(HttpRequest baseRequest, boolean checkScope) {
        HttpService service = baseRequest.httpService();
        String url = baseRequest.url();

        // Deduplication: Don't fuzz requests that we sent ourselves
        if (baseRequest.hasHeader("X-Api-Fuzzer")) {
            return;
        }

        if (checkScope && !api.scope().isInScope(url)) {
            return;
        }

        String foundVersion = null;
        for (String v : VERSION_STRINGS) {
            if (url.contains("/" + v + "/") || url.endsWith("/" + v)) {
                foundVersion = v;
                break;
            }
        }

        if (foundVersion == null) {
            return;
        }

        final String originalVersion = foundVersion;

        threadPool.submit(() -> {
            for (String targetVersion : VERSION_STRINGS) {
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

    private class PassiveScanner implements HttpHandler {
        // FIX: Method name changed from handleRequestToBeSent to handleHttpRequestToBeSent
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

        public LogEntry getLogEntry(int row) {
            return log.get(row);
        }

        public void clear() {
            log.clear();
            fireTableDataChanged();
        }
    }
}
