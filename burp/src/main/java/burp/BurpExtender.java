package burp;

import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.InterruptedException;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import com.google.gson.Gson;
import java.awt.Component;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.SwingUtilities;
import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JTextField;
import javax.swing.GroupLayout;
import javax.swing.JButton;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.exceptions.UnirestException;


public class BurpExtender implements IBurpExtender, IExtensionStateListener,
        IHttpListener, IScannerListener, IProxyListener, ITab {
    static final String NAME = "Burp Buddy";

    private EventServer wss;
    private ApiServer httpApi;
    private Gson gson = new Gson();
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private PrintWriter stderr;
    private IBurpExtenderCallbacks callbacks;
    private JPanel panel;
    private JScrollPane scroll;

    // Defaults
    private final int WSS_DEFAULT_PORT = 8000;
    private final int HTTPAPI_DEFAULT_PORT = 8001;
    private final String DEFAULT_IP = "127.0.0.1";
    private final String DEFAULT_REQUEST_HOOK_URL = "http://localhost:3001/request";
    private final String DEFAULT_RESPONSE_HOOK_URL = "http://localhost:3001/response";

    // Settings
    private JTextField httpPortField;
    private JTextField wssPortField;
    private JTextField interfaceField;
    private JTextField requestHookURLField;
    private JTextField responseHookURLField;
    
    public int wssPort;
    public int httpPort;
    public String ip;
    public String requestHookURL;
    public String responseHookURL;


    @Override
    public void registerExtenderCallbacks (final IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        callbacks.setExtensionName(NAME);
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);
        helpers = callbacks.getHelpers();

        // Create our UI.
        SwingUtilities.invokeLater(() -> {
                panel = new JPanel();
                scroll = new JScrollPane(panel, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
                scroll.setBorder(BorderFactory.createEmptyBorder());

                JLabel requestHookLabel = new JLabel("Request Service URL");
                JLabel responseHookLabel = new JLabel("Response Service URL");
                JLabel wssPortLabel = new JLabel("WebSocket Port");
                JLabel httpPortLabel = new JLabel("HTTP API Port");
                JLabel interfaceLabel = new JLabel("Interface");

                httpPortField = new JTextField(Integer.toString(HTTPAPI_DEFAULT_PORT));
                wssPortField = new JTextField(Integer.toString(WSS_DEFAULT_PORT));
                interfaceField = new JTextField(DEFAULT_IP);
                requestHookURLField = new JTextField(DEFAULT_REQUEST_HOOK_URL);
                responseHookURLField = new JTextField(DEFAULT_RESPONSE_HOOK_URL);

                JButton saveButton = new JButton("Save Settings");
                saveButton.addActionListener((e) -> {
                    stdout.println("saving config");
                    saveConfig();
                });

                // Layout all the things.
                GroupLayout layout = new GroupLayout(panel);
                panel.setLayout(layout);
                layout.setAutoCreateGaps(true);
                layout.setAutoCreateContainerGaps(true);
                GroupLayout.SequentialGroup hGroup = layout.createSequentialGroup();

                hGroup.addGroup(layout.createParallelGroup().addComponent(interfaceLabel).addComponent(httpPortLabel).addComponent(wssPortLabel)
                        .addComponent(requestHookLabel).addComponent(responseHookLabel).addComponent(saveButton));
                hGroup.addGroup(layout.createParallelGroup().addComponent(interfaceField).addComponent(httpPortField)
                        .addComponent(wssPortField).addComponent(requestHookURLField).addComponent(responseHookURLField));
                layout.setHorizontalGroup(hGroup);

                GroupLayout.SequentialGroup vGroup = layout.createSequentialGroup();
                vGroup.addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE).addComponent(interfaceLabel).addComponent(interfaceField));
                vGroup.addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE).addComponent(httpPortLabel).addComponent(httpPortField));
                vGroup.addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE).addComponent(wssPortLabel).addComponent(wssPortField));
                vGroup.addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE).addComponent(requestHookLabel).addComponent(requestHookURLField));
                vGroup.addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE).addComponent(responseHookLabel).addComponent(responseHookURLField));
                vGroup.addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE).addComponent(saveButton));

                layout.setVerticalGroup(vGroup);

                restoreConfig();
                callbacks.customizeUiComponent(scroll);

                // Add the custom tab to Burp's UI.
                callbacks.addSuiteTab(BurpExtender.this);
        });
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse requestResponse) {
        if (messageIsRequest) {
            BHttpRequest req = BHttpRequestFactory.create(toolFlag, requestResponse, helpers.analyzeRequest(requestResponse),
                    callbacks);

            wss.sendToAll(gson.toJson(req));

            try {
                HttpResponse<JsonNode> modRequestResponse = Unirest.post(requestHookURL)
                        .header("accept", "application/json")
                        .header("content-type", "application/json")
                        .body(gson.toJson(req))
                        .asJson();
                if (modRequestResponse.getCode() == 200) {
                    BHttpRequest modifiedHttpRequest = gson.fromJson(new InputStreamReader(modRequestResponse.getRawBody()),
                            BHttpRequest.class);

                    requestResponse.setRequest(helpers.buildHttpMessage(modifiedHttpRequest.headersToList(),
                            modifiedHttpRequest.body));
                    requestResponse.setHttpService(helpers.buildHttpService(modifiedHttpRequest.host,
                            modifiedHttpRequest.port, modifiedHttpRequest.protocol));
                    if (modifiedHttpRequest.comment != null && !modifiedHttpRequest.comment.equals("")) {
                        requestResponse.setComment(modifiedHttpRequest.comment);
                    }
                    if (modifiedHttpRequest.highlight != null && !modifiedHttpRequest.highlight.equals("")) {
                       requestResponse.setHighlight(modifiedHttpRequest.highlight);
                    }
                }
            } catch (UnirestException e) {
                // Do nothing.
            }

        } else {
            BHttpResponse resp = BHttpResponseFactory.create(toolFlag, requestResponse,
                    helpers.analyzeResponse(requestResponse.getResponse()), callbacks);
            wss.sendToAll(gson.toJson(resp));

            try {
                HttpResponse<JsonNode> modRequestResponse = Unirest.post(responseHookURL)
                        .header("accept", "application/json")
                        .header("content-type", "application/json")
                        .body(gson.toJson(resp))
                        .asJson();
                if(modRequestResponse.getCode() == 200) {
                    BHttpResponse modifiedHttpResponse = gson.fromJson(new InputStreamReader(modRequestResponse.getRawBody()),
                            BHttpResponse.class);

                    requestResponse.setResponse(modifiedHttpResponse.raw);

                    if (modifiedHttpResponse.comment != null && !modifiedHttpResponse.comment.equals("")) {
                        requestResponse.setComment(modifiedHttpResponse.comment);
                    }
                    if (modifiedHttpResponse.highlight != null && !modifiedHttpResponse.highlight.equals("")) {
                        requestResponse.setHighlight(modifiedHttpResponse.highlight);
                    }
                }

            } catch (UnirestException e) {
                // Do nothing.
            }
        }
    }

    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
    }

    @Override
    public void newScanIssue(IScanIssue scanIssue) {
        BScanIssue issue = BScanIssueFactory.create(scanIssue, callbacks);
        wss.sendToAll(gson.toJson(issue));
    }

    @Override
    public void extensionUnloaded() {
        stopWSS();
        stopHTTP();
    }

    @Override public String getTabCaption()
    {
        return NAME;
    }

    @Override public Component getUiComponent()
    {
        return scroll;
    }

    public void saveConfig()
    {
        try {
           wssPort= Integer.parseInt(wssPortField.getText());
            if (wssPort < 0 ||wssPort > 65535) {
                stderr.println("Invalid WSS port, using default.");
                wssPort= WSS_DEFAULT_PORT;
            }
        } catch (NumberFormatException e) {
            stderr.println("Invalid WSS port, using default.");
            wssPort= WSS_DEFAULT_PORT;
        }
        wssPortField.setText(String.valueOf(wssPort));

        try {
            httpPort= Integer.parseInt(httpPortField.getText());
            if (httpPort < 0 || httpPort > 65535 || httpPort == wssPort) {
                stderr.println("Invalid HTTP port, using default.");
                httpPort = HTTPAPI_DEFAULT_PORT;
            }
        } catch (NumberFormatException e) {
            stderr.println("Invalid HTTP port, using default.");
            httpPort = HTTPAPI_DEFAULT_PORT;
        }
        httpPortField.setText(String.valueOf(httpPort));

        ip = interfaceField.getText();
        requestHookURL = requestHookURLField.getText();
        responseHookURL = responseHookURLField.getText();

        this.callbacks.saveExtensionSetting("save", "1");
        this.callbacks.saveExtensionSetting("httpPort", Integer.toString(httpPort));
        this.callbacks.saveExtensionSetting("wssPort", Integer.toString(wssPort));
        this.callbacks.saveExtensionSetting("ip", ip); 
        this.callbacks.saveExtensionSetting("requestHookURL", requestHookURL);
        this.callbacks.saveExtensionSetting("responseHookURL", responseHookURL);

        // Restart WSS
        stopWSS();
        startWSS();

        // Restart HTTP API
        stopHTTP();
        startHTTP();
    }

    public void restoreConfig()
    {
        stdout.println("Restore Config called");
        if (callbacks.loadExtensionSetting("save") == null || callbacks.loadExtensionSetting("save").equals("0")) {
            restoreDefaults();
        } else {
            
            if (this.callbacks.loadExtensionSetting("wssPort") != null) {
               wssPort= Integer.parseInt(this.callbacks.loadExtensionSetting("wssPort"));
            } else {
               wssPort= WSS_DEFAULT_PORT;
            }
            wssPortField.setText(String.valueOf(wssPort));

            if (this.callbacks.loadExtensionSetting("httpPort") != null) {
                httpPort= Integer.parseInt(this.callbacks.loadExtensionSetting("httpPort"));
            } else {
                httpPort= HTTPAPI_DEFAULT_PORT;
            }
            httpPortField.setText(String.valueOf(httpPort));

            if (this.callbacks.loadExtensionSetting("ip") != null) {
                ip = this.callbacks.loadExtensionSetting("ip");
            } else {
                ip = DEFAULT_IP;
            }
            interfaceField.setText(ip);

            if (this.callbacks.loadExtensionSetting("requestHookURL") != null) {
                requestHookURL = this.callbacks.loadExtensionSetting("requestHookURL");
            } else {
                requestHookURL = DEFAULT_REQUEST_HOOK_URL;
            }

            if (this.callbacks.loadExtensionSetting("responseHookURL") != null) {
                responseHookURL = this.callbacks.loadExtensionSetting("responseHookURL");
            } else {
                responseHookURL = DEFAULT_RESPONSE_HOOK_URL;
            }

            requestHookURLField.setText(requestHookURL);
            responseHookURLField.setText(responseHookURL);

            startWSS();
            startHTTP();

            callbacks.registerExtensionStateListener(this);
            callbacks.registerHttpListener(this);
            callbacks.registerScannerListener(this);
        }
    }

    public void restoreDefaults() {
        stdout.println("Restore Defaults called");
        this.callbacks.saveExtensionSetting("save", "2");
        
        wssPort= WSS_DEFAULT_PORT;
        httpPort = HTTPAPI_DEFAULT_PORT;
        ip = DEFAULT_IP;
        requestHookURL = DEFAULT_REQUEST_HOOK_URL;
        responseHookURL = DEFAULT_RESPONSE_HOOK_URL;
    }


    public void stopWSS() {
        try {
            wss.stop();
            stdout.println("WebSocket server stopped");
        } catch(IOException|InterruptedException e) {
            stderr.println("Exception when stopping WebSocket server");
            stderr.println(e.getMessage());
        }
    }

    public void startWSS() {
        InetSocketAddress address = new InetSocketAddress(ip, wssPort);
        wss = new EventServer(stdout, stderr, address);
        wss.start();
        stdout.println("WebSocket server started at ws://" + ip + ":" + wssPort);
    }

    public void stopHTTP() {
        stdout.println("HTTP API server stopped");
        httpApi.stopServer();
    }

    public void startHTTP() {
        stdout.println("HTTP API server started at http://" + ip + ":" + httpPort);
        httpApi = new ApiServer(ip, httpPort, callbacks);
    }

}
