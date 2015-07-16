package burp;

import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.InterruptedException;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import com.google.gson.Gson;
import java.awt.Component;
import javax.swing.*;

import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.exceptions.UnirestException;
import org.apache.commons.codec.binary.Base64;


public class BurpExtender implements IBurpExtender, IExtensionStateListener,
        IHttpListener, IScannerListener, IProxyListener, ITab {
    static final String NAME = "burpbuddy";

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
    private final String WSS_DEFAULT_ALLOWED_ORIGIN = "*";

    // Settings
    private JTextField httpPortField;
    private JTextField wssPortField;
    private JTextField wssAllowedOriginField;
    private JTextField interfaceField;
    private JTextField requestHookURLField;
    private JTextField responseHookURLField;
    private JToggleButton httpApiEnabledButton;
    private JToggleButton wssEnabledButton;
    private JToggleButton responseHookEnabledButton;
    private JToggleButton requestHookEnabledButton;
    
    public int wssPort;
    public String wssAllowedOrigin;
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
            JLabel wssAllowedOriginLabel = new JLabel("WebSocket Allowed Origin");
            JLabel httpPortLabel = new JLabel("HTTP API Port");
            JLabel interfaceLabel = new JLabel("Interface");

            httpPortField = new JTextField(Integer.toString(HTTPAPI_DEFAULT_PORT));
            wssPortField = new JTextField(Integer.toString(WSS_DEFAULT_PORT));
            wssAllowedOriginField = new JTextField(WSS_DEFAULT_ALLOWED_ORIGIN);
            interfaceField = new JTextField(DEFAULT_IP);
            requestHookURLField = new JTextField(DEFAULT_REQUEST_HOOK_URL);
            responseHookURLField = new JTextField(DEFAULT_RESPONSE_HOOK_URL);

            httpApiEnabledButton = new JToggleButton("HTTP Server is running", false);
            wssEnabledButton = new JToggleButton("WebSocket Server is running", false);
            requestHookEnabledButton = new JToggleButton("Request hook is enabled", false);
            responseHookEnabledButton = new JToggleButton("Response hook is enabled", false);

            httpApiEnabledButton.addActionListener((e) -> toggleHTTPApi());
            wssEnabledButton.addActionListener((e) -> toggleWSSServer());
            requestHookEnabledButton.addActionListener((e) -> toggleRequestHookEnabled());
            responseHookEnabledButton.addActionListener((e) -> toggleResponseHookEnabled());

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
                    .addComponent(wssAllowedOriginLabel).addComponent(requestHookLabel).addComponent(responseHookLabel).addComponent(saveButton));

            hGroup.addGroup(layout.createParallelGroup().addComponent(interfaceField).addComponent(httpPortField)
                    .addComponent(wssPortField).addComponent(wssAllowedOriginField).addComponent(requestHookURLField).addComponent(responseHookURLField));

            hGroup.addGroup(layout.createParallelGroup().addComponent(httpApiEnabledButton)
                    .addComponent(wssEnabledButton).addComponent(requestHookEnabledButton)
                    .addComponent(responseHookEnabledButton));

            layout.setHorizontalGroup(hGroup);

            GroupLayout.SequentialGroup vGroup = layout.createSequentialGroup();
            vGroup.addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE).addComponent(interfaceLabel)
                    .addComponent(interfaceField));

            vGroup.addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE).addComponent(httpPortLabel)
                    .addComponent(httpPortField).addComponent(httpApiEnabledButton));

            vGroup.addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE).addComponent(wssPortLabel)
                    .addComponent(wssPortField).addComponent(wssEnabledButton));

            vGroup.addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE).addComponent(wssAllowedOriginLabel)
                    .addComponent(wssAllowedOriginField));

            vGroup.addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE).addComponent(requestHookLabel)
                    .addComponent(requestHookURLField).addComponent(requestHookEnabledButton));

            vGroup.addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE).addComponent(responseHookLabel)
                    .addComponent(responseHookURLField).addComponent(responseHookEnabledButton));

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
        } else {
            BHttpResponse resp = BHttpResponseFactory.create(toolFlag, requestResponse,
                    helpers.analyzeResponse(requestResponse.getResponse()), callbacks);
            wss.sendToAll(gson.toJson(resp));
        }
    }

    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
        IHttpRequestResponse iHttpRequestResponse = message.getMessageInfo();
        int messageReference = message.getMessageReference();

        if (messageIsRequest) {
            if (requestHookEnabledButton.isSelected()) {
                return;
            }
            BHttpRequest bHttpRequest = BHttpRequestFactory.create(IBurpExtenderCallbacks.TOOL_PROXY,
                    iHttpRequestResponse,
                    helpers.analyzeRequest(iHttpRequestResponse),
                    callbacks);
            bHttpRequest.referenceID = messageReference;
            try {
                HttpResponse<JsonNode> modRequestResponse = Unirest.post(requestHookURL)
                        .header("accept", "application/json")
                        .header("content-type", "application/json")
                        .body(gson.toJson(bHttpRequest))
                        .asJson();
                if (modRequestResponse.getCode() == 200) {
                    BHttpRequest modifiedHttpRequest = gson.fromJson(new InputStreamReader(modRequestResponse.getRawBody()),
                            BHttpRequest.class);

                    // Call setRequest() only if 'headers' or 'body' were changed. This prevents Burp
                    // marking the request "edited" when there are no changes.
                    // Note: headers.equals() can be used because it is a HashMap of Strings.
                    if (!bHttpRequest.headers.equals(modifiedHttpRequest.headers) ||
                        !bHttpRequest.body.equals(modifiedHttpRequest.body)) {
                        iHttpRequestResponse.setRequest(helpers.buildHttpMessage(modifiedHttpRequest.headersToList(),
                                                                                 Base64.decodeBase64(modifiedHttpRequest.body)));
                    }
                    // Call setHttpService() only if 'host', 'port' or 'protocol' were changed.
                    if (!bHttpRequest.host.equals(modifiedHttpRequest.host) ||
                        (bHttpRequest.port!=modifiedHttpRequest.port) ||
                        !bHttpRequest.protocol.equals(modifiedHttpRequest.protocol)) {
                        iHttpRequestResponse.setHttpService(helpers.buildHttpService(modifiedHttpRequest.host,
                                                                                     modifiedHttpRequest.port, modifiedHttpRequest.protocol));
                    }
                    if (modifiedHttpRequest.comment != null && !modifiedHttpRequest.comment.equals("")) {
                        iHttpRequestResponse.setComment(modifiedHttpRequest.comment);
                    }
                    if (modifiedHttpRequest.highlight != null && !modifiedHttpRequest.highlight.equals("")) {
                        iHttpRequestResponse.setHighlight(modifiedHttpRequest.highlight);
                    }
                }
            } catch (UnirestException e) {
                // Do nothing.
            }

        } else {
            if (responseHookEnabledButton.isSelected()) {
                return;
            }
            BHttpResponse resp = BHttpResponseFactory.create(IBurpExtenderCallbacks.TOOL_PROXY, iHttpRequestResponse,
                    helpers.analyzeResponse(iHttpRequestResponse.getResponse()), callbacks);
            resp.referenceID = messageReference;
            try {
                HttpResponse<JsonNode> modRequestResponse = Unirest.post(responseHookURL)
                        .header("accept", "application/json")
                        .header("content-type", "application/json")
                        .body(gson.toJson(resp))
                        .asJson();
                if(modRequestResponse.getCode() == 200) {
                    BHttpResponse modifiedHttpResponse = gson.fromJson(new InputStreamReader(modRequestResponse.getRawBody()),
                            BHttpResponse.class);

                    // Call setResponse() only if 'raw' was changed. This prevents Burp
                    // marking the response "edited" when there are no changes.
                    if (resp.raw.equals(modifiedHttpResponse.raw)==false) {
                        iHttpRequestResponse.setResponse(Base64.decodeBase64(modifiedHttpResponse.raw));
                    }

                    if (modifiedHttpResponse.comment != null && !modifiedHttpResponse.comment.equals("")) {
                        iHttpRequestResponse.setComment(modifiedHttpResponse.comment);
                    }
                    if (modifiedHttpResponse.highlight != null && !modifiedHttpResponse.highlight.equals("")) {
                        iHttpRequestResponse.setHighlight(modifiedHttpResponse.highlight);
                    }
                }

            } catch (UnirestException e) {
                // Do nothing.
            }
        }
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
        wssAllowedOrigin = wssAllowedOriginField.getText();
        requestHookURL = requestHookURLField.getText();
        responseHookURL = responseHookURLField.getText();

        this.callbacks.saveExtensionSetting("save", "1");
        this.callbacks.saveExtensionSetting("httpPort", Integer.toString(httpPort));
        this.callbacks.saveExtensionSetting("wssPort", Integer.toString(wssPort));
        this.callbacks.saveExtensionSetting("wssAllowedOrigin", wssAllowedOrigin);
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

            if (this.callbacks.loadExtensionSetting("wssAllowedOrigin") != null) {
                wssAllowedOrigin = this.callbacks.loadExtensionSetting("wssAllowedOrigin");
            } else {
                wssAllowedOrigin = WSS_DEFAULT_ALLOWED_ORIGIN;
            }
            wssAllowedOriginField.setText(wssAllowedOrigin);

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
            callbacks.registerProxyListener(this);
            callbacks.registerScannerListener(this);

            // We have to register a "fake" passive scanner to emit request/response pairs to socket clients.
            callbacks.registerScannerCheck(BFakeScannerForMessageFactory.create(callbacks, wss));
        }
    }

    public void restoreDefaults() {
        stdout.println("Restore Defaults called");
        this.callbacks.saveExtensionSetting("save", "2");
        
        wssPort= WSS_DEFAULT_PORT;
        wssAllowedOrigin = WSS_DEFAULT_ALLOWED_ORIGIN;
        httpPort = HTTPAPI_DEFAULT_PORT;
        ip = DEFAULT_IP;
        requestHookURL = DEFAULT_REQUEST_HOOK_URL;
        responseHookURL = DEFAULT_RESPONSE_HOOK_URL;
    }


    public void stopWSS() {
        try {
            wss.stop();
            stdout.println("WebSocket server stopped");
            wssEnabledButton.setSelected(true);
            wssEnabledButton.setText(("WebSocket Server is not running"));
        } catch(IOException|InterruptedException e) {
            wssEnabledButton.setSelected(false);
            stderr.println("Exception when stopping WebSocket server");
            stderr.println(e.getMessage());
        }
    }

    public void startWSS() {
        InetSocketAddress address = new InetSocketAddress(ip, wssPort);
        wss = new EventServer(wssAllowedOrigin, stdout, stderr, address);
        wss.start();
        stdout.println("WebSocket server started at ws://" + ip + ":" + wssPort);
        wssEnabledButton.setSelected(false);
        wssEnabledButton.setText("WebSocket Server is running");
    }

    public void stopHTTP() {
        httpApiEnabledButton.setText("HTTP Server is not running");
        httpApiEnabledButton.setSelected(true);
        stdout.println("HTTP API server stopped");
        httpApi.stopServer();
    }

    public void startHTTP() {
        httpApiEnabledButton.setText("HTTP Server is running");
        httpApiEnabledButton.setSelected(false);
        stdout.println("HTTP API server started at http://" + ip + ":" + httpPort);
        httpApi = new ApiServer(ip, httpPort, callbacks);
    }

    public void toggleHTTPApi() {
        if (httpApiEnabledButton.isSelected()) {
            stopHTTP();
        } else {
            startHTTP();
        }
    }

    public void toggleWSSServer() {
        if (wssEnabledButton.isSelected()) {
            stopWSS();
        } else {
            startWSS();
        }
    }

    public void toggleRequestHookEnabled() {
        if (requestHookEnabledButton.isSelected()) {
            requestHookEnabledButton.setText("Request hook disabled");
        } else {
            requestHookEnabledButton.setText("Request hook enabled");
        }
    }

    public void toggleResponseHookEnabled() {
        if (responseHookEnabledButton.isSelected()) {
            responseHookEnabledButton.setText("Response hook disabled");
        } else {
            responseHookEnabledButton.setText("Response hook enabled");
        }
    }

}
