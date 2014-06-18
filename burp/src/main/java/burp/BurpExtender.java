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
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.exceptions.UnirestException;


public class BurpExtender implements IBurpExtender, IExtensionStateListener,
        IHttpListener, IScannerListener, IProxyListener, ITab {
    static final String NAME = "Burp Buddy";

    private EventServer wss;
    private Gson gson = new Gson();
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private PrintWriter stderr;
    private IBurpExtenderCallbacks callbacks;
    private JPanel panel;
    private JScrollPane scroll;

    // Defaults
    private final int DEFAULT_PORT = 8000;
    private final String DEFAULT_IP = "127.0.0.1";

    // Settings
    private JTextField portField;
    private JTextField interfaceField;
    public int port;
    public String ip;


    @Override
    public void registerExtenderCallbacks (final IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        callbacks.setExtensionName(NAME);
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);
        helpers = callbacks.getHelpers();

        // create our UI
        SwingUtilities.invokeLater(new Runnable()
        {
            @Override
            public void run()
            {
                panel = new JPanel();
                scroll = new JScrollPane(panel, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
                scroll.setBorder(BorderFactory.createEmptyBorder());

                JLabel portLabel = new JLabel("Port");
                JLabel interfaceLabel = new JLabel("Interface");
                portField = new JTextField(Integer.toString(DEFAULT_PORT));
                interfaceField = new JTextField(DEFAULT_IP);

                JButton saveButton = new JButton("Save Settings");
                saveButton.addActionListener(new ActionListener()
                {
                    @Override public void actionPerformed(ActionEvent e)
                    {
                        stdout.println("saving config");
                        saveConfig();
                    }
                });        

                // Layout all the things
                GroupLayout layout = new GroupLayout(panel);
                panel.setLayout(layout);
                layout.setAutoCreateGaps(true);
                layout.setAutoCreateContainerGaps(true);
                GroupLayout.SequentialGroup hGroup = layout.createSequentialGroup();

                hGroup.addGroup(layout.createParallelGroup().addComponent(interfaceLabel).addComponent(portLabel).addComponent(saveButton));
                hGroup.addGroup(layout.createParallelGroup().addComponent(interfaceField).addComponent(portField));
                layout.setHorizontalGroup(hGroup);

                GroupLayout.SequentialGroup vGroup = layout.createSequentialGroup();

                vGroup.addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE).addComponent(interfaceLabel).addComponent(interfaceField));
                vGroup.addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE).addComponent(portLabel).addComponent(portField));
                vGroup.addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE).addComponent(saveButton));

                layout.setVerticalGroup(vGroup);

                restoreConfig();
                callbacks.customizeUiComponent(scroll);

                // add the custom tab to Burp's UI
                callbacks.addSuiteTab(BurpExtender.this);
            }
        });
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse requestResponse) {
        if (messageIsRequest) {
            BHttpRequest req = BHttpRequestFactory.create(requestResponse, helpers.analyzeRequest(requestResponse),
                    callbacks);

            wss.sendToAll(gson.toJson(req));

            try {
                // TODO: Place URL into settings
                // Send request to service hook URL.
                HttpResponse<JsonNode> modRequestResponse = Unirest.post("http://localhost:3001/request")
                        .header("accept", "application/json")
                        .header("content-type", "application/json")
                        .body(gson.toJson(req))
                        .asJson();
                if (modRequestResponse.getCode() == 200) {
                    // Build a BHttpRequest from the JSON response.
                    BHttpRequest modifiedHttpRequest = gson.fromJson(new InputStreamReader(modRequestResponse.getRawBody()),
                            BHttpRequest.class);
                    // Set the request burp sends to server by building a header list and from the possibly modified
                    // request body.
                    // TODO: There should probably be a bit more logic as to how this request gets modified
                    // since there are multiple ways to modify a request.
                    requestResponse.setRequest(helpers.buildHttpMessage(modifiedHttpRequest.headersToList(),
                            modifiedHttpRequest.body));
                    // Set the host, port, and protocol burp uses for the request sent to server.
                    requestResponse.setHttpService(helpers.buildHttpService(modifiedHttpRequest.host,
                            modifiedHttpRequest.port, modifiedHttpRequest.protocol));
                }
            } catch (UnirestException e) {
                // Do nothing.
            }

        } else {
            BHttpResponse resp = BHttpResponseFactory.create(requestResponse,
                    helpers.analyzeResponse(requestResponse.getResponse()), callbacks);
            wss.sendToAll(gson.toJson(resp));
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
    }

    @Override public String getTabCaption()
    {
        return "Burp Buddy";
    }

    @Override public Component getUiComponent()
    {
        return scroll;
    }

    public void saveConfig()
    {
        try {
            port = Integer.parseInt(portField.getText());
            if (port < 0 || port > 65535) {
                stderr.println("Invalid port, using default.");
                port = DEFAULT_PORT;
            }
        } catch (NumberFormatException e) {
            stderr.println("Invalid port, using default.");
            port = DEFAULT_PORT;
        }
        portField.setText(String.valueOf(port));

        ip = interfaceField.getText();

        this.callbacks.saveExtensionSetting("save", "1");
        this.callbacks.saveExtensionSetting("port", Integer.toString(port));
        this.callbacks.saveExtensionSetting("ip", ip); 

        // Restart WSS
        stopWSS();
        startWSS();
    }

    public void restoreConfig()
    {
        stdout.println("Restore Config called");
        if (callbacks.loadExtensionSetting("save") == null || callbacks.loadExtensionSetting("save").equals("0")) {
            restoreDefaults();
        } else {
            
            if (this.callbacks.loadExtensionSetting("port") != null) {
                port = Integer.parseInt(this.callbacks.loadExtensionSetting("port"));
            } else {
                port = DEFAULT_PORT;
            }
            portField.setText(String.valueOf(port));


            if (this.callbacks.loadExtensionSetting("ip") != null) {
                ip = this.callbacks.loadExtensionSetting("ip");
            }
            else {
                ip = DEFAULT_IP;
            }
            interfaceField.setText(ip);

            startWSS();
            callbacks.registerExtensionStateListener(this);
            callbacks.registerHttpListener(this);
            callbacks.registerScannerListener(this);
        }
    }

    public void restoreDefaults()
    {
        stdout.println("Restore Defaults called");
        this.callbacks.saveExtensionSetting("save", "2");
        
        port = DEFAULT_PORT;
        ip = DEFAULT_IP;
    }

    public void stopWSS() 
    {
        try {
            wss.stop();
            stdout.println("WebSocket server stopped");
        } catch(IOException e) {
            stderr.println("Exception when stopping WebSocket server");
            stderr.println(e.getMessage());
        } catch(InterruptedException e) {
            stderr.println("Exception when stopping WebSocket server");
            stderr.println(e.getMessage());
        }
    }

    public void startWSS()
    {
        InetSocketAddress address = new InetSocketAddress(ip, port);
        wss = new EventServer(stdout, stderr, address);
        wss.start();
        stdout.println("WebSocket server started at ws://" + ip + ":" + port);
    }

}
