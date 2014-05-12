package burp;

import java.io.IOException;
import java.lang.InterruptedException;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import com.google.gson.Gson;

public class BurpExtender implements IBurpExtender, IExtensionStateListener,
        IHttpListener, IScannerListener, IProxyListener {
    static final String NAME = "Burp Buddy";

    private EventServer wss;
    private Gson gson = new Gson();
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private PrintWriter stderr;

    @Override
    public void registerExtenderCallbacks (IBurpExtenderCallbacks callbacks) {
        callbacks.setExtensionName(NAME);
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);
        helpers = callbacks.getHelpers();
        String ip = "127.0.0.1";
        int port =  8000;

        InetSocketAddress address = new InetSocketAddress(ip, port);
        wss = new EventServer(stdout, stderr, address);
        wss.start();
        stdout.println("WebSocket server started at ws://" + ip + ":" + port);

        callbacks.registerExtensionStateListener(this);
        callbacks.registerHttpListener(this);
        callbacks.registerScannerListener(this);
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse requestResponse) {
        if (messageIsRequest) {
            BHttpRequest req = BHttpRequestFactory.create(requestResponse, helpers.analyzeRequest(requestResponse));
            wss.sendToAll(gson.toJson(req));
        } else {
            BHttpResponse resp = BHttpResponseFactory.create(requestResponse, helpers.analyzeResponse(requestResponse.getResponse()));
            wss.sendToAll(gson.toJson(resp));
        }
    }

    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {

    }

    @Override
    public void newScanIssue(IScanIssue scanIssue) {
        BScanIssue issue = BScanIssueFactory.create(scanIssue);
        wss.sendToAll(gson.toJson(issue));
    }

    @Override
    public void extensionUnloaded() {
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
}
