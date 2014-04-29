package burp;

import java.io.IOException;
import java.lang.InterruptedException;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import com.google.gson.Gson;

public class BurpExtender implements IBurpExtender, IHttpListener, IExtensionStateListener {
    static final String NAME = "Burp Buddy";

    private EventServer wss;
    private Gson gson = new Gson();
    private IExtensionHelpers helpers;

    @Override
    public void registerExtenderCallbacks (IBurpExtenderCallbacks callbacks) {
        callbacks.setExtensionName(NAME);
        PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
        PrintWriter stderr = new PrintWriter(callbacks.getStderr(), true);
        helpers = callbacks.getHelpers();
        String ip = "127.0.0.1";
        int port =  8000;

        InetSocketAddress address = new InetSocketAddress(ip, port);
        wss = new EventServer(stdout, stderr, address);
        wss.start();
        stdout.println("Websocket server started at ws://" + ip + ":" + port);

        callbacks.registerExtensionStateListener(this);
        callbacks.registerHttpListener(this);
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse request) {
        if (messageIsRequest) {
            BHttpRequest req = BHttpRequestFactory.create(request, helpers.analyzeRequest(request));
            wss.sendToAll(gson.toJson(req));
        }
    }


    @Override
    public void extensionUnloaded() {
        try {
            wss.stop();
        } catch(IOException e) {
            //
        } catch(InterruptedException e) {
            //
        }
    }
}
