package burp;


import java.util.List;
import com.google.gson.Gson;

public class BFakeScannerForMessage implements IScannerCheck {

    private EventServer wss;
    private IBurpExtenderCallbacks callbacks;
    private Gson gson;

    public BFakeScannerForMessage(IBurpExtenderCallbacks callbacks, EventServer wss) {
        this.wss = wss;
        this.callbacks = callbacks;
        gson = new Gson();
    }

    //@Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        BHttpRequestResponse bhttpRequestResponse = BHttpRequestResponseFactory.create(baseRequestResponse,
                callbacks, callbacks.getHelpers());
        wss.sendToAll(gson.toJson(bhttpRequestResponse));
        return null;
    }

   // @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null;
    }

   // @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        return 0;
    }
}
