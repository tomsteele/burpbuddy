package burp;

public class BFakeScannerForMessageFactory {

    public static BFakeScannerForMessage create(IBurpExtenderCallbacks callbacks, EventServer wss) {
        return new BFakeScannerForMessage(callbacks, wss);
    }
}
