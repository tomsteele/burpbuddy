package burp;


public class BHttpRequestResponseFactory {

    public static BHttpRequestResponse create(IHttpRequestResponse requestResponse,
                                              IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
        BHttpRequestResponse bHttpRequestResponse = new BHttpRequestResponse();
        bHttpRequestResponse.request = BHttpRequestFactory.create(requestResponse,
                helpers.analyzeRequest(requestResponse), callbacks);
        bHttpRequestResponse.response = BHttpResponseFactory.create(requestResponse,
                helpers.analyzeResponse(requestResponse.getResponse()), callbacks);
        return bHttpRequestResponse;
    }
}
