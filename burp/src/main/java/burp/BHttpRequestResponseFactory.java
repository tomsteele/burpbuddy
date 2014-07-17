package burp;


public class BHttpRequestResponseFactory {

    public static BHttpRequestResponse create(IHttpRequestResponse requestResponse,
                                              IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
        BHttpRequestResponse bHttpRequestResponse = new BHttpRequestResponse();


        if (requestResponse.getRequest() != null && requestResponse.getRequest().length > 0) {
            bHttpRequestResponse.request = BHttpRequestFactory.create(0x00004242, requestResponse,
                    helpers.analyzeRequest(requestResponse), callbacks);
        }

        if (requestResponse.getResponse() != null && requestResponse.getResponse().length > 0) {
            bHttpRequestResponse.response = BHttpResponseFactory.create(0x00004242, requestResponse,
                    helpers.analyzeResponse(requestResponse.getResponse()), callbacks);
        }

        bHttpRequestResponse.messageType = "requestResponse";
        return bHttpRequestResponse;
    }
}
