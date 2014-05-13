package burp;

import java.util.Arrays;
import java.util.List;
import java.util.HashMap;

public class BHttpRequestFactory {

    public static BHttpRequest create(IHttpRequestResponse request, IRequestInfo requestInfo) {
        int bodyOffset = requestInfo.getBodyOffset();
        byte[] rawRequest = request.getRequest();
        byte[] rawBody = Arrays.copyOfRange(rawRequest, bodyOffset, rawRequest.length);
        IHttpService service = request.getHttpService();
        BHttpRequest req = new BHttpRequest();
        // Burp populates the first header with the Method and Path.
        // Removing it here.
        List<String> allHeaders = requestInfo.getHeaders();
        List<String> headers = allHeaders.subList(1, allHeaders.size());
        HashMap<String, String> headerMap = new HashMap<String, String>();
        for (String header: headers) {
            String[] values = header.split(":", 2);
            if (values.length == 2) {
                headerMap.put(values[0].trim(), values[1].trim());
            }
        }

        req.messageType = "request";
        req.method = requestInfo.getMethod();
        req.url = requestInfo.getUrl().toString();
        req.headers = headerMap;
        req.raw = rawRequest;
        req.body = rawBody;
        req.highlight = request.getHighlight();
        req.comment = request.getComment();
        req.host = service.getHost();
        req.port = service.getPort();
        req.protocol = service.getProtocol();
        return req;
    }
}
