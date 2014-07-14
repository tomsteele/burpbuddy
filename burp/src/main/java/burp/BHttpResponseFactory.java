package burp;

import java.net.MalformedURLException;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.List;
import java.util.HashMap;
import java.net.URL;

public class BHttpResponseFactory {

    public static BHttpResponse create(int toolFlag, IHttpRequestResponse response, IResponseInfo responseInfo,
                                       IBurpExtenderCallbacks callbacks) {
        int bodyOffset = responseInfo.getBodyOffset();
        byte[] rawResponse = response.getResponse();
        byte[] rawBody = Arrays.copyOfRange(rawResponse, bodyOffset, rawResponse.length);
        IHttpService service = response.getHttpService();
        BHttpResponse resp = new BHttpResponse();

        List<String> allHeaders = responseInfo.getHeaders();
        List<String> headers = allHeaders.subList(1, allHeaders.size());
        HashMap<String, String> headerMap = new HashMap<String, String>();
        for (String header: headers) {
            String[] values = header.split(":", 2);
            if (values.length == 2) {
                headerMap.put(values[0].trim(), values[1].trim());
            }
        }

        List<ICookie> burpCookies = responseInfo.getCookies();
        List<BCookie> cookies = new ArrayList<BCookie>();
        for (ICookie cookie: burpCookies) {
            BCookie bcookie = new BCookie();
            bcookie.domain = cookie.getDomain();
            bcookie.expiration = cookie.getExpiration();
            bcookie.name = cookie.getName();
            bcookie.value = cookie.getValue();
            cookies.add(bcookie);
        }

        resp.toolFlag = toolFlag;
        resp.messageType = "response";
        resp.raw = rawResponse;
        resp.body = rawBody;
        resp.mimeType = responseInfo.getStatedMimeType();
        resp.statusCode = responseInfo.getStatusCode();
        resp.cookies = cookies;
        resp.headers = headerMap;
        resp.host = service.getHost();
        resp.port = service.getPort();
        resp.protocol = service.getProtocol();
        resp.comment = response.getComment();
        resp.highlight = response.getHighlight();
        try {
            resp.inScope = callbacks.isInScope(new URL(resp.protocol, resp.host, resp.port, "/"));
        } catch (MalformedURLException e) {
            resp.inScope = false;
        }
        return resp;
    }
}
