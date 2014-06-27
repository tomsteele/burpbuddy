package burp;

public class BHttpRequestResponse extends BSocketMessage implements IHttpRequestResponse {
    public BHttpRequest request;
    public BHttpResponse response;

    public byte[] getRequest() {
        return request.raw;
    }

    public void setRequest(byte[] message) {
        request.raw = message;
    }

    public byte[] getResponse() {
        return response.raw;
    }

    public void setResponse(byte[] message) {
        response.raw = message;
    }

    public String getComment() {
        return request.comment;
    }

    public void setComment(String comment) {
        request.comment = comment;
        response.comment = comment;
    }

    public String getHighlight() {
        return request.highlight;
    }

    public void setHighlight(String color) {
        request.highlight = color;
        response.highlight = color;
    }

    public IHttpService getHttpService() {
        return new IHttpService() {
            @Override
            public String getHost() {
                return request.host;
            }

            @Override
            public int getPort() {
                return request.port;
            }

            @Override
            public String getProtocol() {
                return  request.protocol;
            }
        };
    }

    public void setHttpService(IHttpService httpService) {
        request.host = httpService.getHost();
        request.port = httpService.getPort();
        request.protocol = httpService.getProtocol();
        response.host = httpService.getHost();
        response.port = httpService.getPort();
        response.protocol = httpService.getProtocol();
    }
}
