package burp;

import java.util.HashMap;

public class BHttpRequest extends BSocketMessage {
    public String host;
    public int port;
    public String protocol;
    public String highlight;
    public String comment;
    public String url;
    public String method;
    public HashMap<String, String> headers;
    public String body;
    public String raw;
}
