package burp;

import java.util.HashMap;

public class BHttpRequest {
    public String url;
    public String method;
    public HashMap<String, String> headers;
    public String body;
    public String raw;
}
