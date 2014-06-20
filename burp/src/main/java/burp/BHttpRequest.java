package burp;


import java.util.*;

public class BHttpRequest extends BSocketMessage {
    public String host;
    public int port;
    public String protocol;
    public String highlight;
    public String comment;
    public String url;
    public String path;
    public String httpVersion = "HTTP/1.1";
    public String method;
    public HashMap<String, String> headers;
    public byte[] body;
    public byte[] raw;
    public boolean inScope;
    public int toolFlag = 0x00004242;


    public List<String> headersToList() {
        List<String> burpHeaders = new ArrayList<String>();
        burpHeaders.add(this.method + " " + this.path + " " + this.httpVersion);
        for (Map.Entry<String, String> pair: this.headers.entrySet()) {
            burpHeaders.add(pair.getKey() + ": " + pair.getValue());
        }
        return burpHeaders;
    }
}
