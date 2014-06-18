package burp;


import java.net.URL;
import java.net.MalformedURLException;
import java.util.*;

public class BHttpRequest extends BSocketMessage {
    public String host;
    public int port;
    public String protocol;
    public String highlight;
    public String comment;
    public String url;
    public String method;
    public HashMap<String, String> headers;
    public byte[] body;
    public byte[] raw;
    public boolean inScope;


    public List<String> headersToList() {
        List<String> burpHeaders = new ArrayList<String>();
        try {
            URL url = new URL(this.url);
            // TODO: There is probably a better way to do this. Reference TODO in BurpExtender.
            burpHeaders.add(this.method + " " + url.getPath() + " HTTP/1.1");
        } catch (MalformedURLException e) {
            // Do nothing.
        }
        for (Map.Entry<String, String> pair: this.headers.entrySet()) {
            burpHeaders.add(pair.getKey() + ": " + pair.getValue());
        }
        return burpHeaders;
    }
}
