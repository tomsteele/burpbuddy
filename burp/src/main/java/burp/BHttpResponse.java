package burp;

import java.util.HashMap;
import java.util.List;

public class BHttpResponse extends BSocketMessage {
    public short statusCode;
    public byte[] raw;
    public byte[] body;
    public HashMap<String, String> headers;
    public List<BCookie> cookies;
    public String mimeType;
    public String host;
    public String protocol;
    public int port;
    public String highlight;
    public String comment;
    public boolean inScope;
    public int toolFlag = 0x00004242;
    public int referenceID;
}
