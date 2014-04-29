package burp;

// TODO: Build HTTP requests/response.
public class BScanIssue extends BSocketMessage {
    public String url;
    public String host;
    public int port;
    public String protocol;
    public String name;
    public int issueType;
    public String severity;
    public String confidence;
    public String issueBackground;
    public String remediationBackground;
    public String issueDetail;
    public String remediationDetail;

}
