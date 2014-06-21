package burp;

import java.util.List;

public class BScanQueueItem {
    public int id;
    public int errors;
    public int insertionPointCount;
    public int requestCount;
    public String status;
    public byte percentComplete;
    public List<BScanIssue> issues;
}
