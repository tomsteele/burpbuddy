package burp;

import java.util.ArrayList;

public class BScanQueueItemFactory {

    public static BScanQueueItem create(int key, IScanQueueItem item, IBurpExtenderCallbacks callbacks) {
        BScanQueueItem bScanQueueItem = new BScanQueueItem();
        bScanQueueItem.id = key;
        bScanQueueItem.errors = item.getNumErrors();
        bScanQueueItem.insertionPointCount = item.getNumInsertionPoints();
        bScanQueueItem.requestCount = item.getNumRequests();
        bScanQueueItem.status = item.getStatus();
        bScanQueueItem.percentComplete = item.getPercentageComplete();
        bScanQueueItem.issues = new ArrayList<>();
        for (IScanIssue issue: item.getIssues()) {
            bScanQueueItem.issues.add(BScanIssueFactory.create(issue, callbacks));
        }
        return bScanQueueItem;
    }
}
