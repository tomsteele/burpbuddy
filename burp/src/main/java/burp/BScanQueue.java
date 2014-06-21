package burp;

import java.util.HashMap;

public class BScanQueue {
    private HashMap<Integer, IScanQueueItem> queue;

    public BScanQueue() {
        queue = new HashMap<>();
    }

    public BScanQueueID addToQueue(IScanQueueItem item) {
        int key = getKey();
        queue.put(key, item);
        return BScanQueueIDFactory.create(key);
    }

    public void removeFromQueue(int key) {
        queue.remove(key);
    }

    public IScanQueueItem getItem(int key) {
        return queue.get(key);
    }

    public int getCount() {
        return queue.size();
    }

    private int getKey() {
        return getCount() + 1;
    }
}
