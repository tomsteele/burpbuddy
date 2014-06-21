package burp;

public class BScanQueueIDFactory {

    public static BScanQueueID create(int key) {
        return new BScanQueueID(key);
    }
}
