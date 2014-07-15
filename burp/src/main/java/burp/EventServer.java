package burp;

import java.net.InetSocketAddress;
import java.util.Collection;
import java.io.PrintWriter;
import org.java_websocket.WebSocket;
import org.java_websocket.handshake.ClientHandshake;
import org.java_websocket.server.WebSocketServer;


public class EventServer extends WebSocketServer {

    private PrintWriter stdout;
    private PrintWriter stderr;
    private String allowedOrigin;

    public EventServer(String allowedOrigin, PrintWriter stdout, PrintWriter stderr, InetSocketAddress inetSocketAddress) {
        super(inetSocketAddress);
        this.stdout = stdout;
        this.stderr = stderr;
        this.allowedOrigin = allowedOrigin;
    }

    @Override
    public void onOpen(WebSocket conn, ClientHandshake handshake) {

        String origin = handshake.getFieldValue("Origin");
        if (origin == null || (!origin.equals(allowedOrigin) && !allowedOrigin.equals("*"))) {
            stdout.println("Denied origin: " + origin);
            conn.close();
            return;
        }

        stdout.println(conn.getRemoteSocketAddress().getAddress().getHostAddress() +
                " connected to socket server");
        stdout.println("Origin: " + origin);
    }

    @Override
    public void onClose(WebSocket conn, int code, String reason, boolean remote) {
        stdout.println(conn.getRemoteSocketAddress().getAddress().getHostAddress() +
                       " closed their connection to socket server");
    }

    @Override
    public void onMessage(WebSocket conn, String message ) {
        // Currently the socket server is only used for subscribing to messages.
    }

    @Override
    public void onError(WebSocket conn, Exception ex) {
        stderr.println("Socket server error. Printing stack trace:");
        ex.printStackTrace(stderr);
    }

    public void sendToAll(String text) {
        Collection<WebSocket> con = connections();
        synchronized (con) {
            for(WebSocket c: con) {
                c.send(text);
            }
        }
    }
}
