package burp;

import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.net.URL;
import org.apache.commons.codec.binary.Base64;
import com.google.gson.Gson;
import static spark.Spark.*;

public class ApiServer {


    public ApiServer(String ip, int port, IBurpExtenderCallbacks callbacks) {

        IExtensionHelpers helpers = callbacks.getHelpers();
        PrintWriter stdout = new PrintWriter(callbacks.getStdout());
        PrintWriter stderr = new PrintWriter(callbacks.getStderr());
        setPort(port);
        setIpAddress(ip);

        BScanQueue scanQueue = BScanQueueFactory.create();

        Gson gson = new Gson();

        before((request, response) -> {
            String contentType = request.headers("content-type");
            if (!request.requestMethod().equals("GET") && (contentType == null || !contentType.contains("application/json"))) {
                halt(400);
            }
        });

        get("/scope/:url", (request, response) -> {
            try {
                URL url = new URL(new String(Base64.decodeBase64(request.params("url"))));
                if (callbacks.isInScope(url)) {
                    response.status(200);
                    return "";
                } else {
                    response.status(404);
                    return "";
                }
            } catch (MalformedURLException e) {
                response.status(400);
                return e.getMessage();
            }
        });

        post("/scope", (request, response) -> {
            try {
                BURLMessage message = gson.fromJson(request.body(), BURLMessage.class);
                callbacks.includeInScope(new URL(message.url));
                response.status(201);
                return gson.toJson(message);
            } catch (MalformedURLException e) {
                response.status(400);
                return e.getMessage();
            }
        });

        delete("/scope/:url", (request, response) -> {
            try {
                URL url = new URL(new String(Base64.decodeBase64(request.params("url"))));
                callbacks.excludeFromScope(url);
                response.status(200);
                return "";
            } catch (MalformedURLException e) {
                response.status(400);
                return e.getMessage();
            }
        });

        get("/scanissues", (request, response) -> {
            IScanIssue[] rawIssues = callbacks.getScanIssues("");
            List<BScanIssue> issues = new ArrayList<>();
            for (IScanIssue issue : rawIssues) {
                issues.add(BScanIssueFactory.create(issue, callbacks));
            }
            return gson.toJson(new BArrayWrapper(issues));
        });

        get("/scanissues/:url", (request, response) -> {
            byte[] encodedBytes = Base64.decodeBase64(request.params("url"));
            IScanIssue[] rawIssues =  callbacks.getScanIssues(new String(encodedBytes));
            List<BScanIssue> issues = new ArrayList<>();
            for (IScanIssue issue : rawIssues) {
                issues.add(BScanIssueFactory.create(issue, callbacks));
            }
            return gson.toJson(issues);
        });

        post("/scanissues", (request, response) -> {
            BScanIssue issue = gson.fromJson(request.body(), BScanIssue.class);
            callbacks.addScanIssue(issue);
            response.status(201);
            return gson.toJson(issue);
        });

        post("/spider", (request, response) -> {
            BURLMessage message = gson.fromJson(request.body(), BURLMessage.class);
            try {
                callbacks.sendToSpider(new URL(message.url));
                response.status(200);
                return "";
            } catch (MalformedURLException e) {
                response.status(400);
                return e.getMessage();
            }
        });

        get("/jar", (request, response) -> {
            List<BCookie> cookies = new ArrayList<>();
            for (ICookie burpCookie: callbacks.getCookieJarContents()) {
                BCookie cookie = new BCookie();
                cookie.expiration = burpCookie.getExpiration();
                cookie.domain = burpCookie.getDomain();
                cookie.name = burpCookie.getName();
                cookie.value = burpCookie.getValue();
                cookies.add(cookie);
            }
            return gson.toJson(new BArrayWrapper(cookies));
        });

        post("/jar", (request, response) -> {
            BCookie cookie = gson.fromJson(request.body(), BCookie.class);
            callbacks.updateCookieJar(new ICookie() {
                @Override
                public String getDomain() {
                    return cookie.domain;
                }

                @Override
                public Date getExpiration() {
                    return cookie.expiration;
                }

                @Override
                public String getName() {
                    return cookie.name;
                }

                @Override
                public String getValue() {
                    return cookie.value;
                }
            });
            response.status(201);
            return gson.toJson(cookie);
        });

        post("/scan/active", (request, response) -> {
            BScanMessage message = gson.fromJson(request.body(), BScanMessage.class);
            IScanQueueItem item = callbacks.doActiveScan(message.host, message.port, message.useHttps, message.request);
            BScanQueueID id = scanQueue.addToQueue(item);
            response.status(201);
            return gson.toJson(id);
        });

        get("/scan/active/:id", (request, response) -> {
            int id = Integer.parseInt(request.params("id"));
            IScanQueueItem item = scanQueue.getItem(id);
            if (item == null) {
                response.status(404);
                return "";
            }
            response.status(200);
            BScanQueueItem bScanQueueItem = BScanQueueItemFactory.create(id, item, callbacks);
            return gson.toJson(bScanQueueItem);
        });

        delete("/scan/active/:id", (request, response) -> {
            int id = Integer.parseInt(request.params("id"));
            IScanQueueItem item = scanQueue.getItem(id);
            if (item == null) {
                response.status(404);
                return "";
            }
            response.status(200);
            item.cancel();
            scanQueue.removeFromQueue(id);
            return "";
        });

        post("/scan/passive", (request, response) -> {
            BScanMessage message = gson.fromJson(request.body(), BScanMessage.class);
            callbacks.doPassiveScan(message.host, message.port, message.useHttps, message.request, message.response);
            response.status(201);
            return "ok";
        });

        post("/send/:tool", (request, response) -> {
            String tool = request.params("tool");
            BScanMessage message = gson.fromJson(request.body(), BScanMessage.class);
            switch (tool) {
                case "intruder":
                    callbacks.sendToIntruder(message.host, message.port, message.useHttps, message.request);
                    response.status(201);
                    break;
                case "repeater":
                    callbacks.sendToRepeater(message.host, message.port, message.useHttps, message.request, "buddy");
                    response.status(201);
                    break;
                default:
                    response.status(404);
                    break;
            }
            return "";
        });

        post("/alert", (request, response) -> {
            callbacks.issueAlert(gson.fromJson(request.body(), BMessage.class).message);
            response.status(201);
            return "";
        });

        post("/stdout", (request, response) -> {
            stdout.println(gson.fromJson(request.body(), BMessage.class).message);
            response.status(201);
            return "";
        });

        post("/stderr", (request, response) -> {
            stderr.println(gson.fromJson(request.body(), BMessage.class).message);
            response.status(201);
            return "";
        });

        get("/sitemap", (request, response) -> {
            List<BHttpRequestResponse> pairs = new ArrayList<>();
            for (IHttpRequestResponse requestResponse: callbacks.getSiteMap("")) {
                pairs.add(BHttpRequestResponseFactory.create(requestResponse, callbacks, helpers));
            }
            return gson.toJson(new BArrayWrapper(pairs));
        });

        get("/sitemap/:url", (request, response) -> {
            byte[] encodedBytes = Base64.decodeBase64(request.params("url"));
            List<BHttpRequestResponse> pairs = new ArrayList<>();
            for (IHttpRequestResponse requestResponse: callbacks.getSiteMap(new String(encodedBytes))) {
                pairs.add(BHttpRequestResponseFactory.create(requestResponse, callbacks, helpers));
            }
            return gson.toJson(new BArrayWrapper(pairs));
        });

        post("/sitemap", (request, response) -> {
            BHttpRequestResponse bHttpRequestResponse = gson.fromJson(request.body(), BHttpRequestResponse.class);
            callbacks.addToSiteMap(bHttpRequestResponse);
            response.status(201);
            return gson.toJson(bHttpRequestResponse);
        });

        get("/proxyhistory", (request, response) -> {
            List<BHttpRequestResponse> pairs = new ArrayList<>();
            for (IHttpRequestResponse requestResponse: callbacks.getProxyHistory()) {
                pairs.add(BHttpRequestResponseFactory.create(requestResponse, callbacks, helpers));
            }
            return gson.toJson(new BArrayWrapper(pairs));
        });

    }

    public void stopServer() {
        stop();
    }

}
