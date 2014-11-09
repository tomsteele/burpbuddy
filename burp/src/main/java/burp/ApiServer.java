package burp;

import java.io.*;
import java.net.MalformedURLException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.net.URL;
import java.util.UUID;
import javax.servlet.ServletException;
import javax.servlet.http.Part;
import javax.servlet.MultipartConfigElement;

import org.apache.commons.codec.binary.Base64;
import com.google.gson.Gson;
import static spark.Spark.*;

public class ApiServer {

    public boolean isNotSameOrigin(String host, String origin) {
        if (origin == null || origin.isEmpty()) {
            return false;
        }

        try {
            URL urlOrigin = new URL(origin);
            if (host.equals(urlOrigin.getAuthority())) {
                return false;
            }
        } catch (Exception e) {
            return true;
        }

        return true;
    }

    public ApiServer(String ip, int port, IBurpExtenderCallbacks callbacks) {

        IExtensionHelpers helpers = callbacks.getHelpers();
        setPort(port);
        setIpAddress(ip);

        BScanQueue scanQueue = BScanQueueFactory.create();

        Gson gson = new Gson();

        before((request, response) -> {
            String contentType = request.headers("content-type");
            if (!request.requestMethod().equals("GET") &&
               (contentType == null ||
               !contentType.contains("application/json")) &&
               isNotSameOrigin(request.host(), request.headers("origin"))) {
               halt(400);
            }
        });

        before((request, response) -> {
            response.type("application/json; charset=UTF8");
        });

        exception(Exception.class, (e, request, response) -> {
            response.status(400);
            response.body("{\"error\": \"" + e.getMessage() + "\"}");
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
                response.status(204);
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
            return gson.toJson(new BArrayWrapper(issues));
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
                response.status(201);
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
            IScanQueueItem item = callbacks.doActiveScan(message.host, message.port, message.useHttps,
                   Base64.decodeBase64(message.request));
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
            response.status(204);
            item.cancel();
            scanQueue.removeFromQueue(id);
            return "";
        });

        post("/scan/passive", (request, response) -> {
            BScanMessage message = gson.fromJson(request.body(), BScanMessage.class);
            callbacks.doPassiveScan(message.host, message.port, message.useHttps, Base64.decodeBase64(message.request),
                    Base64.decodeBase64(message.response));
            response.status(201);
            return "ok";
        });

        post("/send/:tool", (request, response) -> {
            String tool = request.params("tool");
            BScanMessage message = gson.fromJson(request.body(), BScanMessage.class);
            switch (tool) {
                case "intruder":
                    callbacks.sendToIntruder(message.host, message.port, message.useHttps,
                            Base64.decodeBase64(message.request));
                    response.status(201);
                    break;
                case "repeater":
                    callbacks.sendToRepeater(message.host, message.port, message.useHttps,
                            Base64.decodeBase64(message.request), "buddy");
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

        get("/state", (request, response) -> {
            File file;
            try {
                file = File.createTempFile(UUID.randomUUID().toString(), "state");
            } catch (IOException e) {
                response.status(500);
                return "{\"error\": \"" + e.getMessage() + "\"}";
            }
            callbacks.saveState(file);

            response.type("application/octet-stream");
            response.header("Content-Disposition", "attachment; filename=burp.state");
            try {
                DataInputStream inputStream = new DataInputStream(new FileInputStream(file.getPath()));
                DataOutputStream outStream = new DataOutputStream(response.raw().getOutputStream());
                byte[] buf = new byte[inputStream.available()];
                inputStream.readFully(buf);
                outStream.write(buf);
                inputStream.close();
                outStream.close();

            } catch (IOException e) {
                response.status(500);
                return "{\"error\": \"" + e.getMessage() + "\"}";
            } finally {
                file.deleteOnExit();
            }
            response.status(200);
            return "";
        });

        post("/state", (request, response) -> {
            MultipartConfigElement multipartConfigElement = new MultipartConfigElement(System.getProperty("java.io.tmpdir"));
            request.raw().setAttribute("org.eclipse.multipartConfig", multipartConfigElement);
            try {
                Part file = request.raw().getPart("file");
                File tmpFile = File.createTempFile(UUID.randomUUID().toString(), "state");

                DataInputStream inputStream = new DataInputStream(file.getInputStream());
                FileOutputStream outStream = new FileOutputStream(tmpFile.getPath());

                byte[] buf = new byte[inputStream.available()];
                inputStream.readFully(buf);
                outStream.write(buf);
                inputStream.close();
                outStream.close();
                callbacks.restoreState(tmpFile);
                tmpFile.deleteOnExit();

            } catch (ServletException|IOException e) {
                response.status(500);
                return "{\"error\": \"" + e.getMessage() + "\"}";
            }

            response.status(200);
            return "";
        });
        
        post("/proxy/intercept/enable", (request, response) -> {
            callbacks.setProxyInterceptionEnabled(true);
            response.status(201);
            return "";
        });
        post("/proxy/intercept/disable", (request, response) -> {
            callbacks.setProxyInterceptionEnabled(false);
            response.status(201);
            return "";
        });


    }

    public void stopServer() {
        stop();
    }

}
