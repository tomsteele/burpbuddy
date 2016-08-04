package burp

import com.github.salomonbrys.kotson.fromJson
import com.github.salomonbrys.kotson.jsonObject
import com.google.gson.Gson
import spark.Request
import spark.Response
import spark.Spark.*
import java.net.MalformedURLException
import java.net.URL
import java.util.*
import com.github.salomonbrys.kotson.jsonArray
import com.github.salomonbrys.kotson.toJsonArray

class API() {

    fun start(ip: String, port: Int, callbacks: IBurpExtenderCallbacks, stdout: java.io.PrintWriter) {
        val b64Decoder = Base64.getDecoder()
        val gson = Gson()
        val b2b = BurpToBuddy(callbacks)

        ipAddress(ip)
        port(port)

        val queue : MutableMap<Int, IScanQueueItem> = mutableMapOf()

        before { request, response -> response.type("application/json; charset=UTF8") }

        before(fun(req: Request, res: Response) {
            val contentType = req.headers("content-type")
            if (req.requestMethod().equals("GET")) {
                return
            }
            if ((contentType == null ||
                    !contentType.contains("application/json")) &&
                    isNotSameOrigin(req.host(), req.headers("origin"))) {
                        halt(400)
                    }
        })

        exception(Exception::class.java) { e, req, resp ->
            resp.status(400)
            resp.body("{\"error\": \"" + e.message + "\"}")
        }

        get("/ping", fun(req: Request, res: Response): String {
            res.status(200)
            return "PONG"
        })

        get("/scope/:url", fun(req: Request, res: Response): String {
            val urlParam = req.params("url") ?: ""
            val plainURL = String(b64Decoder.decode(urlParam))
            try {
                val url = URL(plainURL)
                if (callbacks.isInScope(url)) {
                    res.status(200)
                    return jsonObject("is_in_scope" to true).toString()
                }
                res.status(404)
                return jsonObject("is_in_scope" to false).toString()
            } catch (e: MalformedURLException) {
                res.status(400)
                val msg = e.message ?: "invalid url"
                return b2b.apiError("url", msg).toString()
            }
        })

        post("/scope", fun(req: Request, res: Response): String {
            val scopeMSG = gson.fromJson<URLMessage>(req.body())
            try {
                callbacks.includeInScope(URL(scopeMSG.url))
                res.status(201)
                return gson.toJson(scopeMSG)
            } catch (e: MalformedURLException) {
                res.status(400)
                val msg = e.message ?: "invalid url"
                return b2b.apiError("url", msg).toString()
            }
        })

        delete("/scope/:url", fun(req: Request, res: Response): String {
            val urlParam = req.params("url") ?: ""
            val plainURL = String(b64Decoder.decode(urlParam))
            try {
                val url = URL(plainURL)
                callbacks.excludeFromScope(url)
                res.status(204)
                return ""
            } catch (e: MalformedURLException) {
                res.status(400)
                val msg = e.message ?: "invalid url"
                return b2b.apiError("url", msg).toString()
            }
        })

        get("/scanissues", fun(req: Request, res: Response): String {
            val issues = b2b.scanIssuesToJsonArray(callbacks.getScanIssues(""))
            res.status(200)
            return issues.toString()
        })

        get("/scanissues/:url", fun(req: Request, res: Response): String {
            val url = String(b64Decoder.decode(req.params("url") ?: ""))
            val issues = b2b.scanIssuesToJsonArray(callbacks.getScanIssues(url))
            res.status(200)
            return issues.toString()
        })

        post("/scanissues", fun(req: Request, res: Response) : String {
            val issue = gson.fromJson<ScanIssue>(req.body())
            // TODO: validate fields relevant to burp specific items, e.g, color, confidence.
            callbacks.addScanIssue(BScanIssue(issue))
            res.status(201)
            return gson.toJson(issue)
        })

        post("/spider", fun(req: Request, res: Response): String {
            val urlMSG = gson.fromJson<URLMessage>(req.body())
            try {
                callbacks.sendToSpider(URL(urlMSG.url))
                res.status(201)
                return gson.toJson(urlMSG)
            } catch (e: MalformedURLException) {
                res.status(400)
                val msg = e.message ?: "invalid url"
                return b2b.apiError("url", msg).toString()
            }
        })

        get("/jar", fun(req: Request, res: Response): String{
            val cookies = callbacks.cookieJarContents.map { Cookie(it.domain, it.expiration, it.path, it.name, it.value) }
            res.status(200)
            return jsonArray(cookies).toString()
        })

        post("/jar", fun(req: Request, res: Response): String {
            val cookie = gson.fromJson<Cookie>(req.body())
            callbacks.updateCookieJar(BCookie(cookie))
            res.status(201)
            return gson.toJson(cookie)
        })

        post("/scan/active", fun(req: Request, res: Response): String {
            val scanMSG = gson.fromJson<ScanMessage>(req.body())
            val item = callbacks.doActiveScan(scanMSG.host, scanMSG.port, scanMSG.use_https, b64Decoder.decode(scanMSG.request))
            val id = queue.size + 1
            queue.put(id, item)
            res.status(201)
            return jsonObject(
                    "id" to id
            ).toString()
        })

        get("/scan/active", fun(req: Request, res: Response): String {
            val items = jsonArray()
            queue.entries.forEach {
                val id = it.key
                val item = it.value
                items.add(jsonObject(
                        "id" to id,
                        "issues" to b2b.scanIssuesToJsonArray(item.issues),
                        "error_count" to item.numErrors,
                        "insertion_point_count" to item.numInsertionPoints,
                        "request_count" to item.numRequests,
                        "percent_complete" to item.percentageComplete,
                        "status" to item.status
                ))
            }
            res.status(200)
            return items.toString()
        })

        get("/scan/active/:id", fun(req: Request, res: Response): String {
            val id = req.params("id").toInt()
            val item = queue[id]
            if (item == null) {
                res.status(404)
                return b2b.apiError("id", "scan item not found").toString()
            }
            return jsonObject(
                    "id" to id,
                    "issues" to b2b.scanIssuesToJsonArray(item.issues),
                    "error_count" to item.numErrors,
                    "insertion_point_count" to item.numInsertionPoints,
                    "request_count" to item.numRequests,
                    "percent_complete" to item.percentageComplete,
                    "status" to item.status
            ).toString()
        })

        delete("/scan/active/:id", fun(req: Request, res: Response): String {
            val id = req.params("id").toInt()
            val item = queue[id]
            if (item == null) {
                res.status(404)
                return b2b.apiError("id", "scan item not found").toString()
            }
            item.cancel()
            queue.remove(id)
            res.status(204)
            return ""
        })

        post("/scan/passive", fun(req: Request, res: Response): String {
            val scanMSG = gson.fromJson<ScanMessage>(req.body())
            callbacks.doPassiveScan(scanMSG.host, scanMSG.port, scanMSG.use_https,
                    b64Decoder.decode(scanMSG.request), b64Decoder.decode(scanMSG.response))
            res.status(201)
            return ""
        })

        post("/send/:tool", fun(req: Request, res: Response): String {
            val tool = req.params("tool")
            val scanMSG = gson.fromJson<ScanMessage>(req.body())
            when (tool) {
                "intruder" -> callbacks.sendToIntruder(scanMSG.host, scanMSG.port, scanMSG.use_https,
                        b64Decoder.decode(scanMSG.request))
                "repeater" -> callbacks.sendToRepeater(scanMSG.host, scanMSG.port, scanMSG.use_https,
                        b64Decoder.decode(scanMSG.request), "buddy")
                else -> {
                    res.status(404)
                    return b2b.apiError("tool", "tool not found").toString()
                }
            }
            res.status(200)
            return ""
        })

        post("/alert", fun(req: Request, res:Response): String {
            callbacks.issueAlert(gson.fromJson<Message>(req.body()).message)
            res.status(201)
            return ""
        })

        get("/sitemap", fun(req: Request, res: Response): String {
            val maps = jsonArray()
            callbacks.getSiteMap("").forEach {
                maps.add(b2b.httpRequestResponseToJsonObject(it))
            }
            return maps.toString()
        })

        get("/sitemap/:url", fun(req: Request, res: Response): String {
            val maps = jsonArray()
            callbacks.getSiteMap(String(b64Decoder.decode(req.params("url")))).forEach {
                maps.add(b2b.httpRequestResponseToJsonObject(it))
            }
            return maps.toString()
        })

        post("/sitemap", fun(req: Request, res: Response): String {
            val message = gson.fromJson<SiteMapMessage>(req.body())
            callbacks.addToSiteMap(BHttpRequestResponse(
                    HttpRequestResponse(httpRequestWithOnlyRaw(message.request), httpResponseWithOnlyRaw(message.response),
                            message.highlight, message.comment, HttpService(message.host, message.port, message.protocol)
                            ), HttpService(message.host, message.port, message.protocol)
            ))
            res.status(201)
            return gson.toJson(message)
        })

        get("/proxyhistory", fun(req: Request, res: Response): String {
            val history = jsonArray()
            callbacks.proxyHistory.forEach {
                history.add(b2b.httpRequestResponseToJsonObject(it))
            }
            res.status(200)
            return history.toString()
        })

        post("/proxy/intercept/enable", fun(req: Request, res: Response): String {
            callbacks.setProxyInterceptionEnabled(true);
            res.status(200);
            return ""
        })

        post("/proxy/intercept/disable", fun(req: Request, res: Response): String {
            callbacks.setProxyInterceptionEnabled(false)
            res.status(200);
            return ""
        })
    }

    fun quit() {
        stop()
    }

    fun httpRequestWithOnlyRaw(raw: String): HttpRequest {
        return HttpRequest("", "", "", emptyMap(), raw, 0, "", 0)
    }

    fun httpResponseWithOnlyRaw(raw: String?): HttpResponse? {
        if (raw == null) {
            return null
        }
        return HttpResponse(raw, "", 0, 0, 0, 0, emptyList(), emptyMap())
    }

    fun isNotSameOrigin(host: String, origin: String?): Boolean {
        if (origin == null || origin.isEmpty()) {
            return false
        }

        try {
            val urlOrigin = URL(origin)
            if (host == urlOrigin.authority) {
                return false
            }
        } catch (e: Exception) {
            return true
        }

        return true
    }
}
