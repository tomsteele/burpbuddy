package burp

import com.github.salomonbrys.kotson.jsonArray
import com.github.salomonbrys.kotson.jsonObject
import com.google.gson.JsonArray
import com.google.gson.JsonObject

class BurpToBuddy(val callbacks: IBurpExtenderCallbacks) {
    fun httpMessagesToJsonArray(httpMessages: Array<IHttpRequestResponse>) : JsonArray {
        val messages = jsonArray()
        for (message in httpMessages) {
            messages.add(httpRequestResponseToJsonObject(message))
        }
        return messages
    }

    fun httpRequestToJsonObject(request: ByteArray) : JsonObject {
        val reqInfo = callbacks.helpers.analyzeRequest(request)
        val allHeaders = reqInfo.headers
        val headers = allHeaders.subList(1, allHeaders.size)
        val headersJson = jsonObject()
        for (header in headers) {
            val values = header.split(":".toRegex(), 2).toTypedArray()
            if (values.size == 2) {
                headersJson.addProperty(values[0].trim({ it <= ' ' }), values[1].trim({ it <= ' ' }))
            }
        }

        val firstHeader = allHeaders[0].split(" ")
        var httpVersion = "0"
        var path = ""
        if (firstHeader.size == 3) {
            httpVersion = firstHeader[2].trim({ it <= ' ' })
            path = firstHeader[1].trim({ it <= ' ' })
        }

        return jsonObject(
                "method" to reqInfo.method,
                "path" to path,
                "http_version" to httpVersion,
                "headers" to headersJson,
                "raw" to callbacks.helpers.base64Encode(request),
                "size" to request.size,
                "body" to callbacks.helpers.base64Encode(java.util.Arrays.copyOfRange(request, reqInfo.bodyOffset, request.size)),
                "body_offset" to reqInfo.bodyOffset
        )
    }

    fun cookiesToJsonArray(icookies: List<ICookie>) : JsonArray {
        val cookies = jsonArray()
        for (cookie in icookies) {
            cookies.add(jsonObject(
                    "domain" to cookie.domain,
                    "expiration" to cookie.expiration,
                    "path" to cookie.path,
                    "name" to cookie.name,
                    "value" to cookie.value
            ))
        }
        return cookies
    }

    fun httpResponseToJsonObject(response: ByteArray) : JsonObject {
        val respInfo = callbacks.helpers.analyzeResponse(response)
        val allHeaders = respInfo.headers
        val headers = allHeaders.subList(1, allHeaders.size)
        val headersJson = jsonObject()
        for (header in headers) {
            val values = header.split(":".toRegex(), 2).toTypedArray()
            if (values.size == 2) {
                headersJson.addProperty(values[0].trim({ it <= ' ' }), values[1].trim({ it <= ' ' }))
            }
        }
        return jsonObject(
                "raw" to callbacks.helpers.base64Encode(response),
                "body" to callbacks.helpers.base64Encode(java.util.Arrays.copyOfRange(response,
                        respInfo.bodyOffset, response.size)),
                "body_offset" to respInfo.bodyOffset,
                "mime_type" to respInfo.statedMimeType,
                "size" to response.size,
                "status_code" to respInfo.statusCode,
                "cookies" to cookiesToJsonArray(respInfo.cookies),
                "headers" to headersJson
        )
    }

    fun httpRequestResponseToJsonObject(httpMessage: IHttpRequestResponse) : JsonObject {
        var request = jsonObject()
        var response = jsonObject()
        if (httpMessage.request != null && httpMessage.request.size > 0) {
            request = httpRequestToJsonObject(httpMessage.request)
        }
        if (httpMessage.response != null && httpMessage.response.size > 0) {
            response = httpResponseToJsonObject(httpMessage.response)
        }
        return jsonObject(
                "http_service" to jsonObject(
                        "host" to httpMessage.httpService.host,
                        "port" to httpMessage.httpService.port,
                        "protocol" to httpMessage.httpService.protocol
                ),
                "request" to request,
                "highlight" to httpMessage.highlight,
                "comment" to httpMessage.comment,
                "response" to response
        )
    }


    fun scanIssuesToJsonArray(scanIssues: Array<IScanIssue>) : JsonArray {
        val issues = jsonArray()
        for (scanIssue in scanIssues) {
            issues.add(scanIssueToJsonObject(scanIssue))
        }
        return issues
    }

    fun scanIssueToJsonObject(scanIssue: IScanIssue) : JsonObject {
        val service = scanIssue.httpService

        return jsonObject(
                "url" to scanIssue.url.toString(),
                "host" to service.host,
                "port" to service.port,
                "protocol" to service.protocol,
                "name" to scanIssue.issueName,
                "type" to scanIssue.issueType,
                "severity" to scanIssue.severity,
                "confidence" to scanIssue.confidence,
                "issue_background" to scanIssue.issueBackground,
                "issue_detail" to scanIssue.issueDetail,
                "remediation_background" to scanIssue.remediationBackground,
                "remediation_detail" to scanIssue.remediationDetail,
                "http_messages" to httpMessagesToJsonArray(scanIssue.httpMessages)
        )
    }

    fun apiError(param: String, error: String) : JsonObject {
        return jsonObject(
                "parameter" to param,
                "error" to error
        )
    }
}