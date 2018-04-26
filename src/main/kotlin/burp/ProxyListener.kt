package burp

import com.github.kittinunf.fuel.Fuel
import com.github.kittinunf.fuel.core.FuelManager
import com.github.kittinunf.fuel.core.requests.write
import com.github.kittinunf.fuel.core.requests.writeln
import com.github.salomonbrys.kotson.fromJson
import com.google.gson.Gson
import com.sun.org.apache.xpath.internal.operations.Bool
import javax.swing.JToggleButton
import javax.swing.JTextField

class ProxyListener(private val requestHookField: JTextField, private val responseHookField: JTextField,
                    private val requestHookButton: JToggleButton, private val responseHookButton: JToggleButton,
                    private val callbacks: IBurpExtenderCallbacks): IProxyListener {

    override fun processProxyMessage(messageIsRequest: Boolean, message: IInterceptedProxyMessage) {
        val requestHookURL = requestHookField.text
        val responseHookURL = responseHookField.text

        val httpRequestResponse = message.messageInfo
        val messageReference = message.messageReference
        val gson = Gson()
        FuelManager.instance.baseHeaders = mapOf("Content-Type" to "application/json")

        val b2b = BurpToBuddy(callbacks)
        if (!requestHookButton.isSelected && messageIsRequest && requestHookURL != "") {
            val jsonHttpRequestResponse = b2b.httpRequestResponseToJsonObject(httpRequestResponse)
            jsonHttpRequestResponse.addProperty("tool", "proxy")
            jsonHttpRequestResponse.addProperty("reference_id", messageReference)
            jsonHttpRequestResponse.remove("response")

            val (_, response, _) =  Fuel.post(requestHookURL).
                    body(jsonHttpRequestResponse.toString()).response()
            if (response.statusCode != 200) {
                return
            }

            val modifiedHttpRequest = gson.fromJson<HttpRequestResponse>(String(response.data))
            val originalHttpRequest = gson.fromJson<HttpRequestResponse>(jsonHttpRequestResponse.toString())

            callbacks.stdout.write(modifiedHttpRequest.request.method)
            if (requestHasChangesThatAreNotToRaw(originalHttpRequest, modifiedHttpRequest)) {
                // Build the new "headers" to fit into burp's spec.
                val methodPathVersion = "${modifiedHttpRequest.request.method} ${modifiedHttpRequest.request.path} ${modifiedHttpRequest.request.http_version}"
                val headers = mutableListOf(methodPathVersion)
                headers.addAll(modifiedHttpRequest.request.headers.map({
                    "${it.key}: ${it.value}"
                }))

               httpRequestResponse.request = callbacks.helpers.buildHttpMessage(headers,
                       callbacks.helpers.base64Decode(modifiedHttpRequest.request.body))
            } else if (originalHttpRequest.request.raw != modifiedHttpRequest.request.raw) {
                httpRequestResponse.request = callbacks.helpers.base64Decode(modifiedHttpRequest.request.raw)
            }

            if (modifiedHttpRequest.comment != "") {
                httpRequestResponse.comment = modifiedHttpRequest.comment
            }
            if (modifiedHttpRequest.highlight != "") {
                httpRequestResponse.highlight = modifiedHttpRequest.highlight
            }

        } else if (!responseHookButton.isSelected && responseHookURL != "") {
            val jsonHttpRequestResponse = b2b.httpRequestResponseToJsonObject(httpRequestResponse)
            jsonHttpRequestResponse.addProperty("reference_id", messageReference)
            jsonHttpRequestResponse.addProperty("tool", "proxy")
            jsonHttpRequestResponse.remove("request")
            val (_, response, _) =  Fuel.post(responseHookURL).body(jsonHttpRequestResponse.toString()).responseString()
            if (response.statusCode != 200) {
                return
            }
            val modifiedHttpResponse = gson.fromJson<HttpRequestResponse>(String(response.data))
            val originalHttpResponse = gson.fromJson<HttpRequestResponse>(jsonHttpRequestResponse.toString())
            if (originalHttpResponse.response != null && modifiedHttpResponse.response != null
                    && originalHttpResponse.response.raw != modifiedHttpResponse.response.raw) {
                httpRequestResponse.response = callbacks.helpers.base64Decode(modifiedHttpResponse.response.raw)
            }
            if (modifiedHttpResponse.comment != "" ) {
                httpRequestResponse.comment = modifiedHttpResponse.comment
            }
            if (modifiedHttpResponse.highlight != "") {
                httpRequestResponse.highlight = modifiedHttpResponse.highlight
            }
        }
    }

    private fun requestHasChangesThatAreNotToRaw(x: HttpRequestResponse, y: HttpRequestResponse): Boolean {
        return (x.request.method != y.request.method ||
                x.request.path != y.request.path ||
                x.request.body != y.request.body ||
                x.request.http_version != y.request.http_version)
    }
}