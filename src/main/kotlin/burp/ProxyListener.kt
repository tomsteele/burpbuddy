package burp

import com.github.kittinunf.fuel.Fuel
import com.github.kittinunf.fuel.core.FuelManager
import com.github.salomonbrys.kotson.fromJson
import com.google.gson.Gson
import javax.swing.JToggleButton
import javax.swing.JTextField

class ProxyListener(val requestHookField: JTextField, val responseHookField: JTextField,
                    val requestHookButton: JToggleButton, val responseHookButton: JToggleButton,
                    val callbacks: IBurpExtenderCallbacks): IProxyListener {

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

            val (request, response, result) =  Fuel.post(requestHookURL).
                    body(jsonHttpRequestResponse.toString()).response()
            if (response.httpStatusCode != 200) {
                return
            }

            val modifiedHttpRequest = gson.fromJson<HttpRequestResponse>(String(response.data))
            val originalHttpRequest = gson.fromJson<HttpRequestResponse>(jsonHttpRequestResponse.toString())

            if (!originalHttpRequest.request.headers.equals(modifiedHttpRequest.request.headers) || !originalHttpRequest.request.body.equals(modifiedHttpRequest.request.body)) {
                httpRequestResponse.request = callbacks.helpers.buildHttpMessage(modifiedHttpRequest.request.headers.map{
                    "${it.key}: ${it.value}"
                }, callbacks.helpers.base64Decode(modifiedHttpRequest.request.body))
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
            val (request, response, result) =  Fuel.post(responseHookURL).body(jsonHttpRequestResponse.toString()).responseString()
            if (response.httpStatusCode != 200) {
                return
            }
            val modifiedHttpResponse = gson.fromJson<HttpRequestResponse>(String(response.data))
            val originalHttpResponse = gson.fromJson<HttpRequestResponse>(jsonHttpRequestResponse.toString())
            if (!originalHttpResponse.response.raw.equals(modifiedHttpResponse.response.raw)) {
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
}