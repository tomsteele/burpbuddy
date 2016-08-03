package burp

import com.github.kittinunf.fuel.Fuel
import javax.swing.JTextField
import javax.swing.JToggleButton

class HttpListener(val requestHooksTextField: JTextField, val responseHooksTextField: JTextField,
                   val requestHooksButton: JToggleButton, val responseHooksButton: JToggleButton,
                   val callbacks: IBurpExtenderCallbacks): IHttpListener {

    override fun processHttpMessage(toolFlag: Int, messageIsRequest: Boolean, messageInfo: IHttpRequestResponse) {
        val b2b = BurpToBuddy(callbacks)
        val httpRequestResponse = messageInfo
        val reqHookURLs = requestHooksTextField.text.split(",")
        val resHookURLs = responseHooksTextField.text.split(",")

        if (!requestHooksButton.isSelected && messageIsRequest && reqHookURLs.size > 0) {
            val jsonHttpRequestResponse = b2b.httpRequestResponseToJsonObject(httpRequestResponse)
            jsonHttpRequestResponse.addProperty("tool", toolFlag)
            jsonHttpRequestResponse.remove("response")

            reqHookURLs.forEach{
                Fuel.Companion.post(it).
                body(jsonHttpRequestResponse.toString()).response()
            }

        } else if (!responseHooksButton.isSelected && resHookURLs.size > 0) {
            val jsonHttpRequestResponse = b2b.httpRequestResponseToJsonObject(httpRequestResponse)
            jsonHttpRequestResponse.addProperty("tool", toolFlag)
            jsonHttpRequestResponse.remove("request")
            resHookURLs.forEach{
                Fuel.Companion.post(it).
                        body(jsonHttpRequestResponse.toString()).response()
            }
        }
    }
}