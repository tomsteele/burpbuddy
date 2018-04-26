package burp

import com.github.kittinunf.fuel.Fuel
import javax.swing.JTextField
import javax.swing.JToggleButton

class HttpListener(private val requestHooksTextField: JTextField, private val responseHooksTextField: JTextField,
                   private val requestHooksButton: JToggleButton, private val responseHooksButton: JToggleButton,
                   private val callbacks: IBurpExtenderCallbacks): IHttpListener {

    override fun processHttpMessage(toolFlag: Int, messageIsRequest: Boolean, messageInfo: IHttpRequestResponse) {
        val b2b = BurpToBuddy(callbacks)
        val reqHookURLs = requestHooksTextField.text.split(",")
        val resHookURLs = responseHooksTextField.text.split(",")

        if (!requestHooksButton.isSelected && messageIsRequest && reqHookURLs.isNotEmpty()) {
            val jsonHttpRequestResponse = b2b.httpRequestResponseToJsonObject(messageInfo)
            jsonHttpRequestResponse.addProperty("tool", toolFlag)
            jsonHttpRequestResponse.remove("response")

            reqHookURLs.forEach{
                Fuel.post(it).
                body(jsonHttpRequestResponse.toString()).response()
            }

        } else if (!responseHooksButton.isSelected && resHookURLs.isNotEmpty()) {
            val jsonHttpRequestResponse = b2b.httpRequestResponseToJsonObject(messageInfo)
            jsonHttpRequestResponse.addProperty("tool", toolFlag)
            jsonHttpRequestResponse.remove("request")
            resHookURLs.forEach{
                Fuel.post(it).
                        body(jsonHttpRequestResponse.toString()).response()
            }
        }
    }
}