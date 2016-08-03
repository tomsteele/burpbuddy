package burp

import com.github.kittinunf.fuel.Fuel
import javax.swing.JTextField
import javax.swing.JToggleButton

class FakeScannerMessage(val requestResponseTextField: JTextField, val requestResponseButton: JToggleButton,
                         val callbacks: IBurpExtenderCallbacks) : IScannerCheck {
    override fun doActiveScan(baseRequestResponse: IHttpRequestResponse?, insertionPoint: IScannerInsertionPoint?): MutableList<IScanIssue>? {
        return null
    }

    override fun consolidateDuplicateIssues(existingIssue: IScanIssue?, newIssue: IScanIssue?): Int {
        return 0
    }

    override fun doPassiveScan(baseRequestResponse: IHttpRequestResponse): MutableList<IScanIssue>? {
        if (requestResponseButton.isSelected) {
            return null
        }
        val hookURLs = requestResponseTextField.text.split(",")
        val b2b = BurpToBuddy(callbacks)
        val jsonHttpRequestResponse = b2b.httpRequestResponseToJsonObject(baseRequestResponse)
        hookURLs.forEach{
            Fuel.Companion.post(it).
                    body(jsonHttpRequestResponse.toString()).response()
        }
        return null
    }
}