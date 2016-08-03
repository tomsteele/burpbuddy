package burp

import com.github.kittinunf.fuel.Fuel
import javax.swing.JTextField
import javax.swing.JToggleButton

class ScannerListener(val scannerHookJTextField: JTextField, val scannerHookButton:JToggleButton,
                      val callbacks: IBurpExtenderCallbacks): IScannerListener {

    override fun newScanIssue(issue: IScanIssue) {
        val hookURLs = scannerHookJTextField.text.split(",")
        val b2b = BurpToBuddy(callbacks)
        val issueObj = b2b.scanIssueToJsonObject(issue)
        if (scannerHookButton.isSelected) {
            return
        }
        hookURLs.forEach{
            Fuel.Companion.post(it).
                    body(issueObj.toString()).response()
        }
    }
}