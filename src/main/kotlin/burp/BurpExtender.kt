package burp

import java.io.PrintWriter
import java.net.NetworkInterface
import java.awt.Component
import javax.swing.*

class BurpExtender : IBurpExtender, ITab {

    val version = "3.0.0"
    val extensionName = "BurpBuddy"

    var api: API
    var scroll : JScrollPane
    var panel : JPanel

    init {
        api = API()
        panel = JPanel()
        scroll = JScrollPane(panel, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED)
        scroll.border = BorderFactory.createEmptyBorder()
    }

    object confLabels {
        val IsAPIEnabled = "BB_IS_API_ENABLED"
        val APIAddress = "BB_API_IP"
        val APIPort = "BB_API_PORT"

        val IsProxyRequestHookEnabled = "BB_IS_PROXY_REQUEST_HOOK_ENABLED"
        val ProxyReqHookURL = "BB_PROXY_REQUEST_HOOK_URL"
        val IsProxyResponseHookEnabled = "BB_IS_PROXY_RESPONSE_HOOK_ENABLED"
        val ProxyResHookURL = "BB_PROXY_RESPONSE_HOOK_URL"

        val IsHTTPRequestHooksEnabled = "BB_IS_HTTP_REQUEST_HOOKS_ENABLED"
        val HTTPRequestHookURLs = "BB_HTTP_REQUEST_HOOKS_URLS"

        val IsHTTPResponseHooksEnabled = "BB_IS_HTTP_RESPONSE_HOOKS_ENABLED"
        val HTTPResponseHookURLs = "BB_HTTP_RESPONSE_HOOKS_URLS"

        val IsScannerHooksEnabled = "BB_IS_SCANNER_HOOKS_ENABLED"
        val ScannerHooksURLs = "BB_SCANNER_HOOKS_URLS"

        val IsHTTPRequestResponseHooksEnabled = "BB_IS_HTTP_REQUEST_RESPONSE_HOOKS_ENABLED"
        val HTTPRequestResponseHookURLs = "BB_HTTP_REQUEST_RESPONSE_HOOKS_ENABLED"
    }

    object conf {
        var IsAPIEnabled = "1"
        var APIAddress = "127.0.0.1"
        var APIPort = "8001"

        var IsProxyRequestHookEnabled = "0"
        var ProxyReqHookURL = "http://127.0.0.1:3001/request"
        var IsProxyResponseHookEnabled = "0"
        var ProxyResHookURL = "http://127.0.0.1:3001/response"

        var IsHTTPRequestHooksEnabled = "0"
        var HTTPRequestHookURLs = "http://127.0.0.1:3001/httpreq,http://127.0.0.1:3002/httpreq"

        var IsHTTPResponseHooksEnabled = "0"
        var HTTPResponseHookURLs = "http://127.0.0.1:3001/httpresp,http://127.0.0.1:3002/httpresp"

        var IsScannerHooksEnabled = "0"
        var ScannerHooksURLs = "http://127.0.0.1:3001/scan"

        var IsHTTPRequestResponseHooksEnabled = "0"
        var HTTPRequestResponseHookURLs = "http://127.0.0.1:3001/reqresp"

        fun restore(callbacks: IBurpExtenderCallbacks) {
            IsAPIEnabled = callbacks.loadExtensionSetting(confLabels.IsAPIEnabled) ?: IsAPIEnabled
            APIAddress = callbacks.loadExtensionSetting(confLabels.APIAddress) ?: APIAddress
            APIPort = callbacks.loadExtensionSetting(confLabels.APIPort) ?: APIPort

            IsProxyRequestHookEnabled = callbacks.loadExtensionSetting(confLabels.IsProxyRequestHookEnabled) ?: IsProxyRequestHookEnabled
            ProxyReqHookURL = callbacks.loadExtensionSetting(confLabels.ProxyReqHookURL) ?: ProxyReqHookURL
            IsProxyResponseHookEnabled = callbacks.loadExtensionSetting(confLabels.IsProxyResponseHookEnabled) ?: IsProxyResponseHookEnabled
            ProxyResHookURL = callbacks.loadExtensionSetting(confLabels.ProxyResHookURL) ?: ProxyResHookURL

            IsHTTPRequestHooksEnabled = callbacks.loadExtensionSetting(confLabels.IsHTTPRequestHooksEnabled) ?: IsHTTPRequestHooksEnabled
            HTTPRequestHookURLs = callbacks.loadExtensionSetting(confLabels.HTTPRequestHookURLs) ?: HTTPRequestHookURLs

            IsHTTPResponseHooksEnabled = callbacks.loadExtensionSetting(confLabels.IsHTTPResponseHooksEnabled) ?: IsHTTPResponseHooksEnabled
            HTTPResponseHookURLs = callbacks.loadExtensionSetting(confLabels.HTTPResponseHookURLs) ?: HTTPResponseHookURLs

            IsScannerHooksEnabled = callbacks.loadExtensionSetting(confLabels.IsScannerHooksEnabled) ?: IsScannerHooksEnabled
            ScannerHooksURLs = callbacks.loadExtensionSetting(confLabels.ScannerHooksURLs) ?: ScannerHooksURLs

            IsHTTPRequestResponseHooksEnabled = callbacks.loadExtensionSetting(confLabels.IsHTTPRequestResponseHooksEnabled) ?: IsHTTPRequestResponseHooksEnabled
            HTTPRequestResponseHookURLs = callbacks.loadExtensionSetting(confLabels.HTTPRequestResponseHookURLs) ?: HTTPRequestResponseHookURLs
        }

        fun save(callbacks: IBurpExtenderCallbacks) {
            callbacks.saveExtensionSetting(confLabels.IsAPIEnabled, IsAPIEnabled)
            callbacks.saveExtensionSetting(confLabels.APIAddress, APIAddress)
            callbacks.saveExtensionSetting(confLabels.APIPort, APIPort)
            callbacks.saveExtensionSetting(confLabels.IsProxyRequestHookEnabled, IsProxyRequestHookEnabled)
            callbacks.saveExtensionSetting(confLabels.ProxyReqHookURL, ProxyReqHookURL)
            callbacks.saveExtensionSetting(confLabels.IsProxyResponseHookEnabled, IsProxyResponseHookEnabled)
            callbacks.saveExtensionSetting(confLabels.ProxyResHookURL, ProxyResHookURL)
            callbacks.saveExtensionSetting(confLabels.IsHTTPRequestHooksEnabled, IsHTTPRequestHooksEnabled)
            callbacks.saveExtensionSetting(confLabels.HTTPRequestHookURLs, HTTPRequestHookURLs)
            callbacks.saveExtensionSetting(confLabels.IsHTTPResponseHooksEnabled, IsHTTPResponseHooksEnabled)
            callbacks.saveExtensionSetting(confLabels.HTTPResponseHookURLs, HTTPResponseHookURLs)
            callbacks.saveExtensionSetting(confLabels.IsScannerHooksEnabled, IsScannerHooksEnabled)
            callbacks.saveExtensionSetting(confLabels.ScannerHooksURLs, ScannerHooksURLs)
            callbacks.saveExtensionSetting(confLabels.IsHTTPRequestResponseHooksEnabled, IsHTTPRequestResponseHooksEnabled)
            callbacks.saveExtensionSetting(confLabels.HTTPRequestResponseHookURLs, HTTPRequestResponseHookURLs)
        }
    }

    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks) {
        val stdout = PrintWriter(callbacks.stdout, true)
        val stderr = PrintWriter(callbacks.stderr, true)

        callbacks.setExtensionName("$extensionName $version")

        callbacks.registerExtensionStateListener({
            api.quit()
        })

        conf.restore(callbacks)

        SwingUtilities.invokeLater {

            val apiIPLabel = JLabel("API Address")
            val apiPortLabel = JLabel("API Port")
            val proxyRequestHookLabel = JLabel("Proxy Request Hook URL")
            val proxyResponseHookLabel = JLabel("Proxy Response Hook URL")
            val httpRequestHooksLabel = JLabel("HTTP Request Hook URLs")
            val httpResponseHooksLabel = JLabel("HTTP Response Hook URLs")
            val scannerHooksLabel = JLabel("Scanner Hook URLs")
            val httpRequestResponseHooksLabel = JLabel("HTTP Request/Response Hook URLs")

            val apiIPField = JTextField(conf.APIAddress)
            val apiPortField = JTextField(conf.APIPort)
            val proxyRequestHookField = JTextField(conf.ProxyReqHookURL)
            val proxyResponseHookField = JTextField(conf.ProxyResHookURL)
            val httpRequestHooksField = JTextField(conf.HTTPRequestHookURLs)
            val httpResponseHooksField = JTextField(conf.HTTPResponseHookURLs)
            val scannerHooksField = JTextField(conf.ScannerHooksURLs)
            val httpRequestResponseHooksField = JTextField(conf.HTTPRequestResponseHookURLs)

            val isAPIEnabledButton = JToggleButton("Disabled", true)
            if (conf.IsAPIEnabled == "1") {
                isAPIEnabledButton.text = "Enabled"
                isAPIEnabledButton.isSelected = false
            }
            val isProxyRequestHookEnabledButton = JToggleButton("Disabled", true)
            if (conf.IsProxyRequestHookEnabled == "1") {
                isProxyRequestHookEnabledButton.text = "Enabled"
                isProxyRequestHookEnabledButton.isSelected = false
            }
            val isProxyResponseHookEnabledButton = JToggleButton("Disabled", true)
            if (conf.IsProxyResponseHookEnabled == "1") {
                isProxyResponseHookEnabledButton.text = "Enabled"
                isProxyResponseHookEnabledButton.isSelected = false
            }
            val isHttpRequestHooksEnabledButton = JToggleButton("Disabled", true)
            if (conf.IsHTTPRequestHooksEnabled == "1") {
                isHttpRequestHooksEnabledButton.text = "Enabled"
                isHttpRequestHooksEnabledButton.isSelected = false
            }
            val isHttpResponseHooksEnabledButton = JToggleButton("Disabled", true)
            if (conf.IsHTTPResponseHooksEnabled == "1") {
                isHttpResponseHooksEnabledButton.text = "Enabled"
                isHttpResponseHooksEnabledButton.isSelected = false
            }
            val isScannerHooksEnabledButton = JToggleButton("Disabled", true)
            if (conf.IsScannerHooksEnabled == "1") {
                isScannerHooksEnabledButton.text = "Enabled"
                isScannerHooksEnabledButton.isSelected = false
            }
            val isHttpRequestResponseHooksEnabledButton = JToggleButton("Disabled", true)
            if (conf.IsHTTPRequestResponseHooksEnabled == "1") {
                isHttpRequestResponseHooksEnabledButton.text = "Enabled"
                isHttpRequestResponseHooksEnabledButton.isSelected = false
            }
            val saveButton = JButton("Save Settings")

            saveButton.addActionListener {
                if (!isAPIEnabledButton.isSelected) {
                    conf.IsAPIEnabled = "1"
                } else {
                    conf.IsAPIEnabled = "0"
                }
                conf.APIAddress = apiIPField.text
                conf.APIPort = apiPortField.text

                if (!isProxyRequestHookEnabledButton.isSelected) {
                    conf.IsProxyRequestHookEnabled = "1"
                } else {
                    conf.IsProxyRequestHookEnabled = "0"
                }
                conf.ProxyReqHookURL = proxyRequestHookField.text

                if (!isProxyResponseHookEnabledButton.isSelected) {
                    conf.IsProxyResponseHookEnabled = "1"
                } else {
                    conf.IsProxyResponseHookEnabled = "0"
                }
                conf.ProxyResHookURL = proxyResponseHookField.text

                if (!isHttpRequestHooksEnabledButton.isSelected) {
                    conf.IsHTTPRequestHooksEnabled = "1"
                } else {
                    conf.IsHTTPRequestHooksEnabled = "0"
                }
                conf.HTTPRequestHookURLs = httpRequestHooksField.text

                if (!isHttpResponseHooksEnabledButton.isSelected) {
                    conf.IsHTTPResponseHooksEnabled = "1"
                } else {
                    conf.IsHTTPResponseHooksEnabled = "0"
                }
                conf.HTTPResponseHookURLs = httpResponseHooksField.text

                if (!isScannerHooksEnabledButton.isSelected) {
                    conf.IsScannerHooksEnabled = "1"
                } else {
                    conf.IsScannerHooksEnabled = "0"
                }
                conf.ScannerHooksURLs = scannerHooksField.text

                if (!isHttpRequestResponseHooksEnabledButton.isSelected) {
                    conf.IsHTTPRequestResponseHooksEnabled = "1"
                } else {
                    conf.IsHTTPRequestResponseHooksEnabled = "0"
                }
                conf.HTTPRequestResponseHookURLs = httpRequestResponseHooksField.text

                conf.save(callbacks)
            }

            isAPIEnabledButton.addActionListener {
                if (!isAPIEnabledButton.isSelected) {
                    val address = apiIPField.text
                    val port = apiPortField.text

                    if (!isIPValid(address)) {
                        stderr.println("$address is not a valid IP address for this system")
                    } else if (port.toInt() > 65535 || port.toInt() < 1) {
                        stderr.println("$port is not a valid TCP port")
                    } else {
                        api.start(address, port.toInt(), callbacks, stdout)
                        stdout.println("HTTP Server started on ${conf.APIAddress}:${conf.APIPort}")
                        isAPIEnabledButton.text = "Enabled"
                    }
                } else {
                    isAPIEnabledButton.text = "Disabled"
                    api.quit()
                }
            }

            isProxyRequestHookEnabledButton.addActionListener {
                if(!isProxyRequestHookEnabledButton.isSelected) {
                    isProxyRequestHookEnabledButton.text = "Enabled"
                } else {
                    isProxyRequestHookEnabledButton.text = "Disabled"
                }
            }
            isProxyResponseHookEnabledButton.addActionListener {
                if(!isProxyResponseHookEnabledButton.isSelected) {
                    isProxyResponseHookEnabledButton.text = "Enabled"
                } else {
                    isProxyResponseHookEnabledButton.text = "Disabled"
                }
            }
            isHttpRequestHooksEnabledButton.addActionListener {
                if(!isHttpRequestHooksEnabledButton.isSelected) {
                    isHttpRequestHooksEnabledButton.text = "Enabled"
                } else {
                    isHttpRequestHooksEnabledButton.text = "Disabled"
                }
            }
            isHttpResponseHooksEnabledButton.addActionListener {
                if(!isHttpResponseHooksEnabledButton.isSelected) {
                    isHttpResponseHooksEnabledButton.text = "Enabled"
                } else {
                    isHttpResponseHooksEnabledButton.text = "Disabled"
                }
            }
            isScannerHooksEnabledButton.addActionListener {
                if(!isScannerHooksEnabledButton.isSelected) {
                    isScannerHooksEnabledButton.text = "Enabled"
                } else {
                    isScannerHooksEnabledButton.text = "Disabled"
                }
            }
            isHttpRequestResponseHooksEnabledButton.addActionListener {
                if(!isHttpRequestResponseHooksEnabledButton.isSelected) {
                    isHttpRequestResponseHooksEnabledButton.text = "Enabled"
                } else {
                    isHttpRequestResponseHooksEnabledButton.text = "Disabled"
                }
            }


            callbacks.registerProxyListener(ProxyListener(proxyRequestHookField, proxyResponseHookField,
                    isProxyRequestHookEnabledButton, isProxyResponseHookEnabledButton, callbacks))
            callbacks.registerHttpListener(HttpListener(httpRequestHooksField, httpResponseHooksField,
                    isHttpRequestHooksEnabledButton, isHttpResponseHooksEnabledButton, callbacks))
            callbacks.registerScannerListener(ScannerListener(scannerHooksField, isScannerHooksEnabledButton, callbacks))
            callbacks.registerScannerCheck(FakeScannerMessage(httpRequestResponseHooksField, isHttpResponseHooksEnabledButton, callbacks))

            if (conf.IsAPIEnabled == "1") {
                if (!isIPValid(conf.APIAddress)) {
                    stderr.println("${conf.APIAddress} is not a valid IP address for this system")
                } else if (conf.APIPort.toInt() > 65535 || conf.APIPort.toInt() < 1) {
                    stderr.println("${conf.APIPort} is not a valid TCP port")
                } else {
                    api.start(conf.APIAddress, conf.APIPort.toInt(), callbacks, stdout)
                    stdout.println("HTTP Server started on ${conf.APIAddress}:${conf.APIPort}")
                }
            }


            // Layout all the things.
            val layout = GroupLayout(panel)
            panel.layout = layout
            layout.autoCreateGaps = true
            layout.autoCreateContainerGaps = true

            val hGroup = layout.createSequentialGroup()
            hGroup.addGroup(layout.createParallelGroup().addComponent(apiIPLabel).addComponent(apiPortLabel)
                    .addComponent(proxyRequestHookLabel).addComponent(proxyResponseHookLabel).addComponent(httpRequestHooksLabel)
                    .addComponent(httpResponseHooksLabel).addComponent(scannerHooksLabel).addComponent(httpRequestResponseHooksLabel)
                    .addComponent(saveButton))

            hGroup.addGroup(layout.createParallelGroup().addComponent(apiIPField).addComponent(apiPortField)
                    .addComponent(proxyRequestHookField).addComponent(proxyResponseHookField).addComponent(httpRequestHooksField)
                    .addComponent(httpResponseHooksField).addComponent(scannerHooksField).addComponent(httpRequestResponseHooksField))

            hGroup.addGroup(layout.createParallelGroup().addComponent(isAPIEnabledButton).addComponent(isProxyRequestHookEnabledButton)
                    .addComponent(isProxyResponseHookEnabledButton).addComponent(isHttpRequestHooksEnabledButton)
                    .addComponent(isHttpResponseHooksEnabledButton).addComponent(isScannerHooksEnabledButton)
                    .addComponent(isHttpRequestResponseHooksEnabledButton))

            layout.setHorizontalGroup(hGroup)

            val vGroup = layout.createSequentialGroup()
            vGroup.addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE).addComponent(apiIPLabel)
                    .addComponent(apiIPField))
            vGroup.addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE).addComponent(apiPortLabel)
                    .addComponent(apiPortField).addComponent(isAPIEnabledButton))
            vGroup.addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE).addComponent(proxyRequestHookLabel)
                    .addComponent(proxyRequestHookField).addComponent(isProxyRequestHookEnabledButton))
            vGroup.addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE).addComponent(proxyResponseHookLabel)
                  .addComponent(proxyResponseHookField).addComponent(isProxyResponseHookEnabledButton))
            vGroup.addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE).addComponent(httpRequestHooksLabel)
                    .addComponent(httpRequestHooksField).addComponent(isHttpRequestHooksEnabledButton))
            vGroup.addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE).addComponent(httpResponseHooksLabel)
                    .addComponent(httpResponseHooksField).addComponent(isHttpResponseHooksEnabledButton))
            vGroup.addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE).addComponent(scannerHooksLabel)
                    .addComponent(scannerHooksField).addComponent(isScannerHooksEnabledButton))
            vGroup.addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE).addComponent(httpRequestResponseHooksLabel)
                    .addComponent(httpRequestResponseHooksField).addComponent(isHttpRequestResponseHooksEnabledButton))

            vGroup.addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE).addComponent(saveButton))

            layout.setVerticalGroup(vGroup)

            callbacks.customizeUiComponent(scroll)
            // Add the custom tab to Burp's UI.
            callbacks.addSuiteTab(this@BurpExtender)
        }

    }

    override fun getTabCaption(): String {
        return "BurpBuddy"
    }

    override fun getUiComponent(): Component {
        return scroll
    }

    fun isIPValid(ip: String): Boolean {
        val networks = NetworkInterface.getNetworkInterfaces()
        for (netint in networks) {
            for (inetAddresses in netint.inetAddresses) {
                for (inetAddress in listOf(inetAddresses)) {
                    val inetstr = inetAddress.toString()
                    if (inetstr.indexOf(ip) != -1) {
                        return true
                    }
                }
            }
        }
        return false
    }
}