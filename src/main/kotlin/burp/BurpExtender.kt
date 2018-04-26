package burp

import java.io.PrintWriter
import java.net.NetworkInterface
import java.awt.Component
import javax.swing.*

class BurpExtender : IBurpExtender, ITab {

    private val version = "3.0.0"
    private val extensionName = "BurpBuddy"

    private var api: API = API()
    private var scroll : JScrollPane
    private var panel : JPanel = JPanel()

    init {
        scroll = JScrollPane(panel, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED)
        scroll.border = BorderFactory.createEmptyBorder()
    }

    object ConfLabels {
        const val IsAPIEnabled = "BB_IS_API_ENABLED"
        const val APIAddress = "BB_API_IP"
        const val APIPort = "BB_API_PORT"

        const val IsProxyRequestHookEnabled = "BB_IS_PROXY_REQUEST_HOOK_ENABLED"
        const val ProxyReqHookURL = "BB_PROXY_REQUEST_HOOK_URL"
        const val IsProxyResponseHookEnabled = "BB_IS_PROXY_RESPONSE_HOOK_ENABLED"
        const val ProxyResHookURL = "BB_PROXY_RESPONSE_HOOK_URL"

        const val IsHTTPRequestHooksEnabled = "BB_IS_HTTP_REQUEST_HOOKS_ENABLED"
        const val HTTPRequestHookURLs = "BB_HTTP_REQUEST_HOOKS_URLS"

        const val IsHTTPResponseHooksEnabled = "BB_IS_HTTP_RESPONSE_HOOKS_ENABLED"
        const val HTTPResponseHookURLs = "BB_HTTP_RESPONSE_HOOKS_URLS"

        const val IsScannerHooksEnabled = "BB_IS_SCANNER_HOOKS_ENABLED"
        const val ScannerHooksURLs = "BB_SCANNER_HOOKS_URLS"

        const val IsHTTPRequestResponseHooksEnabled = "BB_IS_HTTP_REQUEST_RESPONSE_HOOKS_ENABLED"
        const val HTTPRequestResponseHookURLs = "BB_HTTP_REQUEST_RESPONSE_HOOKS_ENABLED"
    }

    object Conf {
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
            IsAPIEnabled = callbacks.loadExtensionSetting(ConfLabels.IsAPIEnabled) ?: IsAPIEnabled
            APIAddress = callbacks.loadExtensionSetting(ConfLabels.APIAddress) ?: APIAddress
            APIPort = callbacks.loadExtensionSetting(ConfLabels.APIPort) ?: APIPort

            IsProxyRequestHookEnabled = callbacks.loadExtensionSetting(ConfLabels.IsProxyRequestHookEnabled) ?: IsProxyRequestHookEnabled
            ProxyReqHookURL = callbacks.loadExtensionSetting(ConfLabels.ProxyReqHookURL) ?: ProxyReqHookURL
            IsProxyResponseHookEnabled = callbacks.loadExtensionSetting(ConfLabels.IsProxyResponseHookEnabled) ?: IsProxyResponseHookEnabled
            ProxyResHookURL = callbacks.loadExtensionSetting(ConfLabels.ProxyResHookURL) ?: ProxyResHookURL

            IsHTTPRequestHooksEnabled = callbacks.loadExtensionSetting(ConfLabels.IsHTTPRequestHooksEnabled) ?: IsHTTPRequestHooksEnabled
            HTTPRequestHookURLs = callbacks.loadExtensionSetting(ConfLabels.HTTPRequestHookURLs) ?: HTTPRequestHookURLs

            IsHTTPResponseHooksEnabled = callbacks.loadExtensionSetting(ConfLabels.IsHTTPResponseHooksEnabled) ?: IsHTTPResponseHooksEnabled
            HTTPResponseHookURLs = callbacks.loadExtensionSetting(ConfLabels.HTTPResponseHookURLs) ?: HTTPResponseHookURLs

            IsScannerHooksEnabled = callbacks.loadExtensionSetting(ConfLabels.IsScannerHooksEnabled) ?: IsScannerHooksEnabled
            ScannerHooksURLs = callbacks.loadExtensionSetting(ConfLabels.ScannerHooksURLs) ?: ScannerHooksURLs

            IsHTTPRequestResponseHooksEnabled = callbacks.loadExtensionSetting(ConfLabels.IsHTTPRequestResponseHooksEnabled) ?: IsHTTPRequestResponseHooksEnabled
            HTTPRequestResponseHookURLs = callbacks.loadExtensionSetting(ConfLabels.HTTPRequestResponseHookURLs) ?: HTTPRequestResponseHookURLs
        }

        fun save(callbacks: IBurpExtenderCallbacks) {
            callbacks.saveExtensionSetting(ConfLabels.IsAPIEnabled, IsAPIEnabled)
            callbacks.saveExtensionSetting(ConfLabels.APIAddress, APIAddress)
            callbacks.saveExtensionSetting(ConfLabels.APIPort, APIPort)
            callbacks.saveExtensionSetting(ConfLabels.IsProxyRequestHookEnabled, IsProxyRequestHookEnabled)
            callbacks.saveExtensionSetting(ConfLabels.ProxyReqHookURL, ProxyReqHookURL)
            callbacks.saveExtensionSetting(ConfLabels.IsProxyResponseHookEnabled, IsProxyResponseHookEnabled)
            callbacks.saveExtensionSetting(ConfLabels.ProxyResHookURL, ProxyResHookURL)
            callbacks.saveExtensionSetting(ConfLabels.IsHTTPRequestHooksEnabled, IsHTTPRequestHooksEnabled)
            callbacks.saveExtensionSetting(ConfLabels.HTTPRequestHookURLs, HTTPRequestHookURLs)
            callbacks.saveExtensionSetting(ConfLabels.IsHTTPResponseHooksEnabled, IsHTTPResponseHooksEnabled)
            callbacks.saveExtensionSetting(ConfLabels.HTTPResponseHookURLs, HTTPResponseHookURLs)
            callbacks.saveExtensionSetting(ConfLabels.IsScannerHooksEnabled, IsScannerHooksEnabled)
            callbacks.saveExtensionSetting(ConfLabels.ScannerHooksURLs, ScannerHooksURLs)
            callbacks.saveExtensionSetting(ConfLabels.IsHTTPRequestResponseHooksEnabled, IsHTTPRequestResponseHooksEnabled)
            callbacks.saveExtensionSetting(ConfLabels.HTTPRequestResponseHookURLs, HTTPRequestResponseHookURLs)
        }
    }

    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks) {
        val stdout = PrintWriter(callbacks.stdout, true)
        val stderr = PrintWriter(callbacks.stderr, true)

        callbacks.setExtensionName("$extensionName $version")

        callbacks.registerExtensionStateListener({
            api.quit()
        })

        Conf.restore(callbacks)

        SwingUtilities.invokeLater {

            val apiIPLabel = JLabel("API Address")
            val apiPortLabel = JLabel("API Port")
            val proxyRequestHookLabel = JLabel("Proxy Request Hook URL")
            val proxyResponseHookLabel = JLabel("Proxy Response Hook URL")
            val httpRequestHooksLabel = JLabel("HTTP Request Hook URLs")
            val httpResponseHooksLabel = JLabel("HTTP Response Hook URLs")
            val scannerHooksLabel = JLabel("Scanner Hook URLs")
            val httpRequestResponseHooksLabel = JLabel("HTTP Request/Response Hook URLs")

            val apiIPField = JTextField(Conf.APIAddress)
            val apiPortField = JTextField(Conf.APIPort)
            val proxyRequestHookField = JTextField(Conf.ProxyReqHookURL)
            val proxyResponseHookField = JTextField(Conf.ProxyResHookURL)
            val httpRequestHooksField = JTextField(Conf.HTTPRequestHookURLs)
            val httpResponseHooksField = JTextField(Conf.HTTPResponseHookURLs)
            val scannerHooksField = JTextField(Conf.ScannerHooksURLs)
            val httpRequestResponseHooksField = JTextField(Conf.HTTPRequestResponseHookURLs)

            val isAPIEnabledButton = JToggleButton("Disabled", true)
            if (Conf.IsAPIEnabled == "1") {
                isAPIEnabledButton.text = "Enabled"
                isAPIEnabledButton.isSelected = false
            }
            val isProxyRequestHookEnabledButton = JToggleButton("Disabled", true)
            if (Conf.IsProxyRequestHookEnabled == "1") {
                isProxyRequestHookEnabledButton.text = "Enabled"
                isProxyRequestHookEnabledButton.isSelected = false
            }
            val isProxyResponseHookEnabledButton = JToggleButton("Disabled", true)
            if (Conf.IsProxyResponseHookEnabled == "1") {
                isProxyResponseHookEnabledButton.text = "Enabled"
                isProxyResponseHookEnabledButton.isSelected = false
            }
            val isHttpRequestHooksEnabledButton = JToggleButton("Disabled", true)
            if (Conf.IsHTTPRequestHooksEnabled == "1") {
                isHttpRequestHooksEnabledButton.text = "Enabled"
                isHttpRequestHooksEnabledButton.isSelected = false
            }
            val isHttpResponseHooksEnabledButton = JToggleButton("Disabled", true)
            if (Conf.IsHTTPResponseHooksEnabled == "1") {
                isHttpResponseHooksEnabledButton.text = "Enabled"
                isHttpResponseHooksEnabledButton.isSelected = false
            }
            val isScannerHooksEnabledButton = JToggleButton("Disabled", true)
            if (Conf.IsScannerHooksEnabled == "1") {
                isScannerHooksEnabledButton.text = "Enabled"
                isScannerHooksEnabledButton.isSelected = false
            }
            val isHttpRequestResponseHooksEnabledButton = JToggleButton("Disabled", true)
            if (Conf.IsHTTPRequestResponseHooksEnabled == "1") {
                isHttpRequestResponseHooksEnabledButton.text = "Enabled"
                isHttpRequestResponseHooksEnabledButton.isSelected = false
            }
            val saveButton = JButton("Save Settings")

            saveButton.addActionListener {
                if (!isAPIEnabledButton.isSelected) {
                    Conf.IsAPIEnabled = "1"
                } else {
                    Conf.IsAPIEnabled = "0"
                }
                Conf.APIAddress = apiIPField.text
                Conf.APIPort = apiPortField.text

                if (!isProxyRequestHookEnabledButton.isSelected) {
                    Conf.IsProxyRequestHookEnabled = "1"
                } else {
                    Conf.IsProxyRequestHookEnabled = "0"
                }
                Conf.ProxyReqHookURL = proxyRequestHookField.text

                if (!isProxyResponseHookEnabledButton.isSelected) {
                    Conf.IsProxyResponseHookEnabled = "1"
                } else {
                    Conf.IsProxyResponseHookEnabled = "0"
                }
                Conf.ProxyResHookURL = proxyResponseHookField.text

                if (!isHttpRequestHooksEnabledButton.isSelected) {
                    Conf.IsHTTPRequestHooksEnabled = "1"
                } else {
                    Conf.IsHTTPRequestHooksEnabled = "0"
                }
                Conf.HTTPRequestHookURLs = httpRequestHooksField.text

                if (!isHttpResponseHooksEnabledButton.isSelected) {
                    Conf.IsHTTPResponseHooksEnabled = "1"
                } else {
                    Conf.IsHTTPResponseHooksEnabled = "0"
                }
                Conf.HTTPResponseHookURLs = httpResponseHooksField.text

                if (!isScannerHooksEnabledButton.isSelected) {
                    Conf.IsScannerHooksEnabled = "1"
                } else {
                    Conf.IsScannerHooksEnabled = "0"
                }
                Conf.ScannerHooksURLs = scannerHooksField.text

                if (!isHttpRequestResponseHooksEnabledButton.isSelected) {
                    Conf.IsHTTPRequestResponseHooksEnabled = "1"
                } else {
                    Conf.IsHTTPRequestResponseHooksEnabled = "0"
                }
                Conf.HTTPRequestResponseHookURLs = httpRequestResponseHooksField.text

                Conf.save(callbacks)
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
                        api.start(address, port.toInt(), callbacks)
                        stdout.println("HTTP Server started on ${Conf.APIAddress}:${Conf.APIPort}")
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

            if (Conf.IsAPIEnabled == "1") {
                if (!isIPValid(Conf.APIAddress)) {
                    stderr.println("${Conf.APIAddress} is not a valid IP address for this system")
                } else if (Conf.APIPort.toInt() > 65535 || Conf.APIPort.toInt() < 1) {
                    stderr.println("${Conf.APIPort} is not a valid TCP port")
                } else {
                    api.start(Conf.APIAddress, Conf.APIPort.toInt(), callbacks)
                    stdout.println("HTTP Server started on ${Conf.APIAddress}:${Conf.APIPort}")
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

    private fun isIPValid(ip: String): Boolean {
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