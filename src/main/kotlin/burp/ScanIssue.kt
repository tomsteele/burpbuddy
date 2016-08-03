package burp

data class ScanIssue(val url: String, val host: String, val port: Int, val protocol: String, val name: String, val severity: String,
                val confidence: String, val issue_background: String, val issue_detail: String,
                val remediation_background: String, val remediation_detail: String, val http_messages: List<HttpRequestResponse>)