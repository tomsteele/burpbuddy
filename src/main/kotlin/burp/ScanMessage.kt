package burp

data class ScanMessage(val host: String, val port: Int, val use_https: Boolean, val request: String, val response: String)