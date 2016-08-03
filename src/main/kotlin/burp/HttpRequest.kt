package burp

data class HttpRequest(val method: String, val path: String, val http_version: String, val headers: Map<String, String>,
                       var raw: String, val size: Int, val body: String, val body_offset: Int)