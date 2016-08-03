package burp

data class SiteMapMessage(val host: String, val port: Int, val protocol: String, val request: String, val response: String,
                          val highlight: String, val comment: String)