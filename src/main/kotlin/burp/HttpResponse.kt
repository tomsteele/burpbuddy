package burp

data class HttpResponse(var raw: String, val body: String, val body_offset: Int, val mime_type: Int, val size: Int,
                        val status_code: Int, val cookies: List<Cookie>, val headers: Map<String, String>)