package burp

data class HttpRequestResponse(val request: HttpRequest, val response: HttpResponse, var highlight: String, var comment: String,
                               val http_service: HttpService)
