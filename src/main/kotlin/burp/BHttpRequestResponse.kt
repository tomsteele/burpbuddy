package burp

import java.util.Base64

class BHttpRequestResponse(val httpMessage: HttpRequestResponse, val service: HttpService): IHttpRequestResponse {
    override fun setComment(comment: String) {
        httpMessage.comment = comment
    }

    override fun getComment(): String {
        return httpMessage.comment
    }

    override fun setRequest(rawRequest: ByteArray) {
        // TODO: I'm not sure if i should set all the other variables for a request.
        httpMessage.request.raw = Base64.getEncoder().encodeToString(rawRequest)
    }

    override fun getHttpService(): IHttpService {
        return BHttpService(service)
    }

    override fun getHighlight(): String {
        return highlight
    }

    override fun getResponse(): ByteArray {
        return Base64.getDecoder().decode(httpMessage.response.raw)
    }

    override fun setHighlight(color: String) {
        httpMessage.highlight = color
    }

    override fun setHttpService(httpService: IHttpService) {
        service.protocol = httpService.protocol
        service.port = httpService.port
        service.host = httpService.host
    }

    override fun setResponse(rawResponse: ByteArray) {
        httpMessage.response.raw = Base64.getEncoder().encodeToString(rawResponse)
    }

    override fun getRequest(): ByteArray {
        return Base64.getDecoder().decode(httpMessage.request.raw)
    }
}