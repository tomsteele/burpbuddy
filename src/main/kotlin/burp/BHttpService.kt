package burp

class BHttpService(val service: HttpService): IHttpService {

    override fun getHost(): String {
        return service.host
    }

    override fun getPort(): Int {
        return service.port
    }

    override fun getProtocol(): String {
        return service.protocol
    }
}