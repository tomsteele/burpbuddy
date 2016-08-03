package burp

import java.util.Date

class BCookie(val cookie: Cookie): ICookie {
    override fun getDomain(): String {
        return cookie.domain
    }

    override fun getExpiration(): Date {
        return cookie.expiration
    }

    override fun getName(): String {
        return cookie.name
    }

    override fun getPath(): String {
        return cookie.path
    }

    override fun getValue(): String {
        return cookie.value
    }
}