package burp

import java.util.Date

data class Cookie(val domain: String, val expiration: Date, val path: String, val name: String, val value: String)