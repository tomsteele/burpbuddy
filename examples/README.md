# Web Socket Server

## Payload Examples

### scanIssue

```
{
    "url": "https://avatars3.githubusercontent.com:443/u/370244",
    "host": "avatars3.githubusercontent.com",
    "port": 443,
    "protocol": "https",
    "name": "HTML5 cross-origin resource sharing",
    "issueType": 2098688,
    "severity": "Medium",
    "confidence": "Certain",
    "issueBackground": "The HTML5 cross-origin resource sharing policy controls whether and how content running on other domains can perform two-way interaction with the domain which publishes the policy. The policy is fine-grained and can apply access controls per-request based on the URL and other features of the request.<br><br>If another domain is allowed by the policy, then that domain can potentially attack users of the application. If a user is logged in to the application, and visits a domain allowed by the policy, then any malicious content running on that domain can potentially retrieve content from the application, and sometimes carry out actions within the security context of the logged in user.<br><br>Even if an allowed domain is not overtly malicious in itself, security vulnerabilities within that domain could potentially be leveraged by a third-party attacker to exploit the trust relationship and attack the application which allows access.",
    "remediationBackground": "You should review the domains which are allowed by the CORS policy in relation to any sensitive content within the application, and determine whether it is appropriate for the application to trust both the intentions and security posture of those domains.",
    "issueDetail": "The application implements an HTML5 cross-origin resource sharing (CORS) policy for this request which allows access from any domain.<br><br>Allowing access from all domains means that any domain can perform two-way interaction with the application via this request. Unless the response consists only of unprotected public content, this policy is likely to present a security risk.<br><br><b>Note:</b> The application does not issue an Access-Control-Allow-Credentials header allowing two-way in-session interaction. Without this header in the response, although client code can initiate cross-domain with-cookies requests to the target, the code will not be able to read responses from with-cookies requests. This constraint mitigates the impact of this behavior in relation to cross-domain retrieval of sensitive in-session data.",
    "inScope": true,
    "messageType": "scanIssue"
}
```

### request

```
{
    "host": "s.imgur.com",
    "port": 443,
    "protocol": "https",
    "url": "https://s.imgur.com:443/include/css/elements/signin-dropdown.css?12",
    "path": "/include/css/elements/signin-dropdown.css",
    "httpVersion": "HTTP/1.1",
    "method": "GET",
    "headers": {
        "Accept-Language": "en-US,en;q=0.5",
        "Cookie": "__cfduid=d7fb1a18ae2xx6x1xd90x77xb8dc5x17d13x27181xxx02; __qca=x0-x9xxxx374-13xxxxxxx0661; __qseg=Q_xxx_TxQ_3xxx3xxxxxx8x|x_x7xx7xxxx3x67xQ_23x6xxQ_xxx64|Q_8998|Q_2782|Q_2781|Q_2361|Q_1213|Q_1152|Q_1151|Q_1150|Q_1145|Q_1144; __gads=ID=4xxx17xb4axx0x1a:T=13x2x3xx55:S=ALxI_Mx5Dxxyxxr-BBRxxxx1kxMw_dTx6g; IGT=1; mlUserID=fHxxxAxxxxxs",
        "Host": "s.imgur.com",
        "Referer": "https://imgur.com/include/signin-iframe.html",
        "Accept-Encoding": "gzip, deflate",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:30.0) Gecko/20100101 Firefox/30.0",
        "Connection": "keep-alive",
        "Accept": "text/css,*/*;q=0.1"
    },
    "body": [],
    "raw": [
        71,
        69,
        84,
        32,
        47,
        83,
        32,
        48,
        101,
        13,
        10,
        13,
        10
    ],
    "inScope": true,
    "messageType": "request"
}
```
