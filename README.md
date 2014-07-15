burpbuddy
=========

burpbuddy exposes [Burp Suites's](http://portswigger.net/burp/) extender API over the network through various mediums, with the goal of enabling development in any language without the restrictions of the JVM. See the documentation below and [examples](https://github.com/liftsecurity/burpbuddy/tree/master/examples) for more information.

## Releases


## Build instructions for development or bleeding edge
### OSX
1. ```brew install maven```
1. Install Java 8 
1. Clone this repo
1. ```cd burp```
1. ```export JAVA_HOME=/Library/Java/JavaVirtualMachines/jdk1.8.0_05.jdk/Contents/Home```
1. ```mvn package```
1. ```cd target```
1. copy burpbuddy-0.1-SNAPSHOT.jar where/you/put/burp/stuff

## WebSocket Server
A WebSocket server is available to ingest streaming events from burp. Currently this includes requests, responses, and scan issues. Use the `messageType` field to distinguish between each of these. Sometimes it may appear that duplicate events are being emmited, this is because burp is emitting for different tools (proxy, spider, etc). Use the `toolFlag` parameter to differentiate between these. Also, `highlight` and `comment` fields will be tool dependent.

### Messages
All messages are sent as JSON.
#### request
- host (string)
- port (int)
- protocol (string)
- url (string)
- path (string)
- httpVersion (string)
- method (string)
- headers (object) - key/value pairs of strings
- body (array) - byte array of the request body
- raw (array) - byte array of the entire request
- inScope (bool) - true if the url is in the current burp scope
- highlight (string)
- comment (string)
- toolFlag (int)
- messageType (string) - set to `request`

#### response
- host (string)
- port (int)
- protocol (string)
- headers (object) - key/value pairs of strings
- cookies (array) - array of cookie objects
- mimeType (string)
- body (array) - byte array of the response body
- raw (array) - byte array of the entire response
- inScope (bool) - true if url is in the current burp scope
- highlight (string)
- comment (string)
- toolFlag (int)
- messageType (string) - set to `response`

#### scanIssue
- host (string)
- port (int)
- protocol (string)
- name (string)
- issueType (int)
- severity (string)
- confidence (string)
- issueBackground (string)
- remediationBackground (string)
- issueDetail (string)
- remediationDetail (string)
- requestResponses (array) - array of request/response pairs
- inScope (bool) - true if url is in the current burp scope
- messageType (string) - set to `scanIssue`

#### requestResponse
This combines the request and response message into a single object. It's created by implementing a scanner check that always returns null.
- request (request)
- response (response)
- messageType (string) - set to `requestResponse`

## Request hook
A URL can be configured to hook into burp's proxy processing. On every request, this URL will receive a POST containing a JSON body exactly like in the socket stream. A JSON response is expected from this request with the exact same fields. Certain fields can be modified to alter the request before burp sends it along the proxy chain, which will eventually go to the server. The following fields can be used to modify the request:

- host
- port
- protocol
- httpVersion
- method
- path
- headers
- body
- comment
- highlight

The `referenceID` field may be used to track requests and response pairs.

## Response Hook
Similarly, a URL can be configured to hook into burp's response processing. On every response, this URL will receive a POST containing a JSON body exactly like in the socket stream. A JSON response is expected with the exact same fields. Only the `raw` field can be modified to alter the content of the response. This is a bit of a pain, but the alternative is for the extension to implement magic and build a response for you. In most cases, users will want to transform the byte array into a string, perform some sort of match and replace, and then transform back into a byte array. Other fields below can be modified as well to alter burp's presentation of the response:
- raw
- comment
- highlight

The `referenceID` field may be used to track requests and response pairs.

## HTTP API
Virtually every method call in the burp extender API is exposed via HTTP. The following is a list of paths and required formats. All non `GET` requests must have a content-type of `application/json`.

### GET /scope/{url}
`url` should be a base64 encoded URL. The response will be `200` for a URL that is in burp's current scope and `404` for one that is not.

### POST /scope
The provided URL is added to burp's scope.

Required Fields:
```
url: string
```

### DELETE /scope/{url}
`url` should be a base64 encoded URL to remove from burp's scope.

### GET /scanissues
Get a list of all scan issues.

### GET /scanissues/{url}
Given a base64 encoded URL, return the scan issues for that URL.

### POST /scanissues
Add a new issue.

Required Fields:
```
url: string
host: string
port: int
name: string
issueType: int
severity: string
confidence: string
issueBackground: string
remediationBackground: string
issueDetail: string
remediationDetail: string
requestResposnes: array of request/response pairs. See POST /scan/passive for format.
```

### POST /spider
Send a URL to spider.
Required Fields:
```
url: string
```

### GET /jar
Get a list of all of the cookies in the cookie jar.

### POST /jar
Add a cookie to the cookie jar.

Required Fields:
```
domain: string
expiration: string // In Date format
name: string
value: string
```

### POST /scan/active
Send a request to the active scanner.

Required Fields:
```
host: string
port: int
useHttps: bool
request: byte[]
```

Response:
```
id: int
```

### GET /scan/active/{id}
Get scan item `id` from the active queue.

### DELETE /scan/active/{id}
Delete a scan item `id` from the active queue.

### POST /scan/passive
Send a request/response to the passive scanner for analysis.

Required Fields:
```
host: string
port: int
useHttps: bool
request: byte[]
response: byte[]
```

### POST /send/{tool}
Send a request to repeater or intruder, provided as `tool`.

Required Fields:
```
host: string
port: int
useHttps: bool
request: byte[]
```

### POST /alert
Create an alert.

Required Fields:
```
message: string
```

### POST /stdout
Send a message to stdout.

Required Fields:
```
message: string
```

### POST /stderr
Send a message to stderr.

Required Fields:
```
message: string
```

### GET /sitemap
Get the contents of burp's sitemap

### GET /sitemap/{url}
Get the contents of burp's sitemap containing the provied base64 encoded URL.

### POST /sitemap
Add a request/response to the sitemap.

Required Fields:
```
request: 
    raw: byte[]
    comment: string
    highlight: string
    host: string
    port: int
    protocol: string

response:
    raw: byte[]
```
### GET /proxyhistory
Get all the request/response pairs from burp's proxy history
