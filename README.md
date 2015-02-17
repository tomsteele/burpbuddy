burpbuddy
=========

burpbuddy exposes [Burp Suites's](http://portswigger.net/burp/) extender API over the network through various mediums, with the goal of enabling development in any language without the restrictions of the JVM. See the documentation below and [examples](https://github.com/liftsecurity/burpbuddy/tree/master/examples) for more information.

## Requirements
- Java 8
- [BurpSuite](http://portswigger.net/burp/)

## Releases
A compiled and packaged Jar file is available [here](https://github.com/liftsecurity/burpbuddy/releases/download/v2.1.0/burpbuddy-2.1.0.jar).

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

## Security
The WebSocket Server and HTTP API are protected from CSRF. With the exception that the WebSocket Server allows an origin of `*` by default, which can be modified once you know the domain structure of your connection. We did this because it's very difficult to come up with all the possible combinations that can occur across different mediums. Currently, we do not provide any means of authentication. By default, the servers all listen on localhost.

If you identify a vulnerability, please report it to us security@liftsecurity.io and we will work with you to resolve it. Thanks!

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
- query (string)
- httpVersion (string)
- method (string)
- headers (object) - key/value pairs of strings
- body (string) - base64 encoded string of the request body
- raw (string) - base64 encoded string of the entire request
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
- body (string) - base64 encoded string of the response body
- raw (string) - base64 encoded string of the entire response
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
- query
- headers
- body
- comment
- highlight
- referenceID

The `referenceID` field may be used to track requests and response pairs.

## Response Hook
Similarly, a URL can be configured to hook into burp's response processing. On every response, this URL will receive a POST containing a JSON body exactly like in the socket stream. A JSON response is expected with the exact same fields. Only the `raw` field can be modified to alter the content of the response. This is a bit of a pain, but the alternative is for the extension to implement magic and build a response for you. In most cases, users will want to transform the byte array into a string, perform some sort of match and replace, and then transform back into a byte array. Other fields below can be modified as well to alter burp's presentation of the response:
- raw
- comment
- highlight
- referenceID

The `referenceID` field may be used to track requests and response pairs.

## HTTP API
Virtually every method call in the burp extender API is exposed via HTTP. The following is a list of paths and required formats. All non `GET` requests must have a content-type of `application/json`.

### GET /scope/{url}
`url` should be a base64 encoded URL. The response will be `200` for a URL that is in burp's current scope and `404` for one that is not.

Example:
```
$ curl -i http://localhost:8001/scope/aHR0cDovL3N0YWNrdGl0YW4uY29tLw==
HTTP/1.1 200 OK

$ curl -i http://localhost:8001/scope/aHR0cDovL3N0YWNrdGl0YW4uY2
HTTP/1.1 404 Not Found
```

### POST /scope
The provided URL is added to burp's scope.

Required Fields:
```
url: string
```

Example:
```
$ curl -i http://localhost:8001/scope -X POST -H 'Content-type: application/json' -d '{"url": "http://liftsecurity.io"}'
HTTP/1.1 201 Created

{"url":"http://liftsecurity.io"}
```

### DELETE /scope/{url}
`url` should be a base64 encoded URL to remove from burp's scope.

Example:
```
$ curl -i http://localhost:8001/scope/aHR0cDovL3Rlc3Rhc3AudnVsbndlYi5jb20v -X DELETE -H "content-type: application/json"
HTTP/1.1 204 No Content

```

### GET /scanissues
Get a list of all scan issues.

Example:
```
$ curl -i http://localhost:8001/scanissues
HTTP/1.1 200 OK
Content-Type: application/json; charset=UTF8


{"data":[]}
```

### GET /scanissues/{url}
Given a base64 encoded URL, return the scan issues for that URL.

Example:
```
$ curl -i http://localhost:8001/scanissues/aHR0cDovL3N0YWNrdGl0YW4uY29tLw==
HTTP/1.1 200 OK
Content-Type: application/json; charset=UTF8
Content-Length: 11
Server: Jetty(9.0.z-SNAPSHOT)

{"data":[]}
```

### POST /scanissues
Add a new issue.

Required Fields:
```
url: string
host: string
port: int
protocol: http
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

Example:
```
$ curl -i http://localhost:8001/scanissues -X POST -H 'Content-Type: application/json' -d '{"url": "http://liftsecurity.io", "host": "liftsecurity.io", "port": 4444, "protocol": "http", "name": "Hello World", "issueType": 134217728, "severity": "Information", "confidence": "Certain", "issueBackground": "beep", "remediationBackground": "boop", "issueDetail": "foo", "remediationDetail": "bar", "requestResponses":[{"request": { "host": "liftsecurity.io", "port": 4444, "protocol": "http", "raw": "R0VUIC8gSFRUUDEuMQ=="}, "response": {"host": "liftsecurity.io", "port": 4444, "protocol": "http", "raw": "SFRUUCAyMDAgT0s="}}]}'
HTTP/1.1 201 Created
Content-Type: application/json; charset=UTF8
Content-Length: 661
Server: Jetty(9.0.z-SNAPSHOT)

{"url":"http://liftsecurity.io","host":"liftsecurity.io","port":4444,"protocol":"http","name":"Hello World","issueType":134217728,"severity":"Information","confidence":"Certain","issueBackground":"beep","remediationBackground":"boop","issueDetail":"foo","remediationDetail":"bar","requestResponses":[{"request":{"host":"liftsecurity.io","port":4444,"protocol":"http","httpVersion":"HTTP/1.1","raw":"R0VUIC8gSFRUUDEuMQ\u003d\u003d","inScope":false,"toolFlag":16962,"referenceID":0},"response":{"statusCode":0,"raw":"SFRUUCAyMDAgT0s\u003d","host":"liftsecurity.io","protocol":"http","port":4444,"inScope":false,"toolFlag":16962,"referenceID":0}}],"inScope":false}
```

Resources:
- [Issue Types](http://portswigger.net/burp/help/scanner_issuetypes.html)

### POST /spider
Send a URL to spider.
Required Fields:
```
url: string
```

Example:
```
$ curl -i http://localhost:8001/spider -X POST -H 'Content-Type: application/json' -d '{"url": "http://liftsecurity.io/"}'
HTTP/1.1 201 Created
```

### GET /jar
Get a list of all of the cookies in the cookie jar.

Example:
```
$ curl -i http://localhost:8001/jar
HTTP/1.1 200 OK
Content-Type: application/json; charset=UTF8

{"data":[{"domain":"liftsecurity.io","name":"SID","value":"192891pj2ijf90u129", "expiration":"Oct 15, 2014 9:09:44 AM"}]}
```

### POST /jar
Add a cookie to the cookie jar.

Required Fields:
```
domain: string
expiration: string // In Date format
name: string
value: string
```

Example:
```
$ curl -i http://localhost:8001/jar -X POST -H 'Content-Type: application/json' -d '{"domain":"liftsecurity.io","name":"SID","value":"192891pj2ijf90u129", "expiration":"Oct 15, 2014 9:09:44 AM"}'
HTTP/1.1 201 Created
Content-Type: application/json; charset=UTF8

{"domain":"liftsecurity.io","expiration":"Oct 15, 2014 9:09:44 AM","name":"SID","value":"192891pj2ijf90u129"}
```

### POST /scan/active
Send a request to the active scanner.

Required Fields:
```
host: string
port: int
useHttps: bool
request: string(base64)
```

Example:
```
$ curl -i http://localhost:8001/scan/active -X POST -H 'Content-Type: application/json' -d '{"host": "stacktitan.com", "port": 80, "useHttps": false, "request": "R0VUIC8gSFRUUC8xLjENCkhvc3Q6IHN0YWNrdGl0YW4uY29tDQpBY2NlcHQ6ICovKg0KQWNjZXB0LUxhbmd1YWdlOiBlbg0KVXNlci1BZ2VudDogTW96aWxsYS81LjAgKGNvbXBhdGlibGU7IE1TSUUgOS4wOyBXaW5kb3dzIE5UIDYuMTsgV2luNjQ7IHg2NDsgVHJpZGVudC81LjApDQpDb25uZWN0aW9uOiBjbG9zZQ0KDQo="}'
HTTP/1.1 201 Created
```

### GET /scan/active
Get a list of all items from the active queue.

Example:
```
$ curl -i http://localhost:8001/scan/active
HTTP/1.1 200 OK
Content-Type: application/json; charset=UTF8
Content-Length: 126
Server: Jetty(9.0.z-SNAPSHOT)

{"data":[{"id":1,"errors":0,"insertionPointCount":0,"requestCount":0,"status":"0% complete","percentComplete":0,"issues":[]}]}
```

### GET /scan/active/{id}
Get scan item `id` from the active queue.

Example:
```
$ curl -i http://localhost:8001/scan/active/1
HTTP/1.1 200 OK
Content-Type: application/json; charset=UTF8

{"id":1,"errors":0,"insertionPointCount":3,"requestCount":70,"status":"finished","percentComplete":100,"issues":[]}
```

### DELETE /scan/active/{id}
Delete a scan item `id` from the active queue.

Example:
```
$ curl -i http://localhost:8001/scan/active/1 -X DELETE -H 'Content-Type: application/json'
HTTP/1.1 204 No Content
Content-Type: application/json; charset=UTF8
```

### POST /scan/passive
Send a request/response to the passive scanner for analysis.

Required Fields:
```
host: string
port: int
useHttps: bool
request: string (base64)
response: string (base64)
```

Example:
```
curl -i http://localhost:8001/scan/passive -X POST -H 'Content-Type: application/json' -d '{"host": "liftsecurity.io", "port": 443, "useHttps": true, "request": "R0VUIC8gSFRUUDEuMQ==", "response": "SFRUUCAyMDAgT0s="}'
HTTP/1.1 201 Created
Content-Type: application/json; charset=UTF8
```

### POST /send/{tool}
Send a request to repeater or intruder, provided as `tool`.

Required Fields:
```
host: string
port: int
useHttps: bool
request: string (base64)
```

Example:
```
$ curl -i http://localhost:8001/send/intruder -X POST -H 'Content-Type: application/json' -d '{"host": "liftsecurity.io", "port": 443, "useHttps": true, "request": "R0VUIC8gSFRUUDEuMQ=="}'
HTTP/1.1 201 Created
Content-Type: application/json; charset=UTF8
```

### POST /alert
Create an alert.

Required Fields:
```
message: string
```

Example:
```
$ curl -i http://localhost:8001/alert -X POST -H 'Content-Type: application/json' -d '{"message": "exterminate!"}'
HTTP/1.1 201 Created
Content-Type: application/json; charset=UTF8
```

### GET /sitemap
Get the contents of burp's sitemap

Example:
```
$ curl -i http://localhost:8001/sitemap
HTTP/1.1 200 OK
Content-Type: application/json; charset=UTF8

{"data":[]}
```

### GET /sitemap/{url}
Get the contents of burp's sitemap containing the provied base64 encoded URL.

Example:
```
$ curl -i http://localhost:8001/sitemap/aHR0cHM6Ly9saWZ0c2VjdXJpdHkuaW8v
HTTP/1.1 200 OK
Content-Type: application/json; charset=UTF8
Transfer-Encoding: chunked
Server: Jetty(9.0.z-SNAPSHOT)

{"data":[]}
```

### POST /sitemap
Add a request/response to the sitemap.

Required Fields:
```
request: 
    raw: string (base64)
    comment: string
    highlight: string
    host: string
    port: int
    protocol: string

response:
    raw: string (base64)
```

Example:
```
$ curl -i http://localhost:8001/sitemap -X POST -H 'Content-Type: application/json' -d '{"request": {"host": "liftsecurity.io", "port": 443, "protocol": "https", "highlight": "red", "comment": "woohoo", "raw": "R0VUIC8gSFRUUDEuMQ=="}, "response": {"raw": "SFRUUC8xLjEgMjAwIE9LXHJcblxyXG4="}}'
HTTP/1.1 201 Created
Content-Type: application/json; charset=UTF8

{"request":{"host":"liftsecurity.io","port":443,"protocol":"https","highlight":"red","comment":"woohoo","httpVersion":"HTTP/1.1","raw":"R0VUIC8gSFRUUDEuMQ\u003d\u003d","inScope":false,"toolFlag":16962,"referenceID":0},"response":{"statusCode":0,"raw":"SFRUUC8xLjEgMjAwIE9LXHJcblxyXG4\u003d","port":0,"inScope":false,"toolFlag":16962,"referenceID":0}}
```

Known Issues:
- Highlight is not getting set within burp, this appears to be an issue with the extender API

### GET /proxyhistory
Get all the request/response pairs from burp's proxy history

Example:
```
$ curl -i http://localhost:8001/proxyhistory
HTTP/1.1 200 OK
Content-Type: application/json; charset=UTF8

{"data":[]}
```

### GET /state
Download the current burp state

Example:
```
$ curl -i http://localhost:8001/state
HTTP/1.1 200 OK
Content-Type: application/octet-stream;charset=UTF-8
Content-Disposition: attachment; filename=burp_state
Transfer-Encoding: chunked

...data...
```

### POST /state
Restore state from file. Burp reloads after restoration, so you will receive an empty reply from the server.
```
$ curl -i http://localhost:8001/state -X POST -F file=@restore_state
```

### POST /proxy/intercept/enable
Enable proxy intercept.
```
$ curl -i http://localhost:8001/proxy/intercept/enable -X POST
```

### POST /proxy/intercept/disable
Disable proxy intercept.
```
$ curl -i http://localhost:8001/proxy/intercept/disable -X POST
```
