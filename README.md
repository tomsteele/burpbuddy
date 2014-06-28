burpbuddy
=========

burpbuddy exposes [Burp Suites's](http://portswigger.net/burp/) extender API over the network through various mediums, with the goal of enabling development in any language without the restrictions of the JVM. See the documentation below and [examples](https://github.com/liftsecurity/burpbuddy/tree/master/examples) for more information.

## Status
Heavy development, nothing should be depended upon as stable, things will likely change.

## Build instructions
1. ```brew install maven```
1. Install Java 8 
1. Clone this repo
1. ```cd burp```
1. ``export JAVA_HOME=/Library/Java/JavaVirtualMachines/jdk1.8.0_05.jdk/Contents/Home```
1. ```mvn package```
1. ```cd target```
1. copy burpbuddy-0.1-SNAPSHOT.jar where/you/put/burp/stuff

## WebSocket Server
A WebSocket server is available to ingest streaming events from burp. Currently this includes requests, responses, and scan issues. Use the `messageType` field to distinguish between each of these.

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
- inScope (bool) - true if url is in the current burp scope
- messageType (string) - set to `scanIssue`

#### requestResponse
This combines the request and response message into a single object. It's created by implementing a scanner check that always returns null.
- request (request)
- response (response)
- messageType (string) - set to `requestResponse`

## Request hook
A URL can be configured to hook into burp's request processing. On every request, this URL will receive a POST containing a JSON body exactly like in the socket stream. A JSON response is expected from this request with the exact same fields. Certain fields can be modified to alter the request before burp sends it along to the server. The following fields can be used to modify the request:

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

## Response Hook
Similarly, a URL can be configured to hook into burp's response processing. On every response, this URL will receive a POST containing a JSON body exactly like in the socket stream. A JSON response is expected with the exact same fields. Only the `raw` field can be modified to alter the content of the response. This is a bit of a pain, but the alternative is for the extension to implement magic and build a response for you. In most cases, users will want to transform the byte array into a string, perform some sort of match and replace, and then transform back into a byte array. Other fields below can be modified as well to alter burp's presentation of the response:
- raw
- comment
- highlight


