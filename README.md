burpbuddy
=========

My buddy

## Status
Heavy development, nothing should be depended upon as stable, things will likely change.

## Build instructions
1. ```brew install maven```
1. Clone this repo
1. ```cd burp```
1. ```mvn package```
1. ```cd target```
1. copy burpbuddy-0.1-SNAPSHOT.jar where/you/put/burp/stuff

## WebSocket Server
A WebSocket server is available to ingest streaming events from burp. Currently this includes requests, responses, and scan issues. Use the `messageType` field to distinguish between each of these.

### Messages
#### Request
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


## Request hook
A URL can be configured to hook into burp's request processing. On every request, this URL will receive a POST containing a JSON body exactly like in the socket stream. A JSON response is expected from this request with the exact same fields. Certain fields can be modified to alter the request before burp sends it along to the server. The following fields can be used to modify the request:
```
host
port
protocol
httpVersion
method
path
headers
body
```
