burpbuddy
=========

My buddy

## Build instructions
1. ```brew install maven```
1. Clone this repo
1. ```cd burp```
1. ```mvn package```
1. ```cd target```
1. copy burpbuddy-0.1-SNAPSHOT.jar where/you/put/burp/stuff

## Request hook
A URL can be configured to to hook into burp's request processing. On every request, this URL will receive a POST containing a JSON body exactly like in the socket stream. A JSON response is expected from this request with the exact same fields. Certain fields can be modified to alter the request before burp sends it along to the server. The following fields can be used to modify the request:
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
