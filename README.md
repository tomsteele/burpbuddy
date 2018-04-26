burpbuddy
=========

burpbuddy exposes [Burp Suites's](http://portswigger.net/burp/) extender API over the network through various mediums, with the goal of enabling development in any language without the restrictions of the JVM. See the [wiki](https://github.com/tomsteele/burpbuddy/wiki) for more information.

## Requirements
- Java 8
- [BurpSuite](http://portswigger.net/burp/)

## Releases
A compiled and packaged Jar file is available [here](https://github.com/tomsteele/burpbuddy/releases/latest).

## Building from Source

1. Git clone this repo.
1. Install `gradle` if you don't already have it. (For example,
   `$ brew install gradle` on OS X.)
1. Run `$ gradle shadowJar` in the project root to build the `burpbuddy` JAR in
   `build/libs/burpbuddy-<VERSION>-all.jar`.

## Adding burpbuddy to Burp Suite

This is the standard process for adding any JAR Burp extension.

1. In Burp Suite, go to the Extender tab and click the "Add" button.
1. Click "Select file" and navigate to the downloaded or manually built `burpbuddy` JAR.
1. You should see a message that the extension has successfully been loaded and
   an Output message in the message box like: "HTTP Server started on 127.0.0.1:8001."
1. Confirm that `burpbuddy` is running correctly:
   `$ curl -i http://127.0.0.1:8001/ping`.
