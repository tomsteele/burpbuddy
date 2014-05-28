var WebSocket = require('ws');
var request = require('request');
var ws = new WebSocket('ws://127.0.0.1:8000/');

ws.on('open', function() {
  console.log('opened connection to ws://localhost:8000/');
});

ws.on('message', function(data, flags) {
  var obj = JSON.parse(data);
  if (obj.messageType === 'request' && typeof obj.headers.Cookie !== 'undefined') {
    var req = {
        url: obj.url,
        method: obj.method,
        headers: stripCookies(obj.headers),
        followRedirect: false,
        strictSSL: false,
    };
    if (['patch', 'post', 'put'].indexOf(obj.method.toLowerCase()) !== -1 && obj.body.length > 0)  {
        req.body = new Buffer(obj.body);
    }
    request(req, function(err, resp, body) {
        if (err) {
            return;
        }
        console.log(resp.statusCode + " " + req.method + " " + obj.url);
        if (resp.statusCode < 300 && !err ) {
            console.log(body);
        }
    });
  }
});

ws.on('error', function(err) {
  console.log(err);
  process.exit(1);
});

function stripCookies(headers) {
    delete headers.Cookie;
    return headers;
}
