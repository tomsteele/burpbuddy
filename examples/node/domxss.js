var WebSocket = require('ws');
var ws = new WebSocket('ws://localhost:8000/');

ws.on('open', function() {
  console.log('opened connection to ws://localhost:8000/');
});

ws.on('message', function(data, flags) {
  var obj = JSON.parse(data);
  if (obj.messageType === 'requestResponse' && obj.request.inScope) {
      domXSS(obj.request, obj.response);
  }
});

ws.on('error', function(err) {
  console.log(err);
  process.exit(1);
});

function domXSS(request, response) {
    var contentType = response.headers['Content-Type'];
    if (typeof contentType === 'string' && (contentType.indexOf('javascript') !== -1 || contentType.indexOf('html') !== -1)) {
        var body = new Buffer(response.body).toString().split('\n');
        for (var i = 0; i < body.length; i++) {
            var line = body[i].trim();
            if (line.match(/(location\s*[\[.])|([.\[]\s*["']?\s*(arguments|dialogArguments|innerHTML|write(ln)?|open(Dialog)?|showModalDialog|cookie|URL|documentURI|baseURI|referrer|name|opener|parent|top|content|self|frames)\W)|(localStorage|sessionStorage|Database)/g)) {
                console.log('domxss source', request.url, 'line', i);
                if (line.length < 100) {
                    console.log(line);
                } else {
                    console.log('line too long');
                }
            }
            if (line.match(/((src|href|data|location|code|value|action)\s*["'\]]*\s*\+?\s*=)|((replace|assign|navigate|getResponseHeader|open(Dialog)?|showModalDialog|eval|evaluate|execCommand|execScript|setTimeout|setInterval)\s*["'\]]*\s*\()/g)) {
                console.log('domxss sink', request.url, 'line', i);
                if (line.length < 100) {
                    console.log(line);
                } else {
                    console.log('line too long');
                }
            }
            if (line.match(/after\(|\.append\(|\.before\(|\.html\(|\.prepend\(|\.replaceWith\(|\.wrap\(|\.wrapAll\(|\$\(|\.globalEval\(|\.add\(|jQUery\(|\$\(|\.parseHTML\(/g)) {
                console.log('domxss jquery sink', request.url, 'line', i);
                if (line.length < 100) {
                    console.log(line);
                } else {
                    console.log('line too long');
                }
            }
        }
    }
}
