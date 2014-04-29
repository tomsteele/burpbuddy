var WebSocket = require('ws');
var ws = new WebSocket('ws://localhost:8000/');

ws.on('open', function() {
  console.log('opened connection to ws://localhost:8000/');
});

ws.on('message', function(data, flags) {
  var obj = JSON.parse(data);
  if (obj.messageType === 'request') {
    console.log(JSON.stringify(obj, null, 4));
  }
});

ws.on('error', function(err) {
    console.log(err);
    process.exit(1);
});
