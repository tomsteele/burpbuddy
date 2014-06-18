var Hapi = require('hapi');

var server = Hapi.createServer('localhost', 3001);

server.route({
    method: 'POST',
    path: '/request',
    handler: function (req, reply) {
        req.payload.headers.beep = 'boop';
        reply(req.payload);
    }
});

server.start();

