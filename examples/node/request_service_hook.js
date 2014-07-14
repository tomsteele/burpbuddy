var Hapi = require('hapi');

var server = Hapi.createServer('localhost', 3001);

server.route({
    method: 'POST',
    path: '/request',
    handler: function (req, reply) {
        console.log(req.payload.referenceID);
        req.payload.headers.beep = 'boop';
        req.payload.path = '/foo';
        reply(req.payload);
    }
});

server.start();

