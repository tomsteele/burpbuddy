'use strict';

const Hapi = require('hapi');

const server = Hapi.server({
    port: 3001,
    host: 'localhost'
});

server.route({
    method: 'POST',
    path: '/request',
    handler: (request, reply) => {
        request.payload.request.method = 'DELETE';
        console.log(request.payload);
        return request.payload;
    }
});

server.route({
    method: 'DELETE',
    path: '/testme',
    handler: (request, reply) => {
        return 'woo';
    }
});

const init = async () => {
    await server.start();
    console.log(`Server running at ${server.info.uri}`);
};

process.on('unhandledRejection', (err) => {
    console.log(err);
    process.exit();
});

init();