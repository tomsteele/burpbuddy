var WebSocket = require('ws');
var request = require('request');
var argv = require('minimist')(process.argv.slice(2));
var ws = new WebSocket('ws://127.0.0.1:8000/');
var level = require('level');
var crypto = require("crypto");
var fs = require('fs');
var util = require('util');

// few defaults
argv._[0] = argv._[0] || 'example';

var db = level(argv._[0] + '.db');

var hash = function (input) {
    return crypto.createHash('sha1').update(input).digest('hex').toString();
};

var history = function (obj, cb) {
    var url = obj.url;
    var key = hash(url);
    db.get(key, function (err, isNew) {
        if (!err && isNew === "true") {
            cb = function () {};
            return cb();
        } else if (obj.inScope) {
            return db.put(key, "true", function (err, val) {
                return cb();
            });
        }
    });
};


ws.on('open', function () {
    console.log('opened connection to ws://localhost:8000/');
});

ws.on('message', function (data, flags) {
    var obj = JSON.parse(data);
    if (obj.messageType === 'request' && typeof obj.headers.Cookie !== 'undefined') {
        history(obj, function() {
            var req = {
                url: obj.url,
                method: obj.method,
                headers: stripCookies(obj.headers),
                followRedirect: false,
                strictSSL: false,
            };
            if (['patch', 'post', 'put'].indexOf(obj.method.toLowerCase()) !== -1 && obj.body.length > 0) {
                req.body = new Buffer(obj.body, 'base64');
            }
            request(req, function (err, resp, body) {
                if (!err) {
                    fs.appendFileSync(argv._[0] + '.rpt', '\n' + resp.statusCode + " Hash: " + hash(resp.body) + " " + req.method + " " + obj.url);
                    fs.appendFileSync(argv._[0] + '.log', util.inspect({
                        "Code": resp.statusCode,
                        "URL": req.url,
                        "Hash": hash(body),
                        "Request": req,
                        "Response": resp
                    }));
                    if (resp.statusCode < 300) {
                        fs.appendFileSync(argv._[0] + '.issues', '-' + "\nWARNING: " + hash(resp.body) + '\nWARNING: ' + resp.statusCode + " " + req.method + " " + obj.url);
                        console.log('-' + "\nWARNING: " + hash(resp.body) + '\nWARNING: ' + resp.statusCode + " " + req.method + " " + obj.url);
                    }
                }
            });
        });
    }
});

ws.on('error', function (err) {
    console.log(err);
    process.exit(1);
});

function stripCookies (headers) {
    delete headers.Cookie;
    return headers;
}
