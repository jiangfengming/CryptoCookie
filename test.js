var http = require('http');
var url = require('url');
var cryptoCookie = require('./cryptoCookie');
var crypto = require('crypto');

var server = http.createServer(function(req, res) {
  var cookie = new cryptoCookie(req, res, {
    algorithm: 'aes-256-cfb',
    ivSize: 128,
    keys: [crypto.pbkdf2Sync('pASsWoRD', 'SaLt', 4096, 32), crypto.pbkdf2Sync('OlDpaSSwoRd', 'sAlt', 4096, 32)]
  });

  var urlInfo = url.parse(req.url);

  if (urlInfo.pathname == '/set') {
    console.log('set cookies');

    cookie.set('foo', '1', {
      maxAge: 3600,
      httponly: true
    });
    cookie.set('bar', '2', {
      encrypt: true,
    });
    cookie.set('名字', '值');
    cookie.set('秘密', '呵呵', {
      encrypt: true
    });
  }

  console.log(cookie.reqCookies);
  console.log(cookie.get('foo'));
  console.log(cookie.get('bar', true));
  console.log(cookie.get('名字'));
  console.log(cookie.get('秘密', true));

  res.end();
}).listen(8088);

/*http.get('http://127.0.0.1:8088/set', function(res) {
  console.log(res.headers);

  http.get('http://127.0.0.1:8088', function(res) {
    console.log(res.headers);
    server.close();
  });
});
*/
