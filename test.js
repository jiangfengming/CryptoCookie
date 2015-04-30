var http = require('http');
var url = require('url');
var CryptoCookie = require('./CryptoCookie');
var crypto = require('crypto');

var server = http.createServer(function(req, res) {
  var cookie = new CryptoCookie(req, res, [{
    algorithm: 'aes-256-cfb',
    ivSize: 128,
    key: crypto.pbkdf2Sync('pASsWoRD', 'SaLt', 4096, 32)
  }, {
    algorithm: 'aes-256-cfb',
    ivSize: 128,
    key: crypto.pbkdf2Sync('OlDpaSSwoRd', 'sAlt', 4096, 32)
  }]);

  var cookie2 = new CryptoCookie(req, res,[{
    algorithm: 'aes-256-cfb',
    ivSize: 128,
    key: crypto.pbkdf2Sync('newPasSword', 'sAlt', 4096, 32)
  }, {
    algorithm: 'aes-256-cfb',
    ivSize: 128,
    key: crypto.pbkdf2Sync('pASsWoRD', 'SaLt', 4096, 32)
  }]);

  var urlInfo = url.parse(req.url);

  if (urlInfo.pathname == '/set') {
    console.log('set cookies');

    cookie.set('foo', 'foooo', {
      maxAge: 3600,
      httponly: true
    });
    cookie.set('secret', 'this is a secret message', {
      encrypt: true,
    });
    cookie.set('名字', '蒋凤鸣');
    cookie.set('秘密', '这是一条秘密消息', {
      encrypt: true
    });
  }

  console.log(cookie.reqCookies);
  console.log(cookie.get('foo'));
  console.log(cookie.get('secret', true));
  console.log(cookie2.get('secret', true));
  console.log(cookie.get('名字'));
  console.log(cookie.get('秘密', true));
  console.log(cookie2.get('秘密', true));

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
