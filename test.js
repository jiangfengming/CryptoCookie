var assert = require('assert');
var http = require('http');
var CryptoCookie = require('./CryptoCookie');
var crypto = require('crypto');
var request = require('supertest');

describe('CryptoCookie', function() {
  var server = http.createServer(function(req, res) {
    var methods = {
      setSessionCookie: function() {
        var cookie = new CryptoCookie(req, res);
        cookie.set('sessionId', 123);
        res.end();
      },

      removeCookie: function() {
        var cookie = new CryptoCookie(req, res);
        cookie.remove('rem');
        res.end();
      },

      removeCookieAttrs: function() {
        var cookie = new CryptoCookie(req, res);
        cookie.remove('rem', {
          path: '/foo',
          domain: 'www.example.com'
        });

        res.end();
      },

      setCookieAttrs: function() {
        var cookie = new CryptoCookie(req, res);
        cookie.set('attrs', 'ok', {
          maxAge: 500,
          expires: new Date('2015-05-13T07:30:00Z'),
          path: '/foo',
          domain: 'www.example.com',
          secure: true,
          httpOnly: true
        });
        res.end();
      },

      setCookieExpiresGMT: function() {
        var cookie = new CryptoCookie(req, res);
        cookie.set('expiresGMT', 'ok', {
          expires: 'Wed, 13 May 2015 07:30:00 GMT'
        });
        res.end();
      },

      setCookieExpiresISODate: function() {
        var cookie = new CryptoCookie(req, res);
        cookie.set('expiresISODate', 'ok', {
          expires: '2015-05-13T07:30:00Z'
        });
        res.end();
      },

      setCookieExpiresLocalDate: function() {
        var cookie = new CryptoCookie(req, res);
        cookie.set('expiresLocalDate', 'ok', {
          expires: '2015-05-13 07:30:00'
        });
        res.end();
      },

      setCookieExpiresTimestamp: function() {
        var cookie = new CryptoCookie(req, res);
        cookie.set('expiresTimestamp', 'ok', {
          expires: 1431922243259
        });
        res.end();
      },

      setupCookieDefaults: function() {
        var cookie = new CryptoCookie(req, res, {
          maxAge: 500,
          expires: new Date('2015-05-13T07:30:00Z'),
          path: '/foo',
          domain: 'www.example.com',
          secure: true,
          httpOnly: true
        });

        cookie.set('defaults', 'ok');
        res.end();
      },

      setEncryptedCookie: function() {
        var cookie = new CryptoCookie(req, res, {
          keys: [crypto.pbkdf2Sync('pASsWoRD', 'SaLt', 4096, 32)]
        });

        cookie.set('encrypted', 'ok', {
          encrypted: true,
          path: '/'
        });

        var value = cookie.get('encrypted', {
          encrypted: true
        });

        res.end(value);
      },

      getEncryptedCookie: function() {
        var cookie = new CryptoCookie(req, res, {
          keys: [crypto.pbkdf2Sync('pASsWoRD', 'SaLt', 4096, 32)]
        });

        var value = cookie.get('encrypted', {
          encrypted: true
        });

        res.end(value);
      },

      setSignedCookie: function() {
        var cookie = new CryptoCookie(req, res, {
          keys: [crypto.pbkdf2Sync('pASsWoRD', 'SaLt', 4096, 32)]
        });

        cookie.set('signed', 'ok', {
          signed: true,
          path: '/'
        });

        var value = cookie.get('signed', {
          signed: true
        });

        res.end(value);
      },

      getSignedCookie: function() {
        var cookie = new CryptoCookie(req, res, {
          keys: [crypto.pbkdf2Sync('pASsWoRD', 'SaLt', 4096, 32)]
        });

        var value = cookie.get('signed', {
          signed: true
        });

        res.end(value);
      },

      getCookieWithRotateKeys: function() {
        var cookie = new CryptoCookie(req, res, {
          keys: [
            crypto.pbkdf2Sync('NEWpASsWoRD', 'SaLt', 4096, 32),
            crypto.pbkdf2Sync('pASsWoRD', 'SaLt', 4096, 32)
          ]
        });

        var encrypted = cookie.get('encrypted', {
          encrypted: true
        });

        var signed = cookie.get('signed', {
          signed: true
        });

        res.end(encrypted + ',' + signed);
      }
    };

    var method = req.url.slice(1);
    methods[method]();
  });

  var agent = request.agent(server);

  it('should set a session cookie', function(done) {
    agent.get('/setSessionCookie').expect('set-cookie', 'sessionId=123', done);
  });

  it('should set a cookie with Max-Age, Expires (format: Date object), Path, Domain, Secure, HttpOnly attributes', function(done) {
    agent.get('/setCookieAttrs').expect('set-cookie', 'attrs=ok; Max-Age=500; Expires=Wed, 13 May 2015 07:30:00 GMT; Path=/foo; Domain=www.example.com; Secure; HttpOnly', done);
  });

  it('should remove a cookie', function(done) {
    agent.get('/removeCookie').expect('set-cookie', 'rem=; Max-Age=0', done);
  });

  it('should remove a cookie with attributes', function(done) {
    agent.get('/removeCookieAttrs').expect('set-cookie', 'rem=; Max-Age=0; Path=/foo; Domain=www.example.com', done);
  });

  it('should set a cookie with Expires (format: GMT)', function(done) {
    agent.get('/setCookieExpiresGMT').expect('set-cookie', 'expiresGMT=ok; Expires=Wed, 13 May 2015 07:30:00 GMT', done);
  });

  it('should set a cookie with Expires (format: ISO 8601)', function(done) {
    agent.get('/setCookieExpiresISODate').expect('set-cookie', 'expiresISODate=ok; Expires=Wed, 13 May 2015 07:30:00 GMT', done);
  });

  it('should set a cookie with Expires (format: local date)', function(done) {
    agent.get('/setCookieExpiresLocalDate').expect('set-cookie', 'expiresLocalDate=ok; Expires=Tue, 12 May 2015 23:30:00 GMT', done);
  });

  it('should set a cookie with Expires (format: milliseconds timestamp)', function(done) {
    agent.get('/setCookieExpiresTimestamp').expect('set-cookie', 'expiresTimestamp=ok; Expires=Mon, 18 May 2015 04:10:43 GMT', done);
  });

  it('should create a cookie object with default options', function(done) {
    agent.get('/setupCookieDefaults').expect('set-cookie', 'defaults=ok; Max-Age=500; Expires=Wed, 13 May 2015 07:30:00 GMT; Path=/foo; Domain=www.example.com; Secure; HttpOnly', done);
  });

  it('should set an encrypted cookie', function(done) {
    agent.get('/setEncryptedCookie').expect('ok', done);
  });

  it('should get an encrypted cookie', function(done) {
    agent.get('/getEncryptedCookie').expect('ok', done);
  });

  it('should set a signed cookie', function(done) {
    agent.get('/setSignedCookie').expect('ok', done);
  });

  it('should get a signed cookie', function(done) {
    agent.get('/getSignedCookie').expect('ok', done);
  });

  it('should get encrypted/signed cookies with rotate keys', function(done) {
    agent.get('/getCookieWithRotateKeys').expect('ok,ok', done);
  });
});

/*
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
*/

/*http.get('http://127.0.0.1:8088/set', function(res) {
  console.log(res.headers);

  http.get('http://127.0.0.1:8088', function(res) {
    console.log(res.headers);
    server.close();
  });
});
*/
