crypto-cookie
============

```
var cryptoCookie = require('crypto-cookie');
var crypto = require('crypto');

var cookie = new cryptoCookie(req, res, {
  algorithm: 'aes-256-cfb',
  ivSize: 128,
  keys: [
    crypto.pbkdf2Sync('pASsWoRD', 'SaLt', 4096, 32),
    crypto.pbkdf2Sync('OlDpaSSwoRd', 'sAlt', 4096, 32)
  ], // ['current Key', 'old Key', ...]
});

// all cookies
console.log(cookie.reqCookies);

// set a cookie
cookie.set('name', 'value', {
	encrypt: false,
	maxAge: 3600
	path: '/',
	domain: 'www.example.com',
	secure: false,
	httpOnly: false
});

// get a cookie
cookie.get('name');
cookie.reqCookies.name;

// get an encrypted cookie
cookie.get('secret', true);

// delete a cookie
cookie.remove('name', options); // options is the same as cookie.set()

```
