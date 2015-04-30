crypto-cookie
============

```js
var cryptoCookie = require('crypto-cookie');
var crypto = require('crypto');

var cookie = new CryptoCookie(req, res, [{
  algorithm: 'aes-256-cfb',
  ivSize: 128,
  key: crypto.pbkdf2Sync('pASsWoRD', 'SaLt', 4096, 32)
}, {
  algorithm: 'aes-256-cfb',
  ivSize: 128,
  key: crypto.pbkdf2Sync('OlDpaSSwoRd', 'sAlt', 4096, 32)
}]);

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
