crypto-cookie
============

```
var cryptoCookie = require('crypto-cookie');

var cookie = new cryptoCookie(req, res, {
	algorithm: 'aes-256-cbc',
	ivSize: 128,
	keys: ['J%9Mt7Cg_2N_Q#Qk]:j~N9<{`CWt0Xse', 'op`dZK@4L1|N(oe1nMP9F-6}"Y+4ysR}'], // ['current Key', 'old Key', ...]
});

// all cookies
console.log(cookie.reqCookies);

// set a cookie
cookie.set('name', 'value', {
	encrypt: false,
	expires: Date.now + 30000, // Date object, or milliseconds, or UTC string
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
cookie.delete('name', options); // options is the same as cookie.set()

```
