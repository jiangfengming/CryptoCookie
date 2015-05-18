# crypto-cookie

## Usage
```js
var cryptoCookie = require('crypto-cookie');

// create a cookie object
var cookie = new CryptoCookie(req, res);

// set a session cookie
cookie.set('sessionId', 123);

// get a cookie
cookie.get('sessionId');

// or
cookie.reqCookies.sessionId

// set a cookie with attributes
cookie.set('attrs', 'ok', {
  maxAge: 500,
  expires: new Date('2015-05-13T07:30:00Z'),
  path: '/foo',
  domain: 'www.example.com',
  secure: true,
  httpOnly: true
});

// remove a cookie
cookie.remove('foo');

// remove a cookie with attributes
cookie.remove('foo', {
  path: '/foo',
  domain: 'www.example.com'
});

// set cookie expires with GMT date string
cookie.set('expiresGMT', 'ok', {
  expires: 'Wed, 13 May 2015 07:30:00 GMT'
});

// set cookie expires with ISO date string
cookie.set('expiresISODate', 'ok', {
  expires: '2015-05-13T07:30:00Z'
});

// set cookie expires with local date format
cookie.set('expiresLocalDate', 'ok', {
  expires: '2015-05-13 07:30:00'
});

// set cookie expires with milliseconds timestamp
cookie.set('expiresTimestamp', 'ok', {
  expires: 1431922243259
});

// create cookie object with default options
// the default options will apply to cookie.set()
var cookie = new CryptoCookie(req, res, {
  maxAge: 500,
  expires: new Date('2015-05-13T07:30:00Z'),
  path: '/foo',
  domain: 'www.example.com',
  secure: true,
  httpOnly: true
});

// set a cookie and override some default options
cookie.set('defaults', 'ok', {
  maxAge: 1000
});
/*
  will equivalent to
  cookie.set('defaults', 'ok', {
    maxAge: 100,
    expires: new Date('2015-05-13T07:30:00Z'),
    path: '/foo',
    domain: 'www.example.com',
    secure: true,
    httpOnly: true
  });
*/


// create cookie object with keys
var cookie = new CryptoCookie(req, res, {
  keys: [crypto.pbkdf2Sync('pASsWoRD', 'SaLt', 4096, 32)]
});

// set an encrypted cookie
// this will use hmac to hash the cookie name, and aes-256-gcm to encrypt the value
cookie.set('encrypted', 'ok', {
  encrypted: true
});

// get an encrypted cookie
var value = cookie.get('encrypted', {
  encrypted: true
});

// set a signed cookie
cookie.set('signed', 'ok', {
  signed: true
});

// get a signed cookie
var value = cookie.get('signed', {
  signed: true
});

// rotate keys support
var cookie = new CryptoCookie(req, res, {
  keys: [
    crypto.pbkdf2Sync('NEWpASsWoRD', 'SaLt', 4096, 32),
    crypto.pbkdf2Sync('pASsWoRD', 'SaLt', 4096, 32)
  ]
});

// when we insert a new password at the beginning of the keys list,
// we still can get the cookie encrypted with old password
var encrypted = cookie.get('encrypted', {
  encrypted: true
});

// and signed cookie as well
var signed = cookie.get('signed', {
  signed: true
});

```

## License
MIT
