/*!
 * CryptoCookie.js
 * http://www.noindoin.com/
 *
 * Copyright 2014 Jiang Fengming <fenix@noindoin.com>
 * Released under the MIT license
 */

var crypto = require('crypto');

function CryptoCookie(req, res, ciphers) {
  if (!ciphers)
    ciphers = [];
  else if (ciphers.constructor == Object)
    ciphers = [ciphers];

  this.req = req;
  this.res = res;
  this.ciphers = ciphers;
  this.resCookies = [];
  this.reqCookies = {};

  if (req.headers.cookie) {
    var cookies = req.headers.cookie.split('; ');
    for (var i = cookies.length - 1; i >= 0; i--) {
      var c = cookies[i].split('=');
      this.reqCookies[decodeURIComponent(c[0])] = decodeURIComponent(c[1]);
    }
  }
}

CryptoCookie.prototype.set = function(name, value, opts) {
  if (!opts)
    opts = {};

  if (opts.encrypt) {
    var cipher = this.ciphers[0];
    name = crypto.createHmac('sha256', cipher.key).update(name).digest('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    value = new Buffer(String(value));
    var checksum = crypto.createHash('sha256').update(value).digest();
    value = Buffer.concat([checksum, value]);
    var iv = crypto.randomBytes(cipher.ivSize / 8);
    var cip = crypto.createCipheriv(cipher.algorithm, cipher.key, iv);
    value = Buffer.concat([iv, cip.update(value), cip.final()]).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  var cookie = encodeURIComponent(name) + '=' + encodeURIComponent(value);

  if (opts.maxAge != undefined)
    cookie += '; max-age=' + opts.maxAge;
  if (opts.expires !=  undefined)
    cookie += '; expires=' + opts.expires.constructor == Date ? opts.expires.toUTCString() : new Date(opts.expires).toUTCString();
  if (opts.path)
    cookie += '; path=' + opts.path;
  if (opts.domain)
    cookie += '; domain=' + opts.domain;
  if (opts.secure)
    cookie += '; secure';
  if (opts.httponly)
    cookie += '; httponly';

  this.resCookies.push(cookie);
  this.reqCookies[name] = value;
  this.res.setHeader('Set-Cookie', this.resCookies);
  return this;
};

CryptoCookie.prototype.get = function(name, encrypted) {
  if (!encrypted)
    return this.reqCookies[name];

  try {
    for (var i = 0; i < this.ciphers.length; i++) {
      var cipher = this.ciphers[i];
      var n = crypto.createHmac('sha256', cipher.key).update(name).digest('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      if (this.reqCookies[n]) {
        var data = new Buffer(this.reqCookies[n].replace(/-/g, '+').replace(/_/g, '/'), 'base64');
        var ivSize = cipher.ivSize / 8;
        var iv = data.slice(0, ivSize);
        data = data.slice(ivSize);
        var decip = crypto.createDecipheriv(cipher.algorithm, cipher.key, iv);
        data = Buffer.concat([decip.update(data), decip.final()]);
        var checksum = data.slice(0, 32);
        data = data.slice(32);
        return checksum.equals(crypto.createHash('sha256').update(data).digest()) ? data.toString() : undefined;
      }
    }
  } catch (e) {
    return undefined;
  }
};

CryptoCookie.prototype.remove = function(name, opts) {
  if (!opts)
    opts = {};
  opts.maxAge = 0;
  this.set(name, '', opts);
  delete this.reqCookies[name];
  return this;
};

module.exports = CryptoCookie;
