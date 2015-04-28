/*!
 * cryptoCookie.js v2.0
 * http://www.noindoin.com/
 *
 * Copyright 2014 Jiang Fengming <fenix@noindoin.com>
 * Released under the MIT license
 */

var crypto = require('crypto');

function cryptoCookie(req, res, opts) {
  if (opts) {
    for (var p in opts)
      this[p] = opts[p];
  }

  this.req = req;
  this.res = res;

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

cryptoCookie.prototype.set = function(name, value, opts) {
  if (!opts)
    opts = {};

  if (opts.encrypt) {
    var key = this.keys[0];

    name = crypto.createHmac('sha256', key).update(name).digest('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

    var iv = crypto.randomBytes(this.ivSize / 8);
    var cip = crypto.createCipheriv(this.algorithm, key, iv);
    var secret = Buffer.concat([cip.update(String(value), 'utf8'), cip.final()]);
    value = (iv.toString('base64') + secret.toString('base64')).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
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

cryptoCookie.prototype.get = function(name, encrypted) {
  if (!encrypted)
    return this.reqCookies[name];

  for (var i = 0; i < this.keys.length; i++) {
    var key = this.keys[i];
    var n = crypto.createHmac('sha256', key).update(name).digest('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    if (this.reqCookies[n]) {
      try {
        var data = this.reqCookies[n];
        var ivSize = Math.ceil((this.ivSize / 8) * 4 / 3);
        var iv = new Buffer(data.slice(0, ivSize).replace(/-/g, '+').replace(/_/g, '/'), 'base64');
        var secret = new Buffer(data.slice(ivSize).replace(/-/g, '+').replace(/_/g, '/'), 'base64');
        var decip = crypto.createDecipheriv(this.algorithm, key, iv);
        return Buffer.concat([decip.update(secret), decip.final()]).toString('utf8');
      } catch (e) {
        return undefined;
      }
    }
  }
};

cryptoCookie.prototype.remove = function(name, opts) {
  if (!opts)
    opts = {};
  opts.maxAge = 0;
  this.set(name, '', opts);
  delete this.reqCookies[name];
  return this;
};

module.exports = cryptoCookie;
