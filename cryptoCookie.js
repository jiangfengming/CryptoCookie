var crypto = require('crypto');

function CryptoCookie(req, res, opts) {
  this.req = req;
  this.res = res;
  this.opts = opts || {};
  this.resCookies = [];
  this.reqCookies = {};

  if (req.headers.cookie) {
    var cookies = req.headers.cookie.split(/;\s*/);
    for (var i = cookies.length - 1; i >= 0; i--) {
      var c = cookies[i].split('=');
      this.reqCookies[decodeURIComponent(c[0])] = decodeURIComponent(c[1]);
    }
  }
}

CryptoCookie.prototype.set = function(name, value, _opts) {
  if (!_opts)
    _opts = {};

  var opts = {};
  for (var k in this.opts)
    opts[k] = this.opts[k];
  for (k in _opts)
    opts[k] = _opts[k];

  value = String(value);

  if (opts.signed) {
    var key = this.opts.keys[0];
    value += base64url.encode(crypto.createHmac('sha224', key).update(value).digest());
  } else if (opts.encrypted) {
    key = this.opts.keys[0];
    name = base64url.encode(crypto.createHmac('sha224', key).update(name).digest());
    value = new Buffer(value);
    var iv = crypto.randomBytes(12);
    var cip = crypto.createCipheriv('aes-256-gcm', key, iv);
    value = base64url.encode(Buffer.concat([cip.update(value), cip.final(), cip.getAuthTag(), iv]));
  }

  var cookie = encodeURIComponent(name) + '=' + encodeURIComponent(value);

  if (opts.maxAge != undefined)
    cookie += '; Max-Age=' + opts.maxAge;
  if (opts.expires !=  undefined)
    cookie += '; Expires=' + (opts.expires.constructor == Date ? opts.expires.toUTCString() : new Date(opts.expires).toUTCString());
  if (opts.path)
    cookie += '; Path=' + opts.path;
  if (opts.domain)
    cookie += '; Domain=' + opts.domain;
  if (opts.secure)
    cookie += '; Secure';
  if (opts.httpOnly)
    cookie += '; HttpOnly';

  this.resCookies.push(cookie);

  if (opts.maxAge == 0)
    delete this.reqCookies[name];
  else
    this.reqCookies[name] = value;
  this.res.setHeader('Set-Cookie', this.resCookies);
  return this;
};

CryptoCookie.prototype.get = function(name, opts) {
  if (!opts)
    opts = {};

  if (opts.signed) {
    var value = this.reqCookies[name];
    if (!value)
      return undefined;
    var sig = base64url.decode(value.slice(-38));
    value = value.slice(0, -38);
    for (var i = 0; i < this.opts.keys.length; i++) {
      var key = this.opts.keys[i];
      if (crypto.createHmac('sha224', key).update(value).digest().equals(sig))
        return value;
    }
    return undefined;
  } else if (opts.encrypted) {
    try {
      for (var i = 0; i < this.opts.keys.length; i++) {
        var key = this.opts.keys[i];
        var n = base64url.encode(crypto.createHmac('sha224', key).update(name).digest());
        if (this.reqCookies[n]) {
          var data = base64url.decode(this.reqCookies[n]);
          var iv = data.slice(-12);
          var tag = data.slice(-28, -12);
          data = data.slice(0, -28);
          var decip = crypto.createDecipheriv('aes-256-gcm', key, iv);
          decip.setAuthTag(tag);
          return Buffer.concat([decip.update(data), decip.final()]).toString();
        }
      }
      return undefined;
    } catch (e) {
      return undefined;
    }
  }

  return this.reqCookies[name];
};

CryptoCookie.prototype.remove = function(name, opts) {
  if (!opts)
    opts = {};
  opts.maxAge = 0;
  this.set(name, '', opts);
  return this;
};

var base64url = {
  encode: function(buf) {
    return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  },

  decode: function(str) {
    return new Buffer(str.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  }
};

module.exports = CryptoCookie;
