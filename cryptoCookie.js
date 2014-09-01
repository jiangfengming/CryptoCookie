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
			this.reqCookies[c[0]] = decodeURIComponent(c[1]);
		}
	}
}

cryptoCookie.prototype.set = function(name, value, opts) {
	if (!opts)
		opts = {};

	if (opts.encrypt) {
		var key = this.keys[0];

		name = crypto.createHmac('md5', key).update(name).digest('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

		var iv = new Buffer(this.ivSize / 8);
		for (var i = this.ivSize / 8 - 1; i >= 0; i--)
			iv[i] = Math.floor(256 * Math.random());

		var cip = crypto.createCipheriv(this.algorithm, key, iv);
		var secret = Buffer.concat([cip.update(value), cip.final()]);
		value = (iv.toString('base64') + secret.toString('base64')).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
	}

	var cookie = name + '=' + encodeURIComponent(value) + ';';

	if (opts.expires) {
		var expires;
		if (opts.expires.constructor == Date)
			expires = opts.expires.toUTCString();
		else if (opts.expires.constructor == Number)
			expires = new Date(opts.expires).toUTCString();
		else
			expires = opts.expires;
		cookie += ' expires=' + expires + ';';
	}

	if (opts.path)
		cookie += ' path=' + opts.path + ';';
	if (opts.domain)
		cookie += ' domain=' + opts.domain + ';';
	if (opts.secure)
		cookie += ' Secure;';
	if (opts.httpOnly)
		cookies += ' HttpOnly;';

	this.resCookies.push(cookie);
	this.res.setHeader('Set-Cookie', this.resCookies);
};

cryptoCookie.prototype.get = function(name, encrypted) {
	if (!encrypted)
		return this.reqCookies[name];

	for (var i = 0; i < this.keys.length; i++) {
		var key = this.keys[i];
		var n = crypto.createHmac('md5', key).update(name).digest('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
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

cryptoCookie.prototype.delete = function(name, opts) {
	if (!opts)
		opts = {};
	opts.expires = 1;
	this.set(name, '', opts);
};

module.exports = cryptoCookie;