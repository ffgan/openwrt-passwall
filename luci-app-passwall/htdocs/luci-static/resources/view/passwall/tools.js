'use strict';
'require baseclass';
'require dom';
'require fs';
'require rpc';
'require uci';
'require ui';
'require validation';

function isJsonText(str) {
	try {
		var result = JSON.parse(str);
		return typeof result === 'object' && result !== null;
	}
	catch (e) {
		return false;
	}
}

function isTimeHHMM(str) {
	var match = String(str).match(/^(\d?\d):(\d\d)$/);
	if (!match)
		return false;
	var hour = parseInt(match[1], 10);
	var minute = parseInt(match[2], 10);
	return hour >= 0 && hour <= 23 && minute >= 0 && minute <= 59;
}

function isBase64(str) {
	return /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$/.test(str);
}

function isUUID(str) {
	return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(str);
}

function installValidators() {
	if (!validation.types.base64)
		validation.types.base64 = function() {
			return this.assert(isBase64(this.value), _('Must be Base64 text!'));
		};
	if (!validation.types.json)
		validation.types.json = function() {
			return this.assert(isJsonText(this.value), _('Must be JSON text!'));
		};
	if (!validation.types.timehhmm)
		validation.types.timehhmm = function() {
			return this.assert(isTimeHHMM(this.value), _('valid time (hh:mm)'));
		};
	if (!validation.types.uuid)
		validation.types.uuid = function() {
			return this.assert(isUUID(this.value), _('Must be UUID format!'));
		};
}

function installTheme() {
	if (typeof document === 'undefined' || !document.head || document.getElementById('pw-theme'))
		return;
	var link = document.createElement('link');
	link.id = 'pw-theme';
	link.rel = 'stylesheet';
	link.href = L.resource('view/passwall/passwall.css');
	document.head.appendChild(link);
}

installValidators();
installTheme();

return baseclass.extend({
	__init__: function() {
		installValidators();
		installTheme();
	},

	appname: 'passwall',

	call: function(method, params) {
		params = params || {};
		var keys = [];
		var vals = [];
		Object.keys(params).forEach(function(key) {
			if (params[key] == null)
				return;
			keys.push(key);
			vals.push(String(params[key]));
		});
		var fn = rpc.declare({
			object: 'luci.passwall',
			method: method,
			params: keys
		});
		return fn.apply(null, vals);
	},

	unwrap: function(res) {
		if (res && typeof res === 'object' && typeof res.output === 'string')
			return res.output;
		return res;
	},

	pageUrl: function(page) {
		var parts = [ 'admin', 'services', 'passwall' ];
		for (var i = 0; i < arguments.length; i++)
			if (arguments[i] != null && arguments[i] !== '')
				parts.push(String(arguments[i]));
		return L.url.apply(L, parts);
	},

	routeArg: function() {
		var req = L.env.requestpath || [];
		var disp = L.env.dispatchpath || [];
		if (req.length > disp.length)
			return decodeURIComponent(req[req.length - 1]);
		return null;
	},

	sectionId: function(config, type) {
		var list = uci.sections(config, type) || [];
		return list.length ? list[0]['.name'] : null;
	},

	rand: function(length) {
		var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
		var out = '';
		length = length || 8;
		for (var i = 0; i < length; i++)
			out += chars.charAt(Math.floor(Math.random() * chars.length));
		return out;
	},

	parseBody: function(x) {
		var text = (x && (x.responseText || x.response)) || '';
		if (typeof text !== 'string')
			text = String(text || '');
		if (!text)
			return text;
		try {
			return JSON.parse(text);
		}
		catch (e) {
			return text;
		}
	},

	get: function(action, params) {
		var self = this;
		return this.call(action, params).then(function(res) {
			return self.unwrap(res);
		});
	},

	post: function(action, params) {
		return this.get(action, params);
	},

	loadCaps: function() {
		var self = this;
		if (self._caps)
			return Promise.resolve(self._caps);
		return self.get('capabilities').then(function(data) {
			self._caps = data || {};
			return self._caps;
		});
	},

	readText: function(path) {
		return fs.read(path).then(function(v) {
			return v || '';
		}).catch(function() {
			return '';
		});
	},

	writeText: function(path, value) {
		return fs.write(path, String(value == null ? '' : value).replace(/\r\n/g, '\n'));
	},

	bindReload: function(root, selector, saveFn) {
		var nodes = root.querySelectorAll(selector);
		nodes.forEach(function(el) {
			el.addEventListener('change', function() {
				var pending = saveFn ? saveFn() : Promise.resolve();
				Promise.resolve(pending).then(function() {
					window.location.reload();
				}).catch(function(err) {
					ui.addNotification(null, E('p', {}, err.message || String(err)));
				});
			});
		});
	},

	applyGroups: function(select, items, placeholder) {
		if (!select)
			return;
		var current = select.value;
		while (select.firstChild)
			select.removeChild(select.firstChild);
		if (placeholder)
			select.appendChild(E('option', { value: placeholder.value }, placeholder.label));
		var groups = {};
		var order = [];
		(items || []).forEach(function(it) {
			var g = it.group || _('default');
			if (!groups[g]) {
				groups[g] = [];
				order.push(g);
			}
			groups[g].push(it);
		});
		order.forEach(function(g) {
			var og = E('optgroup', { label: g });
			groups[g].forEach(function(it) {
				og.appendChild(E('option', { value: it.value }, it.label));
			});
			select.appendChild(og);
		});
		if (current)
			select.value = current;
	},

	fillValues: function(option, pairs) {
		(pairs || []).forEach(function(pair) {
			option.value(pair[0], pair[1]);
		});
		return option;
	},

	weekMode: function(option, withLoop) {
		option.value('', _('Disable'));
		if (withLoop)
			option.value('8', _('Loop Mode'));
		option.value('7', _('Every day'));
		option.value('1', _('Every Monday'));
		option.value('2', _('Every Tuesday'));
		option.value('3', _('Every Wednesday'));
		option.value('4', _('Every Thursday'));
		option.value('5', _('Every Friday'));
		option.value('6', _('Every Saturday'));
		option.value('0', _('Every Sunday'));
		return option;
	},

	portPresets: function(option) {
		option.value('disable', _('No patterns are used'));
		option.value('1:65535', _('All'));
		return option;
	},

	normalizePorts: function(value) {
		return String(value || '').replace(/-/g, ':');
	}
});
