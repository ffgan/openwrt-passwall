'use strict';
'require baseclass';

function takeObject(text) {
	try {
		var obj = JSON.parse(text);
		if (obj && typeof obj === 'object' && !Array.isArray(obj))
			return obj;
	}
	catch (e) {}
	return null;
}

function fillJson(map, obj) {
	Object.keys(obj).forEach(function(key) {
		if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key))
			return;
		if (obj[key] == null || obj[key] === '')
			return;
		map[key] = String(obj[key]);
	});
}

function fillLegacy(map, text) {
	String(text || '').split('\n').forEach(function(line) {
		var found = line.match(/^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/);
		if (!found)
			return;
		var val = found[2];
		if (val.length >= 2 && val.charAt(0) === "'" && val.charAt(val.length - 1) === "'")
			val = val.substring(1, val.length - 1).replace(/'\\''/g, "'");
		if (val !== '')
			map[found[1]] = val;
	});
}

function parseCache(text) {
	var raw = String(text || '').replace(/^\uFEFF/, '').trim();
	var map = {};
	if (raw.charAt(0) === '{') {
		var obj = takeObject(raw);
		var rest = '';
		if (!obj) {
			var nl = raw.indexOf('\n');
			if (nl >= 0) {
				obj = takeObject(raw.slice(0, nl));
				rest = raw.slice(nl + 1);
			}
		}
		if (obj) {
			fillJson(map, obj);
			fillLegacy(map, rest);
			return map;
		}
	}
	fillLegacy(map, text);
	return map;
}

return baseclass.extend({
	parseCache: parseCache
});
