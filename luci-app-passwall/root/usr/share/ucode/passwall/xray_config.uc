'use strict';

// No API/UCI dependency: the same merge policy is used by generation and RPC.
function fail(path, reason) {
	die("Xray JSON " + path + ": " + reason);
}
function copy(value) { return json(sprintf('%J', value)); }
function equal(a, b) {
	if (type(a) != type(b)) return false;
	if (type(a) == 'object' || type(a) == 'array') {
		if (length(a) != length(b)) return false;
		for (let key, value in a)
			if ((type(b) == 'object' && !exists(b, key)) || !equal(value, b[key])) return false;
		return true;
	}
	return a === b;
}
function object(value) { return type(value) == 'object'; }

function merge(base, patch) {
	if (!object(base) || !object(patch)) return copy(patch);
	let result = copy(base);
	for (let key, value in patch)
		result[key] = exists(base, key) ? merge(base[key], value) : copy(value);
	return result;
}

// A managed value may be repeated, or extended with new object properties.
function protect(base, patch, path) {
	if (object(base) && object(patch)) {
		for (let key, value in patch)
			if (exists(base, key)) protect(base[key], value, path + '.' + key);
	}
	else if (!equal(base, patch)) fail(path, 'managed by PassWall');
}

function tagged(items, path) {
	if (type(items) != 'array') fail(path, 'expected array');
	let tags = {};
	for (let i, item in items) {
		if (!object(item) || type(item.tag) != 'string' || trim(item.tag) == '')
			fail(path + '[' + i + '].tag', 'expected nonempty tag');
		if (exists(tags, item.tag)) fail(path + '[' + i + '].tag', 'duplicate tag');
		tags[item.tag] = true;
	}
}

function endpoints(base, patch, path, server) {
	tagged(base, path);
	tagged(patch, path);
	let result = copy(base);
	for (let item in patch) {
		let found = false;
		for (let i, old in base) {
			if (old.tag != item.tag) continue;
			found = true;
			let at = path + '[' + i + ']';
			if (path == '$.inbounds' && !server) protect(old, item, at);
			else {
				for (let key in ['tag', 'protocol', 'listen', 'port', 'proxySettings'])
					if (exists(old, key) && exists(item, key)) protect(old[key], item[key], at + '.' + key);
				let sock = old.streamSettings?.sockopt;
				let psock = item.streamSettings?.sockopt;
				if (sock != null && exists(item, 'streamSettings') && !object(item.streamSettings)) fail(at + '.streamSettings', 'managed socket settings');
				if (sock != null && object(item.streamSettings) && exists(item.streamSettings, 'sockopt') && !object(psock)) fail(at + '.streamSettings.sockopt', 'managed socket settings');
				if (sock != null && psock != null)
					for (let key in ['mark', 'dialerProxy'])
						if (exists(sock, key) && exists(psock, key)) protect(sock[key], psock[key], at + '.streamSettings.sockopt.' + key);
			}
			result[i] = merge(old, item);
			break;
		}
		if (!found) {
			let added = copy(item);
			if (path == '$.outbounds' && !server && added.protocol != 'blackhole' && added.protocol != 'dns' && added.protocol != 'loopback' && added.protocol != 'wireguard') {
				if (added.streamSettings == null) added.streamSettings = {};
				if (added.streamSettings.sockopt == null) added.streamSettings.sockopt = {};
				if (exists(added.streamSettings.sockopt, 'mark') && added.streamSettings.sockopt.mark != 255) fail(path, 'custom outbound must use bypass mark 255');
				added.streamSettings.sockopt.mark = 255;
			}
			push(result, added);
		}
	}
	return result;
}

function visit(tag, edges, active, done) {
	if (active[tag]) fail('$.outbounds', 'cyclic outbound proxy chain');
	if (done[tag]) return;
	active[tag] = true;
	for (let next in edges[tag] ?? []) visit(next, edges, active, done);
	delete active[tag];
	done[tag] = true;
}

function references(config) {
	let outs = {}, ins = {}, balancers = {};
	for (let item in config.outbounds ?? []) {
		outs[item.tag] = true;
		if (item.protocol == 'loopback' && item.settings?.inboundTag != null) ins[item.settings.inboundTag] = true;
	}
	for (let item in config.inbounds ?? []) ins[item.tag] = true;
	if (config.api?.tag != null) outs[config.api.tag] = true;
	for (let item in config.reverse?.bridges ?? []) ins[item.tag] = true;
	for (let item in config.reverse?.portals ?? []) outs[item.tag] = true;
	for (let item in config.routing?.balancers ?? []) {
		if (type(item.tag) != 'string' || exists(balancers, item.tag)) fail('$.routing.balancers', 'missing or duplicate tag');
		balancers[item.tag] = true;
	}
	let edges = {};
	for (let i, item in config.outbounds ?? []) {
		edges[item.tag] = [];
		for (let tag in [item.proxySettings?.tag, item.streamSettings?.sockopt?.dialerProxy]) {
			if (tag != null && !exists(outs, tag)) fail('$.outbounds[' + i + ']', 'unknown outbound reference');
			if (tag != null) push(edges[item.tag], tag);
		}

	}
	let active = {}, done = {};
	for (let tag in keys(edges)) visit(tag, edges, active, done);
	for (let item in config.routing?.balancers ?? [])
		if (item.fallbackTag != null && !exists(outs, item.fallbackTag)) fail('$.routing.balancers', 'unknown fallback outbound');
	for (let i, rule in config.routing?.rules ?? []) {
		let at = '$.routing.rules[' + i + ']';
		if (rule.outboundTag != null && !exists(outs, rule.outboundTag)) fail(at + '.outboundTag', 'unknown outbound');
		if (rule.balancerTag != null && !exists(balancers, rule.balancerTag)) fail(at + '.balancerTag', 'unknown balancer');
		for (let tag in rule.inboundTag ?? [])
			if (!exists(ins, tag) && tag != config.api?.tag && tag != config.dns?.tag)
				fail(at + '.inboundTag', 'unknown inbound');
	}
}

export function merge_config(base, patch, server) {
	if (!object(base) || !object(patch)) fail('$', 'expected JSON object');
	let result = copy(base);
	for (let key, value in patch) {
		let at = '$.' + key;
		if (key == 'inbounds' || key == 'outbounds')
			result[key] = endpoints(base[key] ?? [], value, at, server);
		else if (key == 'routing') {
			if (!object(value)) fail(at, 'expected object');
			let rest = copy(value);
			delete rest.rules;
			delete rest.balancers;
			if (base.routing != null) protect(base.routing, rest, at);
			result.routing = merge(base.routing ?? {}, rest);
			if (exists(value, 'balancers')) {
				tagged(value.balancers, at + '.balancers');
				result.routing.balancers = copy(base.routing?.balancers ?? []);
				for (let item in value.balancers) {
					let found = false;
					for (let i, old in result.routing.balancers) {
						if (old.tag != item.tag) continue;
						protect(old, item, at + '.balancers[' + i + ']');
						result.routing.balancers[i] = merge(old, item);
						found = true;
						break;
					}
					if (!found) push(result.routing.balancers, copy(item));
				}
			}
			if (exists(value, 'rules')) {
				if (type(value.rules) != 'array') fail(at + '.rules', 'expected array');
				result.routing.rules = copy(base.routing?.rules ?? []);
				for (let rule in value.rules) push(result.routing.rules, copy(rule));
			}
		}
		else if (key == 'dns' && object(base.dns) && object(value)) {
			let rest = copy(value);
			delete rest.servers;
			protect(base.dns, rest, at);
			result.dns = merge(base.dns, rest);
			if (exists(value, 'servers')) {
				if (type(value.servers) != 'array') fail(at + '.servers', 'expected array');
				result.dns.servers = copy(base.dns.servers ?? []);
				for (let item in value.servers) {
					let found = false;
					for (let old in result.dns.servers) if (equal(old, item)) found = true;
					if (!found) push(result.dns.servers, copy(item));
				}
			}
		}
		else if (key == 'dns' || key == 'fakedns' || key == 'version' || key == 'reverse') {
			if (exists(base, key)) protect(base[key], value, at);
			result[key] = exists(base, key) ? merge(base[key], value) : copy(value);
		}
		else result[key] = exists(base, key) ? merge(base[key], value) : copy(value);
	}
	references(result);
	return result;
};

export function apply_config(base, settings, server) {
	if (settings.json_merge != '1') return base;
	let patch;
	try { patch = json(settings.json_config ?? '{}'); }
	catch (e) { fail('$', 'invalid JSON'); }
	return merge_config(base, patch, server);
};
