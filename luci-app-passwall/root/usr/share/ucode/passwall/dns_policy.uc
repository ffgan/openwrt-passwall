'use strict';
import * as fs from 'fs';
import { bounded_integer } from 'passwall.reliability';

// Clamp only upper bounds. Never inflate short/zero upstream TTLs or add a
// minimum TTL. Keep the cap below the managed dynamic-set lifetime (2 days).
export function apply_ttl_limits(lines, configured, inherited) {
	inherited = inherited ?? {};
	let cap = bounded_integer(configured, 60, 86400, 3600);
	let cache = cap, client = cap, kept = [];
	for (let line in lines ?? []) {
		let option = match(trim(line), /^(max-cache-ttl|max-ttl)=([0-9]+)$/);
		if (option != null) {
			if (option[1] == 'max-cache-ttl') cache = min(cache, int(option[2]));
			else client = min(client, int(option[2]));
		} else push(kept, line);
	}
	if (inherited['max-cache-ttl'] == null) push(kept, 'max-cache-ttl=' + cache);
	if (inherited['max-ttl'] == null) push(kept, 'max-ttl=' + min(client, cache));
	return kept;
};

// dnsmasq forbids repeating these options across conf-file includes. Leave
// administrator-owned include values intact, even if larger than our cap.
export function inherited_ttl_limits(lines, seen, depth) {
	seen = seen ?? {};
	depth = depth ?? 0;
	let found = {};
	if (depth > 8) die('DNS configuration include depth exceeded');
	for (let line in lines ?? []) {
		let include = match(trim(line), /^conf-file=(\/[^,]+)(,.*)?$/);
		if (include == null || seen[include[1]]) continue;
		let path = include[1];
		seen[path] = true;
		let text = fs.readfile(path);
		if (text == null) continue;
		let nested = split(text, '\n');
		for (let entry in nested) {
			let option = match(trim(entry), /^(max-cache-ttl|max-ttl)=([0-9]+)$/);
			if (option != null) found[option[1]] = int(option[2]);
		}
		for (let key, value in inherited_ttl_limits(nested, seen, depth + 1)) found[key] = value;
	}
	return found;
};
