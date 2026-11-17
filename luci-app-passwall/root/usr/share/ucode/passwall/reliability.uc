'use strict';

// Pure helpers shared by generation and recovery; no network or UCI writes.
export function bounded_integer(value, minimum, maximum, fallback) {
	if (value == null || value == '') return fallback;
	if (match('' + value, /^[0-9]+$/) == null) die('Expected non-negative integer');
	let n = int(value);
	if (n < minimum || n > maximum) die('Integer outside supported range');
	return n;
};

export function retry_delay(failures) {
	let delay = 5;
	for (let i = 1; i < failures && delay < 300; i++) delay *= 2;
	return delay > 300 ? 300 : delay;
};

export function valid_address(value, ipv6) {
	let parts = split(value, '/');
	if (length(parts) > 2) return false;
	if (length(parts) == 2 && (match(parts[1], /^[0-9]+$/) == null || int(parts[1]) > (ipv6 ? 128 : 32))) return false;
	let address = parts[0];
	if (!ipv6) {
		let octets = split(address, '.');
		if (length(octets) != 4) return false;
		for (let octet in octets)
			if (match(octet, /^(0|[1-9][0-9]{0,2})$/) == null || int(octet) > 255) return false;
		return true;
	}
	if (match(address, /^[0-9A-Fa-f:]+$/) == null) return false;
	let halves = split(address, '::');
	if (length(halves) > 2) return false;
	let groups = 0;
	for (let half in halves) {
		if (half == '') continue;
		for (let group in split(half, ':')) {
			if (match(group, /^[0-9A-Fa-f]{1,4}$/) == null) return false;
			groups++;
		}
	}
	return length(halves) == 2 ? groups < 8 : groups == 8;
};
