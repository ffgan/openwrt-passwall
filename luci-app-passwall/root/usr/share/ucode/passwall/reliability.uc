'use strict';

// Pure helpers shared by generation and recovery; no network or UCI writes.
export function bounded_integer(value, minimum, maximum, fallback) {
	if (value == null || value == '') return fallback;
	if (match('' + value, /^[0-9]+$/) == null) die('Expected non-negative integer');
	let n = int(value);
	if (n < minimum || n > maximum) die('Integer outside supported range');
	return n;
};

// Home routers cannot spare HAProxy's default pools. maxconn 60000 plus a
// 10k stick table was enough, with the forked health checks, to trip the
// OOM killer on a 256MB device and take DNS with it.
export function haproxy_limits(mem_total_kb, cpus) {
	let mem = int(mem_total_kb);
	if (mem != mem || mem <= 0)
		mem = 262144;
	let threads = int(cpus);
	if (threads != threads || threads < 1)
		threads = 1;
	if (mem < 393216)
		return { maxconn: 1024, server_maxconn: 256, stick_size: 1024, nbthread: 1 };
	if (mem < 1048576) {
		let n = threads > 2 ? 2 : threads;
		return { maxconn: 4096, server_maxconn: 1024, stick_size: 4096, nbthread: n };
	}
	return { maxconn: 16384, server_maxconn: 3000, stick_size: 10000, nbthread: threads };
};

export function chinadns_bind_port(text) {
	let found = match(text ?? '', /(^|\n)bind-port[ \t]+([0-9]+)/);
	if (found == null)
		return '';
	return found[2];
};

// A live command line is not enough: the process can be wedged, or a
// leftover shell can still mention the binary after the listener is gone.
export function chinadns_needs_start(has_process, port, port_open) {
	if (port != null && ('' + port) != '' && !port_open)
		return true;
	return !has_process;
};

// External checks fork ucode and curl. Below this, that fork is what tips
// the OOM killer, so leave the server in the pool instead.
function available_kb(value) {
	if (match('' + (value ?? ''), /^[0-9]+$/) == null)
		return null;
	return int(value);
};

export function skip_external_check(mem_available_kb) {
	let mem = available_kb(mem_available_kb);
	if (mem == null)
		return false;
	return mem < 24576;
};

export function skip_media_probe(mem_available_kb) {
	let mem = available_kb(mem_available_kb);
	if (mem == null)
		return false;
	return mem < 49152;
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
