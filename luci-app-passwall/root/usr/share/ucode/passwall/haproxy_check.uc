'use strict';

import * as fs from 'fs';
import * as api from 'passwall.api';
import { read_cmd } from 'passwall.proc';
import { peer_recent } from 'passwall.haproxy_pool';

const ALIVE_DIR = '/tmp/etc/passwall/haproxy/alive';

let bracket_host, probe_window, load_stamps, mark_alive, probe, main;

bracket_host = function(host) {
	if (host == null)
		return "";
	host = "" + host;
	if (match(host, /^\[.*\]$/) != null)
		return host;
	if (index(host, ":") >= 0)
		return "[" + host + "]";
	return host;
};

probe_window = function() {
	let inter = int(api.uci_get_c('@global_haproxy[0]', 'health_check_inter'));
	if (inter != inter || inter < 20)
		inter = 20;
	let window = inter - 8;
	if (window < 12)
		window = 12;
	return window;
};

load_stamps = function() {
	let stamps = {};
	let names = fs.lsdir(ALIVE_DIR);
	if (names == null)
		return stamps;
	for (let name in names) {
		if (match(name, /^[0-9]+$/) == null)
			continue;
		let raw = fs.readfile(ALIVE_DIR + '/' + name);
		if (type(raw) != 'string')
			continue;
		stamps[name] = int(trim(raw));
	}
	return stamps;
};

mark_alive = function(port) {
	if (match(port, /^[0-9]+$/) == null)
		return;
	api.fs.mkdirr(ALIVE_DIR);
	api.fs.writefile(ALIVE_DIR + '/' + port, '' + time() + '\n');
};

probe = function(server, port) {
	let primary = api.get_cache_var("HAPROXY_PROBE_URL");
	if (primary == null || primary == "")
		primary = "https://www.google.com/generate_204";
	let urls = [[primary, true]];
	let second = "https://www.cloudflare.com/cdn-cgi/trace";
	if (primary != second)
		push(urls, [second, false]);
	for (let item in urls) {
		let args = [
			"/usr/bin/curl", "-q", "-o", "/dev/null", "-sk", "--noproxy", "",
			"-x", "socks5h://" + server + ":" + port,
			"--connect-timeout", "4", "--max-time", "8",
			"-w", "%{http_code}"
		];
		if (item[1])
			push(args, "-I");
		push(args, item[0]);
		let got = read_cmd(args);
		if (got == null || got.rc != 0)
			continue;
		let status = trim(got.out);
		if (status == "200" || status == "204")
			return true;
	}
	return false;
};

// HAProxy external-check appends proxy address, proxy port, server address, server port.
main = function(argv) {
	let busy = api.proc_lines("passwall/");
	if (match(busy, /(app|service)\.uc.*(start|stop|restart)|nftables\.uc/) != null)
		exit(0);

	let server = bracket_host(argv[2] ?? "");
	let port = "" + (argv[3] ?? "");
	if (probe(server, port)) {
		mark_alive(port);
		exit(0);
	}
	// Another exit worked moments ago, so this one can leave the pool.
	// If none did, keep it: a shared timeout must not take the whole network down.
	if (match(port, /^[0-9]+$/) != null && peer_recent(time(), port, load_stamps(), probe_window()))
		exit(1);
	exit(0);
};

export { main };
