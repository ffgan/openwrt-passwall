'use strict';

import * as fs from 'fs';
import * as api from 'passwall.api';
import { read_cmd } from 'passwall.proc';
import { peer_recent } from 'passwall.haproxy_pool';
import { meminfo_kb } from 'passwall.text';
import { skip_external_check, skip_media_probe } from 'passwall.reliability';

const ALIVE_DIR = '/tmp/etc/passwall/haproxy/alive';
const MEDIA_DIR = '/tmp/etc/passwall/haproxy/media';
const MEDIA_INTERVAL = 300;
const MEDIA_SIZE = '524288';

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
			"--connect-timeout", "4", "--max-time", "7",
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

// Sample the data path infrequently. Retry a failed sample on each health
// check and require positive evidence from a peer since our first failure.
function media_healthy(server, port, url) {
	if (match(url, /^https:\/\/\S+$/) == null || match(port, /^[0-9]+$/) == null)
		return true;

	let path = MEDIA_DIR + '/' + port;
	let now = time();
	let raw = fs.readfile(path) ?? "";
	let state = split(trim(raw), ' ');
	let stamp = int(state[1] ?? 0);
	let failed_since = state[0] == 'fail' && state[2] == url ? stamp : 0;
	if (state[0] == 'ok' && state[2] == url && now >= stamp && now - stamp < MEDIA_INTERVAL)
		return true;

	let got = read_cmd([
		"/usr/bin/curl", "-q", "-sS", "--noproxy", "",
		"-x", "socks5h://" + server + ":" + port,
		"--connect-timeout", "4", "--max-time", "5", "--max-filesize", MEDIA_SIZE,
		"--range", "0-524287", "-o", "/dev/null", "-w", "%{http_code} %{size_download}", url
	]);
	now = time();
	api.fs.mkdirr(MEDIA_DIR);
	if (got != null && got.rc == 0 && trim(got.out) == "206 " + MEDIA_SIZE) {
		api.fs.writefile(path, sprintf("ok %d %s\n", now, url));
		return true;
	}

	if (failed_since <= 0 || failed_since > now) {
		api.fs.writefile(path, sprintf("fail %d %s\n", now, url));
		return true;
	}

	for (let name in (fs.lsdir(MEDIA_DIR) ?? [])) {
		if (name == port || match(name, /^[0-9]+$/) == null)
			continue;
		let peer = split(trim(fs.readfile(MEDIA_DIR + '/' + name) ?? ""), ' ');
		let success = int(peer[1] ?? 0);
		if (peer[0] == 'ok' && peer[2] == url && success > failed_since &&
		    success <= now && now - success < MEDIA_INTERVAL)
			return false;
	}
	return true;
}

// HAProxy external-check appends proxy address, proxy port, server address, server port.
function mem_available() {
	let text = fs.readfile("/proc/meminfo");
	return meminfo_kb(type(text) == "string" ? text : "", "MemAvailable");
};

main = function(argv) {
	let avail = mem_available();
	// Forking curl here is what pushed the 256MB router into OOM.
	if (skip_external_check(avail))
		exit(0);

	let busy = api.proc_lines("passwall/");
	if (match(busy, /(app|service)\.uc.*(start|stop|restart)|nftables\.uc/) != null)
		exit(0);

	let server = bracket_host(argv[2] ?? "");
	let port = "" + (argv[3] ?? "");
	if (probe(server, port)) {
		mark_alive(port);
		if (skip_media_probe(avail))
			exit(0);
		let media_url = trim(api.uci_get_c("@global_haproxy[0]", "health_media_url") ?? "");
		exit(media_healthy(server, port, media_url) ? 0 : 1);
	}
	// Another exit worked moments ago, so this one can leave the pool.
	// If none did, keep it: a shared timeout must not take the whole network down.
	if (match(port, /^[0-9]+$/) != null && peer_recent(time(), port, load_stamps(), probe_window()))
		exit(1);
	exit(0);
};

export { main };
