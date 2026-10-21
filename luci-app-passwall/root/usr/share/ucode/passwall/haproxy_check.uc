'use strict';

import * as api from 'passwall.api';
import { popen } from 'fs';

let read_cmd, bracket_host, main;

read_cmd = function(argv) {
	let ph = popen(argv, "r");
	if (ph == null)
		return null;
	let out = "";
	let chunk = ph.read(4096);
	while (chunk != null && chunk != "") {
		out += chunk;
		chunk = ph.read(4096);
	}
	let rc = ph.close();
	return { out: out, rc: rc == null ? 255 : rc };
};

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

// HAProxy external-check appends proxy address, proxy port, server address, server port.
main = function(argv) {
	let busy = read_cmd(["busybox", "pgrep", "-af", "passwall/"]);
	if (busy != null && match(busy.out, /(app|service)\.uc.*(start|stop|restart)|nftables\.uc|iptables\.uc|subscribe\.uc/) != null)
		exit(0);

	let server = bracket_host(argv[2] ?? "");
	let port = argv[3] ?? "";
	let probe = api.get_cache_var("HAPROXY_PROBE_URL");
	if (probe == null || probe == "")
		probe = "https://www.google.com/generate_204";
	let got = read_cmd([
		"/usr/bin/curl", "-q", "-I", "-o", "/dev/null", "-sk", "--noproxy", "",
		"-x", "socks5h://" + server + ":" + port,
		"--connect-timeout", "3", "--max-time", "6",
		"-w", "%{http_code}", probe
	]);
	if (got == null || got.rc != 0)
		exit(1);
	let status = trim(got.out);
	if (status == "200" || status == "204")
		exit(0);
	exit(1);
};

export { main };
