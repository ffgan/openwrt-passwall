'use strict';

import * as api from 'passwall.api';
import { read_cmd } from 'passwall.proc';

let bracket_host, main;

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
	let busy = api.proc_lines("passwall/");
	if (match(busy, /(app|service)\.uc.*(start|stop|restart)|nftables\.uc/) != null)
		exit(0);

	let server = bracket_host(argv[2] ?? "");
	let port = argv[3] ?? "";
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
			"--connect-timeout", "2", "--max-time", "3",
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
			exit(0);
	}
	exit(1);
};

export { main };
