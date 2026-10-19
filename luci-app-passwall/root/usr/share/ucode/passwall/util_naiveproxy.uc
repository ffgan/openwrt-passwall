'use strict';

import * as api from 'passwall.api';

function ltruth(v) {
	return v != null && v !== false;
}

function lor(a, b) {
	if (a == null || a === false)
		return b;
	return a;
}

export function gen_config(var) {
	let node_id = var["node"];
	if (node_id == null || node_id === false) {
		print("node 不能为空\n");
		return null;
	}
	let node = api.uci_get_c(node_id);
	let run_type = var["run_type"];
	let local_addr = var["local_addr"];
	let local_port = var["local_port"];
	let server_host = var["server_host"];
	if (server_host == null || server_host === false)
		server_host = lc(lor(node.address, ""));
	let server_port = lor(var["server_port"], node.port);

	if (api.is_ipv6(server_host))
		server_host = api.get_ipv6_full(server_host);
	let server = server_host + ":" + server_port;

	let config = {
		listen: run_type + "://" + local_addr + ":" + local_port,
		proxy: node.protocol + "://" + node.username + ":" + node.password + "@" + server
	};

	return api.jsonc.stringify(config, 1);
}

function print_result(result) {
	if (result == null)
		print("nil\n");
	else if (type(result) == "string")
		print(result, "\n");
	else
		print(api.jsonc.stringify(result, 1), "\n");
}

// argv[0] = gen_config; argv[1] = JSON object string.
export function main(argv) {
	if (argv == null || length(argv) < 1 || argv[0] == null || argv[0] === false)
		return;
	let func = null;
	if (argv[0] == "gen_config")
		func = gen_config;
	if (func == null)
		return;
	let parsed = null;
	if (length(argv) > 1 && argv[1] != null)
		parsed = api.jsonc.parse(argv[1]);
	print_result(func(parsed));
}
