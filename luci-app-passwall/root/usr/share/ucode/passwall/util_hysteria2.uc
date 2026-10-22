'use strict';

import * as api from 'passwall.api';
import { truth as ltruth, lua_or as lor, to_number as tonumber, leading_int } from 'passwall.text';
let set_if, obfs_of, bandwidth_of, realm_of, apply_gecko, server_users, server_listen, hop_udp, idle_timeout, keep_alive, auth_pair, gen_config_server, gen_config, print_result, dispatch, main;

set_if = function(obj, key, val) {
	if (val != null)
		obj[key] = val;
};

obfs_of = function(node) {
	if (!(ltruth(node.hysteria2_obfs_type) && ltruth(node.hysteria2_obfs_password)))
		return null;
	let obfs = { type: node.hysteria2_obfs_type };
	obfs[node.hysteria2_obfs_type] = { password: node.hysteria2_obfs_password };
	return obfs;
};

bandwidth_of = function(node) {
	if (!(ltruth(node.hysteria2_up_mbps) || ltruth(node.hysteria2_down_mbps)))
		return null;
	let bw = {};
	if (ltruth(node.hysteria2_up_mbps))
		bw.up = node.hysteria2_up_mbps + " mbps";
	if (ltruth(node.hysteria2_down_mbps))
		bw.down = node.hysteria2_down_mbps + " mbps";
	return bw;
};

realm_of = function(node) {
	if (!(ltruth(node.hysteria2_realms) && ltruth(node.hysteria2_realm_stun)))
		return null;
	let realm = { stunServers: node.hysteria2_realm_stun };
	if (node.hysteria2_realm_upnp === "1")
		realm.portMapping = { enabled: true };
	return realm;
};

apply_gecko = function(config, node) {
	if (config.obfs == null || config.obfs.gecko == null)
		return;
	let min = tonumber(node.hysteria2_obfs_MinPacketSize);
	let max = tonumber(node.hysteria2_obfs_MaxPacketSize);
	if (min == null)
		min = 512;
	if (max == null)
		max = 1200;
	if (min <= 0 || min > max || max > 2048) {
		min = 512;
		max = 1200;
	}
	config.obfs.gecko.minPacketSize = min;
	config.obfs.gecko.maxPacketSize = max;
};

server_users = function(node) {
	if (!(ltruth(node.users) && length(node.users) > 0))
		return null;
	let users = {};
	for (let v in node.users) {
		let user = api.uci_get_s(v);
		if (user == null || user === false)
			user = {};
		if (user[".type"] == "user")
			users[user.username] = user.password;
	}
	if (length(users) == 0)
		return null;
	return users;
};

server_listen = function(node) {
	if (ltruth(node.hysteria2_realms) && ltruth(node.hysteria2_realm_url)) {
		let url = replace(node.hysteria2_realm_url, /\/+$/, "");
		if (ltruth(node.port))
			url = url + (index(url, "?") >= 0 ? "&lport=" : "?lport=") + node.port;
		return url;
	}
	let port = node.port;
	if (port == null || port === false)
		port = "0";
	return ":" + port;
};

hop_udp = function(node) {
	if (!ltruth(node.hysteria2_hop))
		return null;
	let t = node.hysteria2_hop_interval;
	if (t == null || t === false)
		return null;
	let udp = {};
	if (index("" + t, "-") >= 0) {
		let mm = match("" + t, /^([0-9]+)-([0-9]+)$/);
		if (mm != null) {
			let min = tonumber(mm[1]);
			let max = tonumber(mm[2]);
			if (min != null && max != null) {
				min = (min >= 5) ? min : 5;
				max = (max >= min) ? max : min;
				udp.minHopInterval = min + "s";
				udp.maxHopInterval = max + "s";
				return udp;
			}
		}
	}
	let n = leading_int(lor(t, "30"));
	n = (n != null && n >= 5) ? n : 30;
	udp.hopInterval = n + "s";
	return udp;
};

idle_timeout = function(t) {
	if (t == null || t === false)
		t = "30";
	let n = leading_int(t);
	return (n != null && n >= 4 && n <= 120) ? (n + "s") : "30s";
};

keep_alive = function(t) {
	if (t == null || t === false)
		t = "0";
	let n = leading_int(t);
	if (n != null && n >= 2 && n <= 60)
		return n + "s";
	return null;
};

auth_pair = function(user, pass) {
	if (ltruth(user) && ltruth(pass))
		return [user, pass];
	return [null, null];
};

gen_config_server = function(node) {
	let users = server_users(node);
	let config = {
		listen: server_listen(node),
		tls: {
			cert: node.tls_certificateFile,
			key: node.tls_keyFile
		},
		ignoreClientBandwidth: node.hysteria2_ignoreClientBandwidth === "1",
		disableUDP: node.hysteria2_udp === "0"
	};
	set_if(config, "obfs", obfs_of(node));
	if (users != null)
		config.auth = { type: "userpass", userpass: users };
	set_if(config, "bandwidth", bandwidth_of(node));
	set_if(config, "realm", realm_of(node));
	if (ltruth(node.ech_keyFile) && node.ech_keyFile != "")
		config.ech = { keyPath: node.ech_keyFile };
	apply_gecko(config, node);
	return config;
};

gen_config = function(var) {
	let node_id = var["node"];
	if (node_id == null || node_id === false) {
		print("node 不能为空\n");
		return null;
	}
	let node = api.uci_get_c(node_id);
	let local_redir_port = var["local_redir_port"];
	let local_socks_address = lor(var["local_socks_address"], "0.0.0.0");
	let local_socks_port = var["local_socks_port"];
	let local_socks_username = var["local_socks_username"];
	let local_socks_password = var["local_socks_password"];
	let local_http_address = lor(var["local_http_address"], "0.0.0.0");
	let local_http_port = var["local_http_port"];
	let local_http_username = var["local_http_username"];
	let local_http_password = var["local_http_password"];
	let tcp_proxy_way = var["tcp_proxy_way"];
	let server_host = var["server_host"];
	if (server_host == null || server_host === false)
		server_host = lc(lor(node.address, ""));
	let server_port = lor(var["server_port"], node.port);

	if (api.is_ipv6(server_host))
		server_host = api.get_ipv6_full(server_host);

	let port_hop = lor(server_port, "") + "," + lor(node.hysteria2_hop, "");
	port_hop = replace(port_hop, /^[[:space:],]+/, "");
	port_hop = replace(port_hop, /[[:space:],]+$/, "");
	port_hop = replace(port_hop, ":", "-");
	let server = server_host + ":" + (port_hop != "" ? port_hop : "443");

	let server_value = server;
	if (ltruth(node.hysteria2_realms) && ltruth(node.hysteria2_realm_url))
		server_value = replace(node.hysteria2_realm_url, /\/+$/, "");

	let tls = { insecure: node.tls_allowInsecure === "1" };
	set_if(tls, "sni", node.tls_serverName);
	if (ltruth(node.tls_pinSHA256) && node.tls_pinSHA256 != "")
		tls.pinSHA256 = api.sha256_sb_xray(node.tls_pinSHA256);
	if (node.ech === "1" && node.ech_config != null && node.ech_config !== false)
		tls.ech = node.ech_config;

	let quic = {
		maxIdleTimeout: idle_timeout(node.hysteria2_idle_timeout),
		disablePathMTUDiscovery: ltruth(node.hysteria2_disable_mtu_discovery)
	};
	let stream_win = tonumber(node.hysteria2_stream_recv_win);
	if (stream_win != null)
		quic.initStreamReceiveWindow = stream_win * 1048576;
	let conn_win = tonumber(node.hysteria2_conn_recv_win);
	if (conn_win != null)
		quic.initConnReceiveWindow = conn_win * 1048576;
	set_if(quic, "keepAlivePeriod", keep_alive(node.hysteria2_keep_alive_period));

	let config = {
		server: server_value,
		transport: {
			type: "udp"
		},
		tls: tls,
		quic: quic,
		fast_open: node.fast_open === "1",
		lazy: node.hysteria2_lazy_start === "1"
	};
	set_if(config, "realm", realm_of(node));
	set_if(config.transport, "udp", hop_udp(node));
	set_if(config, "obfs", obfs_of(node));
	set_if(config, "auth", node.hysteria2_auth_password);
	set_if(config, "bandwidth", bandwidth_of(node));

	if (ltruth(local_socks_address) && ltruth(local_socks_port)) {
		let socks = {
			listen: local_socks_address + ":" + local_socks_port,
			disableUDP: false
		};
		let pair = auth_pair(local_socks_username, local_socks_password);
		set_if(socks, "username", pair[0]);
		set_if(socks, "password", pair[1]);
		config.socks5 = socks;
	}
	if (ltruth(local_http_address) && ltruth(local_http_port)) {
		let http = { listen: local_http_address + ":" + local_http_port };
		let pair = auth_pair(local_http_username, local_http_password);
		set_if(http, "username", pair[0]);
		set_if(http, "password", pair[1]);
		config.http = http;
	}
	if (tcp_proxy_way === "redirect" && ltruth(local_redir_port))
		config.tcpRedirect = { listen: "0.0.0.0:" + local_redir_port };
	if (tcp_proxy_way === "tproxy" && ltruth(local_redir_port))
		config.tcpTProxy = { listen: "0.0.0.0:" + local_redir_port };
	if (ltruth(local_redir_port))
		config.udpTProxy = { listen: "0.0.0.0:" + local_redir_port };

	apply_gecko(config, node);
	return api.jsonc.stringify(config, 1);
};

print_result = function(result) {
	if (result == null)
		print("nil\n");
	else if (type(result) == "string")
		print(result, "\n");
	else
		print(api.jsonc.stringify(result, 1), "\n");
};

dispatch = function(name) {
	if (name == "gen_config")
		return gen_config;
	if (name == "gen_config_server")
		return gen_config_server;
	return null;
};

// argv[0] = gen_config | gen_config_server; argv[1] = JSON object string.
main = function(argv) {
	if (argv == null || length(argv) < 1 || argv[0] == null || argv[0] === false)
		return;
	let func = dispatch(argv[0]);
	if (func == null)
		return;
	let parsed = null;
	if (length(argv) > 1 && argv[1] != null)
		parsed = api.jsonc.parse(argv[1]);
	print_result(func(parsed));
};
export { gen_config_server, gen_config, main };
