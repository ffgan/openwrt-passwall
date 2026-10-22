'use strict';

import * as api from 'passwall.api';
import * as fs from 'fs';
import { parse_nft_state } from 'passwall.state';

const TABLE = "inet passwall";
const MARK = "0x50535731";
const TMP = "/tmp/etc/passwall";
const RULES = "/usr/share/passwall/rules";
const USER_RULES = "/etc/passwall/rules";
const LIBEXEC = "/usr/libexec/passwall/nftables.uc";

let env = {};
let pending = [];
// ucode 2026.01.16 does not hoist functions. Names used before their
// definition have to be declared up front.
let wan_addresses, add_icmp_rules, flush_table;

function run(argv, quiet) {
	let rc;
	if (type(global.system) == "function")
		rc = global.system(argv);
	else {
		let p = api.command_pipe(argv, "r");
		rc = p == null ? 255 : p.close();
	}
	if (rc == null)
		rc = 255;
	if (rc != 0 && !quiet)
		api.log("命令执行失败 (" + rc + "): " + join(" ", argv));
	return rc;
}

function output(argv) {
	let p = api.command_pipe(argv, "r");
	if (p == null)
		return "";
	let data = p.read("all") ?? "";
	p.close();
	return data;
}

function shell_join(argv) {
	let parts = [];
	for (let arg in argv)
		push(parts, api.shellquote(arg));
	return join(" ", parts);
}

function quiet_status(argv) {
	let p = api.command_pipe(shell_join(argv) + " >/dev/null 2>&1", "r");
	if (p == null)
		return 255;
	let rc = p.close();
	return rc == null ? 255 : rc;
}

function quiet_output(argv) {
	let p = api.command_pipe(shell_join(argv) + " 2>/dev/null", "r");
	if (p == null)
		return "";
	let data = p.read("all") ?? "";
	p.close();
	return data;
}

function exists(path) {
	return fs.stat(path) != null;
}

function read(path) {
	return fs.readfile(path) ?? "";
}

function write(path, data) {
	return fs.writefile(path, data);
}

function lines(data) {
	let out = [];
	for (let line in split(replace(data ?? "", /\r/g, ""), "\n")) {
		line = trim(line);
		if (line != "")
			push(out, line);
	}
	return out;
}

function words(data) {
	let out = [];
	for (let value in split(trim(data ?? ""), /[[:space:]]+/))
		if (value != "")
			push(out, value);
	return out;
}

function load_env() {
	let data = read(TMP + "/nft.json");
	if (trim(data) == "")
		data = read(TMP + "/nft.env");
	env = parse_nft_state(data);
}

function e(name, fallback) {
	let value = env[name];
	return value == null ? (fallback ?? "") : value;
}

function cfg(section, option, fallback) {
	let value = api.uci_get_c(section, option);
	return value == null ? (fallback ?? "") : "" + value;
}

function include_path() {
	let path = trim(output(["uci", "-q", "get", "firewall.passwall.path"]));
	return path == "" ? "/tmp/etc/passwall.include" : path;
}

function log(message) {
	api.log(message);
}

function quote_comment(value) {
	return "\"" + replace(replace("" + value, /\\/g, "\\\\"), /"/g, "\\\"") + "\"";
}

function nft(command) {
	push(pending, command);
}

function nft_flush(quiet) {
	if (!length(pending))
		return 0;
	let path = TMP + "/nft.batch";
	let script = "";
	for (let command in pending)
		script += command + "\n";
	pending = [];
	write(path, script);
	return run(["nft", "-f", path], quiet);
}

function nft_now(command, quiet) {
	nft(command);
	return nft_flush(quiet);
}

function nft_output(argv) {
	nft_flush(true);
	return output(["nft", ...argv]);
}

function table_exists() {
	return quiet_status(["nft", "list", "table", "inet", "passwall"]) == 0;
}

function set_exists(name) {
	nft_flush(true);
	return quiet_status(["nft", "list", "set", "inet", "passwall", name]) == 0;
}

function ensure_table() {
	if (table_exists())
		return;
	nft("add table inet passwall");
	nft("add chain inet passwall dstnat { type nat hook prerouting priority dstnat - 1; policy accept; }");
	nft("add chain inet passwall mangle_prerouting { type filter hook prerouting priority mangle - 1; policy accept; }");
	nft("add chain inet passwall mangle_output { type route hook output priority mangle - 1; policy accept; }");
	nft("add chain inet passwall nat_output { type nat hook output priority -1; policy accept; }");
	nft_flush(false);
}

function ensure_set(name, addr_type, timeout) {
	if (set_exists(name))
		return;
	let spec = "add set " + TABLE + " " + name + " { type " + addr_type + "; flags interval";
	if (timeout != "0")
		spec += ", timeout; timeout " + timeout + "; gc-interval 1h";
	spec += "; auto-merge; }";
	nft(spec);
}

function add_elements(name, values) {
	let unique = {};
	let batch = [];
	for (let value in values) {
		value = trim(value);
		if (value == "" || unique[value])
			continue;
		unique[value] = true;
		push(batch, value);
		if (length(batch) == 500) {
			nft("add element " + TABLE + " " + name + " { " + join(", ", batch) + " }");
			batch = [];
		}
	}
	if (length(batch))
		nft("add element " + TABLE + " " + name + " { " + join(", ", batch) + " }");
}

function file_addresses(path, ipv6) {
	let out = [];
	for (let line in lines(read(path))) {
		line = trim(replace(line, /#.*/, ""));
		if (line == "")
			continue;
		if ((index(line, ":") >= 0) == ipv6)
			push(out, line);
	}
	return out;
}

function interface_addresses(family) {
	let out = [];
	let args = ["ip", "-o", family == 6 ? "-6" : "-4", "addr", "show", "scope", "global"];
	for (let line in lines(output(args))) {
		let fields = split(line, /[[:space:]]+/);
		if (length(fields) < 4)
			continue;
		let address = split(fields[3], "/")[0];
		if (address != null && address != "")
			push(out, address);
	}
	return out;
}

function resolve_host(family, host, count) {
	if (host == null || host == "")
		return "";
	host = replace(replace("" + host, /^\[/, ""), /\]$/, "");
	if ((family == 6 && index(host, ":") >= 0) ||
	    (family == 4 && match(host, /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) != null))
		return host;
	let resolved = lines(output(["resolveip", family == 6 ? "-6" : "-4", "-t", "" + (count ?? 3), host]));
	return length(resolved) ? resolved[0] : "";
}

function geoview_bin() {
	let configured = cfg("@global_app[0]", "geoview_file");
	for (let path in [configured, "/usr/bin/geoview", "/bin/geoview", TMP + "/bin/geoview"])
		if (path != "" && exists(path))
			return path;
	return "";
}

function geoip_addresses(codes, family) {
	if (cfg("@global_rules[0]", "enable_geoview", "0") != "1")
		return [];
	let bin = geoview_bin();
	let asset = cfg("@global_rules[0]", "v2ray_location_asset", "/usr/share/v2ray/");
	let input = replace(asset, /\/+$/, "") + "/geoip.dat";
	if (bin == "" || !exists(input) || !length(codes))
		return [];
	let unique = {};
	for (let code in codes)
		if (code != "" && code != "private")
			unique[code] = true;
	let list = join(",", keys(unique));
	if (list == "")
		return [];
	let output_path = "/tmp/etc/passwall_tmp/geo_output/geoip-" + replace(list, /[^A-Za-z0-9_.-]/g, "_") + "-" + family;
	run(["mkdir", "-p", "/tmp/etc/passwall_tmp/geo_output"], true);
	if (!exists(output_path)) {
		let argv = [bin, "-input", input, "-list", list];
		push(argv, family == 6 ? "-ipv4=false" : "-ipv6=false");
		push(argv, "-lowmem=true", "-output", output_path);
		run(argv, true);
	}
	return file_addresses(output_path, family == 6);
}

function list_file_data(path) {
	let ip4 = [], ip6 = [], geo = [];
	for (let value in lines(read(path))) {
		value = trim(replace(value, /#.*/, ""));
		if (value == "")
			continue;
		if (substr(value, 0, 6) == "geoip:")
			push(geo, substr(value, 6));
		else
			push(index(value, ":") >= 0 ? ip6 : ip4, value);
	}
	return [ip4, ip6, geo];
}

function factor(ports, expression) {
	if (ports == null || ports == "" || ports == "1:65535" || ports == "1-65535")
		return "";
	if (match(ports, /^([A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2}$/) != null)
		return expression + " { " + ports + " }";
	let seen = {};
	let values = [];
	for (let port in split(replace(ports, /[[:space:]]/g, ""), ",")) {
		port = replace(port, /:/g, "-");
		if (port != "" && !seen[port]) {
			seen[port] = true;
			push(values, port);
		}
	}
	if (!length(values) || (length(values) == 1 && values[0] == "1-65535"))
		return "";
	return expression + " { " + join(", ", values) + " }";
}

function redirect(port, mode) {
	if (port == null || port == "")
		return "counter redirect";
	if (mode == "TPROXY4")
		return "counter meta mark " + MARK + " tproxy ip to :" + port;
	if (mode == "TPROXY6")
		return "counter meta mark " + MARK + " tproxy ip6 to :" + port;
	if (mode == "TPROXY")
		return "counter meta mark " + MARK + " tproxy to :" + port;
	return "counter redirect to :" + port;
}

function jump(mode, action) {
	if (mode == "direct")
		return "mark != " + MARK + " counter return";
	if (mode == "proxy")
		return action ?? "counter redirect";
	return "";
}

function dual(chain, condition, name, action, static_name) {
	nft("add rule " + TABLE + " " + chain + " " + condition + " @" + name + " " + action);
	nft("add rule " + TABLE + " " + chain + " " + condition + " @" + (static_name ?? name + "_static") + " " + action);
}

function chain(name) {
	nft("add chain " + TABLE + " " + name);
	nft("flush chain " + TABLE + " " + name);
}

function filter_vps_addr(addresses) {
	let ip4 = [], ip6 = [];
	for (let address in addresses) {
		if (address == "" || match(address, /^(0\.0\.0\.0|127\.0\.0\.1|1\.1\.1\.[12]|8\.8\.[48]\.8|9\.9\.9\.9)$/) != null)
			continue;
		let value4 = resolve_host(4, address);
		let value6 = resolve_host(6, address);
		if (value4 != "")
			push(ip4, value4);
		if (value6 != "")
			push(ip6, value6);
	}
	add_elements("psw_vps", ip4);
	add_elements("psw_vps6", ip6);
	if (length(ip4))
		log("  - 加入IPv4节点服务器IP到nftset[psw_vps]直连完成");
	if (length(ip6))
		log("  - 加入IPv6节点服务器IP到nftset[psw_vps6]直连完成");
}

function filter_vpsip() {
	let addresses = [];
	api.uci_foreach_c("nodes", (s) => {
		push(addresses, "" + (s.address ?? ""), "" + (s.download_address ?? ""));
	});
	filter_vps_addr(addresses);
}

function filter_haproxy() {
	if (cfg("@global_haproxy[0]", "balancing_enable", "0") != "1")
		return;
	let section = api.uci_get_c("@global_haproxy[0]") ?? {};
	let values = section.lbss ?? [];
	if (type(values) != "array")
		values = [values];
	let addresses = [];
	for (let item in values)
		push(addresses, split("" + item, ":")[0]);
	filter_vps_addr(addresses);
}

function populate_shunt_sets(node, set4, set6) {
	let group = cfg(node, "shunt_group");
	api.uci_foreach_c("shunt_rules", (s) => {
		if (group != "" && "" + (s.group ?? "") != group)
			return;
		let path = TMP + "/shunt-" + s[".name"] + ".list";
		write(path, "" + (s.ip_list ?? ""));
		let data = list_file_data(path);
		add_elements(set4, data[0]);
		add_elements(set6, data[1]);
		add_elements(set4, geoip_addresses(data[2], 4));
		add_elements(set6, geoip_addresses(data[2], 6));
	});
}

function populate_sets() {
	let definitions = [
		["psw_wan", "ipv4_addr", "0"], ["psw_vps", "ipv4_addr", "0"],
		["psw_gfw", "ipv4_addr", "2d"], ["psw_local", "ipv4_addr", "0"],
		["psw_lan", "ipv4_addr", "0"], ["psw_chn", "ipv4_addr", "2d"],
		["psw_chn_static", "ipv4_addr", "0"], ["psw_black", "ipv4_addr", "2d"],
		["psw_black_static", "ipv4_addr", "0"], ["psw_white", "ipv4_addr", "2d"],
		["psw_white_static", "ipv4_addr", "0"], ["psw_block", "ipv4_addr", "2d"],
		["psw_block_static", "ipv4_addr", "0"], ["psw_shunt", "ipv4_addr", "2d"],
		["psw_shunt_static", "ipv4_addr", "0"],
		["psw_wan6", "ipv6_addr", "0"], ["psw_vps6", "ipv6_addr", "0"],
		["psw_gfw6", "ipv6_addr", "2d"], ["psw_local6", "ipv6_addr", "0"],
		["psw_lan6", "ipv6_addr", "0"], ["psw_chn6", "ipv6_addr", "2d"],
		["psw_chn6_static", "ipv6_addr", "0"], ["psw_black6", "ipv6_addr", "2d"],
		["psw_black6_static", "ipv6_addr", "0"], ["psw_white6", "ipv6_addr", "2d"],
		["psw_white6_static", "ipv6_addr", "0"], ["psw_block6", "ipv6_addr", "2d"],
		["psw_block6_static", "ipv6_addr", "0"], ["psw_shunt6", "ipv6_addr", "2d"],
		["psw_shunt6_static", "ipv6_addr", "0"]
	];
	for (let d in definitions)
		ensure_set(d[0], d[1], d[2]);
	nft_flush(false);

	add_elements("psw_lan", file_addresses(USER_RULES + "/lanlist_ipv4", false));
	add_elements("psw_lan6", file_addresses(USER_RULES + "/lanlist_ipv6", true));
	add_elements("psw_chn_static", file_addresses(RULES + "/chnroute", false));
	add_elements("psw_chn6_static", file_addresses(RULES + "/chnroute6", true));
	if (e("USE_DIRECT_LIST") == "1") {
		let data = list_file_data(USER_RULES + "/direct_ip");
		add_elements("psw_white_static", data[0]);
		add_elements("psw_white6_static", data[1]);
		add_elements("psw_white_static", geoip_addresses(data[2], 4));
		add_elements("psw_white6_static", geoip_addresses(data[2], 6));
	}
	if (e("USE_PROXY_LIST") == "1") {
		let data = list_file_data(USER_RULES + "/proxy_ip");
		add_elements("psw_black_static", data[0]);
		add_elements("psw_black6_static", data[1]);
		add_elements("psw_black_static", geoip_addresses(data[2], 4));
		add_elements("psw_black6_static", geoip_addresses(data[2], 6));
	}
	if (e("USE_BLOCK_LIST") == "1") {
		let data = list_file_data(USER_RULES + "/block_ip");
		add_elements("psw_block_static", data[0]);
		add_elements("psw_block6_static", data[1]);
		add_elements("psw_block_static", geoip_addresses(data[2], 4));
		add_elements("psw_block6_static", geoip_addresses(data[2], 6));
	}
	if (cfg(e("NODE"), "protocol") == "_shunt") {
		populate_shunt_sets(e("NODE"), "psw_shunt_static", "psw_shunt6_static");
	}
	add_elements("psw_white", words(e("ISP_DNS")));
	add_elements("psw_white6", words(e("ISP_DNS6")));
	filter_vpsip();
	filter_haproxy();
	let wan4 = wan_addresses(4), wan6 = wan_addresses(6);
	let wan4map = {}, wan6map = {};
	for (let value in wan4) wan4map[value] = true;
	for (let value in wan6) wan6map[value] = true;
	for (let value in interface_addresses(4))
		if (!wan4map[value]) add_elements("psw_local", [value]);
	add_elements("psw_local", ["127.0.0.1"]);
	for (let value in interface_addresses(6))
		if (!wan6map[value]) add_elements("psw_local6", [value]);
	add_elements("psw_local6", ["::1"]);
	let lan_ifname = trim(output(["uci", "-q", "-p", "/tmp/state", "get", "network.lan.ifname"]));
	if (lan_ifname != "") {
		for (let line in lines(output(["ip", "-o", "address", "show", "dev", lan_ifname]))) {
			let fields = split(line, /[[:space:]]+/);
			if (length(fields) > 3 && fields[2] == "inet")
				add_elements("psw_lan", [fields[3]]);
			else if (length(fields) > 3 && fields[2] == "inet6")
				add_elements("psw_lan6", [fields[3]]);
		}
	}
	nft_flush(false);
}

function add_list_rules(chain4, chain6, proto, ports, action4, action6, comment, prefix, options) {
	options = options ?? {};
	let use_fakedns = options.use_fakedns ?? e("USE_FAKEDNS");
	let use_proxy = options.use_proxy ?? e("USE_PROXY_LIST");
	let use_gfw = options.use_gfw ?? e("USE_GFW_LIST");
	let chn_mode = options.chn_mode ?? e("CHN_LIST");
	let use_shunt = options.use_shunt ?? (cfg(e("NODE"), "protocol") == "_shunt" ? "1" : "0");
	let proxy_mode = options.proxy_mode ?? e(proto == "tcp" ? "TCP_PROXY_MODE" : "UDP_PROXY_MODE");
	let ipv6 = options.ipv6 ?? e("PROXY_IPV6");
	let black4 = options.black4 ?? "psw_black";
	let black6 = options.black6 ?? "psw_black6";
	let gfw4 = options.gfw4 ?? "psw_gfw";
	let gfw6 = options.gfw6 ?? "psw_gfw6";
	let shunt4 = options.shunt4 ?? "psw_shunt";
	let shunt6 = options.shunt6 ?? "psw_shunt6";
	let p4 = "ip protocol " + proto + " " + (prefix ?? "") + factor(ports, proto + " dport");
	let p6 = "meta l4proto " + proto + " " + (prefix ?? "") + factor(ports, proto + " dport");
	let c = " comment " + quote_comment(comment);
	if (use_fakedns == "1") {
		nft("add rule " + TABLE + " " + chain4 + " " + p4 + " ip daddr 198.18.0.0/16 " + action4 + c);
		if (ipv6 == "1")
			nft("add rule " + TABLE + " " + chain6 + " " + p6 + " ip6 daddr 2001:2::/48 " + action6 + c);
	}
	if (use_proxy == "1") {
		dual(chain4, p4 + " ip daddr", black4, action4 + c, "psw_black_static");
		if (ipv6 == "1")
			dual(chain6, p6 + " ip6 daddr", black6, action6 + c, "psw_black6_static");
	}
	if (use_gfw == "1") {
		nft("add rule " + TABLE + " " + chain4 + " " + p4 + " ip daddr @" + gfw4 + " " + action4 + c);
		if (ipv6 == "1")
			nft("add rule " + TABLE + " " + chain6 + " " + p6 + " ip6 daddr @" + gfw6 + " " + action6 + c);
	}
	if (chn_mode != "0") {
		dual(chain4, p4 + " ip daddr", "psw_chn", jump(chn_mode, action4) + c);
		if (ipv6 == "1")
			dual(chain6, p6 + " ip6 daddr", "psw_chn6", jump(chn_mode, action6) + c);
	}
	if (use_shunt == "1") {
		dual(chain4, p4 + " ip daddr", shunt4, action4 + c);
		if (ipv6 == "1")
			dual(chain6, p6 + " ip6 daddr", shunt6, action6 + c);
	}
	if (proxy_mode != "disable") {
		nft("add rule " + TABLE + " " + chain4 + " " + p4 + " " + action4 + c);
		if (ipv6 == "1")
			nft("add rule " + TABLE + " " + chain6 + " " + p6 + " " + action6 + c);
	}
}

function add_default_rules(tproxy) {
	let tcp_chain = tproxy ? "PSW_MANGLE" : "PSW_NAT";
	let tcp_action = tproxy ? "counter jump PSW_RULE" : redirect(e("REDIR_PORT"));
	if (e("TCP_NO_REDIR_PORTS") != "disable")
		nft("add rule " + TABLE + " " + tcp_chain + " ip protocol tcp " + factor(e("TCP_NO_REDIR_PORTS"), "tcp dport") + " counter return comment \"默认\"");
	if (e("UDP_NO_REDIR_PORTS") != "disable")
		nft("add rule " + TABLE + " PSW_MANGLE ip protocol udp " + factor(e("UDP_NO_REDIR_PORTS"), "udp dport") + " counter return comment \"默认\"");
	let dns = e("DNS_REDIRECT_PORT");
	if (dns == "" && cfg("@global[0]", "dns_redirect", "1") == "1")
		dns = "53";
	if (dns != "") {
		nft("add rule " + TABLE + " PSW_MANGLE ip protocol udp udp dport 53 counter return comment \"默认\"");
		nft("add rule " + TABLE + " PSW_MANGLE ip protocol tcp tcp dport 53 counter return comment \"默认\"");
		nft("add rule " + TABLE + " PSW_MANGLE_V6 meta l4proto udp udp dport 53 counter return comment \"默认\"");
		nft("add rule " + TABLE + " PSW_MANGLE_V6 meta l4proto tcp tcp dport 53 counter return comment \"默认\"");
		nft("add rule " + TABLE + " PSW_DNS meta l4proto udp udp dport 53 counter redirect to :" + dns + " comment \"默认\"");
		nft("add rule " + TABLE + " PSW_DNS meta l4proto tcp tcp dport 53 counter redirect to :" + dns + " comment \"默认\"");
	}

	if (e("USE_BLOCK_LIST") == "1") {
		dual("PSW_MANGLE", "ip daddr", "psw_block", "counter reject comment \"默认\"");
		if (!tproxy)
			dual("PSW_NAT", "ip daddr", "psw_block", "counter reject comment \"默认\"");
		if (e("PROXY_IPV6") == "1")
			dual("PSW_MANGLE_V6", "ip6 daddr", "psw_block6", "counter reject comment \"默认\"");
	}
	if (e("USE_DIRECT_LIST") == "1") {
		dual("PSW_MANGLE", "ip daddr", "psw_white", "counter return comment \"默认\"");
		if (!tproxy)
			dual("PSW_NAT", "ip daddr", "psw_white", "counter return comment \"默认\"");
		if (e("PROXY_IPV6") == "1")
			dual("PSW_MANGLE_V6", "ip6 daddr", "psw_white6", "counter return comment \"默认\"");
	}
	if (e("TCP_PROXY_DROP_PORTS") != "disable")
		add_list_rules(tproxy ? "PSW_MANGLE" : "PSW_NAT", "PSW_MANGLE_V6", "tcp", e("TCP_PROXY_DROP_PORTS"), "counter reject", "counter reject", "默认");
	if (e("UDP_PROXY_DROP_PORTS") != "disable")
		add_list_rules("PSW_MANGLE", "PSW_MANGLE_V6", "udp", e("UDP_PROXY_DROP_PORTS"), "counter reject", "counter reject", "默认");
	if (e("TCP_PROXY_MODE") != "") {
		add_list_rules(tcp_chain, "PSW_MANGLE_V6", "tcp", e("TCP_REDIR_PORTS"), tcp_action, "counter jump PSW_RULE", "默认");
		if (tproxy)
			nft("add rule " + TABLE + " PSW_MANGLE ip protocol tcp " + redirect(e("REDIR_PORT"), "TPROXY4") + " comment \"默认\"");
		if (e("PROXY_IPV6") == "1")
			nft("add rule " + TABLE + " PSW_MANGLE_V6 meta l4proto tcp " + redirect(e("REDIR_PORT"), "TPROXY") + " comment \"默认\"");
	}
	if (e("UDP_PROXY_MODE") != "") {
		add_list_rules("PSW_MANGLE", "PSW_MANGLE_V6", "udp", e("UDP_REDIR_PORTS"), "counter jump PSW_RULE", "counter jump PSW_RULE", "默认");
		nft("add rule " + TABLE + " PSW_MANGLE ip protocol udp " + redirect(e("REDIR_PORT"), "TPROXY4") + " comment \"默认\"");
		if (e("PROXY_IPV6") == "1")
			nft("add rule " + TABLE + " PSW_MANGLE_V6 meta l4proto udp " + redirect(e("REDIR_PORT"), "TPROXY") + " comment \"默认\"");
	}
	nft("add rule " + TABLE + " " + tcp_chain + " ip protocol tcp counter return comment \"默认\"");
	nft("add rule " + TABLE + " PSW_MANGLE ip protocol udp counter return comment \"默认\"");
	if (e("PROXY_IPV6") == "1") {
		nft("add rule " + TABLE + " PSW_MANGLE_V6 meta l4proto tcp counter return comment \"默认\"");
		nft("add rule " + TABLE + " PSW_MANGLE_V6 meta l4proto udp counter return comment \"默认\"");
	}
	add_icmp_rules();
}

function source_expr(source, iface) {
	let prefix = iface != "" ? "iifname " + quote_comment(iface) + " " : "";
	if (substr(source, 0, 3) == "ip:")
		return [prefix + factor(substr(source, 3), "ip saddr"), true];
	if (substr(source, 0, 8) == "iprange:")
		return [prefix + factor(substr(source, 8), "ip saddr"), true];
	if (substr(source, 0, 6) == "ipset:")
		return [prefix + "ip saddr @" + substr(source, 6), true];
	if (substr(source, 0, 4) == "mac:")
		return [prefix + factor(substr(source, 4), "ether saddr"), false];
	if (source == "any")
		return [prefix, false];
	return null;
}

function interface_device(name) {
	if (name == "")
		return "";
	let data = output(["ubus", "call", "network.interface." + name, "status"]);
	try {
		let status = json(data);
		if (status.device != null && status.device != "")
			return status.device;
	} catch (e) {}
	if (exists("/sys/class/net/" + name))
		return name;
	return name;
}

function load_acls(tproxy) {
	if (e("ENABLED_ACLS") != "1")
		return;
	api.uci_foreach_c("acl_rule", (s) => {
		if ("" + (s.enabled ?? "0") != "1")
			return;
		let sid = s[".name"];
		let remarks = "" + (s.remarks ?? sid);
		let global_cfg = "" + (s.use_global_config ?? "0") == "1";
		let tcp_mode = global_cfg ? e("TCP_PROXY_MODE") : "" + (s.tcp_proxy_mode ?? "proxy");
		let udp_mode = global_cfg ? e("UDP_PROXY_MODE") : "" + (s.udp_proxy_mode ?? "proxy");
		let tcp_ports = global_cfg ? e("TCP_REDIR_PORTS") : "" + (s.tcp_redir_ports ?? e("TCP_REDIR_PORTS"));
		let udp_ports = global_cfg ? e("UDP_REDIR_PORTS") : "" + (s.udp_redir_ports ?? e("UDP_REDIR_PORTS"));
		let tcp_no = "" + (s.tcp_no_redir_ports ?? e("TCP_NO_REDIR_PORTS"));
		let udp_no = "" + (s.udp_no_redir_ports ?? e("UDP_NO_REDIR_PORTS"));
		let use_proxy = global_cfg ? e("USE_PROXY_LIST") : "" + (s.use_proxy_list ?? "1");
		let use_gfw = global_cfg ? e("USE_GFW_LIST") : "" + (s.use_gfw_list ?? "1");
		let use_direct = global_cfg ? e("USE_DIRECT_LIST") : "" + (s.use_direct_list ?? "1");
		let use_block = global_cfg ? e("USE_BLOCK_LIST") : "" + (s.use_block_list ?? "1");
		let chn_mode = global_cfg ? e("CHN_LIST") : "" + (s.chn_list ?? "direct");
		let tcp_drop = "" + (s.tcp_proxy_drop_ports ?? e("TCP_PROXY_DROP_PORTS"));
		let udp_drop = "" + (s.udp_proxy_drop_ports ?? e("UDP_PROXY_DROP_PORTS"));
		let node = api.get_cache_var("ACL_" + sid + "_node") ?? "" + (s.node ?? "");
		let use_shunt = cfg(node, "protocol") == "_shunt" ? "1" : "0";
		let use_fakedns = api.get_cache_var("ACL_" + sid + "_fakedns") ?? "0";
		let black4 = global_cfg ? "psw_black" : "psw_" + sid + "_black";
		let black6 = global_cfg ? "psw_black6" : "psw_" + sid + "_black6";
		let gfw4 = global_cfg ? "psw_gfw" : "psw_" + sid + "_gfw";
		let gfw6 = global_cfg ? "psw_gfw6" : "psw_" + sid + "_gfw6";
		let shunt4 = global_cfg ? "psw_shunt" : "psw_" + sid + "_shunt";
		let shunt6 = global_cfg ? "psw_shunt6" : "psw_" + sid + "_shunt6";
		if (!global_cfg) {
			if (use_proxy == "1") {
				ensure_set(black4, "ipv4_addr", "2d");
				ensure_set(black6, "ipv6_addr", "2d");
			}
			if (use_gfw == "1") {
				ensure_set(gfw4, "ipv4_addr", "2d");
				ensure_set(gfw6, "ipv6_addr", "2d");
			}
			if (use_shunt == "1") {
				ensure_set(shunt4, "ipv4_addr", "2d");
				ensure_set(shunt4 + "_static", "ipv4_addr", "0");
				ensure_set(shunt6, "ipv6_addr", "2d");
				ensure_set(shunt6 + "_static", "ipv6_addr", "0");
				populate_shunt_sets(node, shunt4 + "_static", shunt6 + "_static");
			}
			nft_flush(false);
		}
		let options = {
			use_fakedns, use_proxy, use_gfw, chn_mode, use_shunt,
			black4, black6, gfw4, gfw6, shunt4, shunt6,
			ipv6: e("PROXY_IPV6")
		};
		let redir = api.get_cache_var("ACL_" + sid + "_redir_port") ?? e("REDIR_PORT");
		let dns = api.get_cache_var("ACL_" + sid + "_dns_port");
		let sources = lines(read(TMP + "/acl/" + sid + "/source_list"));
		for (let source in sources) {
			let parsed = source_expr(source, interface_device("" + (s.interface ?? "")));
			if (parsed == null)
				continue;
			let src = parsed[0];
			let ipv4_only = parsed[1];
			if (tcp_no != "disable")
				nft("add rule " + TABLE + " " + (tproxy ? "PSW_MANGLE" : "PSW_NAT") + " ip protocol tcp " + src + " " + factor(tcp_no, "tcp dport") + " counter return comment " + quote_comment(remarks));
			if (udp_no != "disable")
				nft("add rule " + TABLE + " PSW_MANGLE ip protocol udp " + src + " " + factor(udp_no, "udp dport") + " counter return comment " + quote_comment(remarks));
			if (dns != null && dns != "") {
				nft("add rule " + TABLE + " PSW_DNS meta l4proto udp " + src + " udp dport 53 counter redirect to :" + dns + " comment " + quote_comment(remarks));
				nft("add rule " + TABLE + " PSW_DNS meta l4proto tcp " + src + " tcp dport 53 counter redirect to :" + dns + " comment " + quote_comment(remarks));
			}
			if (use_block == "1") {
				dual("PSW_MANGLE", src + " ip daddr", "psw_block", "counter reject comment " + quote_comment(remarks));
				if (!tproxy)
					dual("PSW_NAT", src + " ip daddr", "psw_block", "counter reject comment " + quote_comment(remarks));
				if (e("PROXY_IPV6") == "1" && !ipv4_only)
					dual("PSW_MANGLE_V6", src + " ip6 daddr", "psw_block6", "counter reject comment " + quote_comment(remarks));
			}
			if (use_direct == "1") {
				dual("PSW_MANGLE", src + " ip daddr", "psw_white", "counter return comment " + quote_comment(remarks));
				if (!tproxy)
					dual("PSW_NAT", src + " ip daddr", "psw_white", "counter return comment " + quote_comment(remarks));
				if (e("PROXY_IPV6") == "1" && !ipv4_only)
					dual("PSW_MANGLE_V6", src + " ip6 daddr", "psw_white6", "counter return comment " + quote_comment(remarks));
			}
			if (cfg("@global_forwarding[0]", "accept_icmp", "0") == "1") {
				if (use_direct == "1") dual("PSW_ICMP_REDIRECT", "ip protocol icmp " + src + " ip daddr", "psw_white", "counter return comment " + quote_comment(remarks));
				if (use_fakedns == "1") nft("add rule " + TABLE + " PSW_ICMP_REDIRECT ip protocol icmp " + src + " ip daddr 198.18.0.0/16 counter redirect comment " + quote_comment(remarks));
				if (use_proxy == "1") dual("PSW_ICMP_REDIRECT", "ip protocol icmp " + src + " ip daddr", black4, "counter redirect comment " + quote_comment(remarks), "psw_black_static");
				if (use_gfw == "1") nft("add rule " + TABLE + " PSW_ICMP_REDIRECT ip protocol icmp " + src + " ip daddr @" + gfw4 + " counter redirect comment " + quote_comment(remarks));
				if (chn_mode != "0") dual("PSW_ICMP_REDIRECT", "ip protocol icmp " + src + " ip daddr", "psw_chn", jump(chn_mode, "counter redirect") + " comment " + quote_comment(remarks));
				if (tcp_mode != "disable") nft("add rule " + TABLE + " PSW_ICMP_REDIRECT ip protocol icmp " + src + " counter redirect comment " + quote_comment(remarks));
				nft("add rule " + TABLE + " PSW_ICMP_REDIRECT ip protocol icmp " + src + " counter return comment " + quote_comment(remarks));
			}
			if (cfg("@global_forwarding[0]", "accept_icmpv6", "0") == "1" && !ipv4_only) {
				if (use_direct == "1") dual("PSW_ICMP_REDIRECT", "meta l4proto icmpv6 " + src + " ip6 daddr", "psw_white6", "counter return comment " + quote_comment(remarks));
				if (use_fakedns == "1") nft("add rule " + TABLE + " PSW_ICMP_REDIRECT meta l4proto icmpv6 " + src + " ip6 daddr 2001:2::/48 counter redirect comment " + quote_comment(remarks));
				if (use_proxy == "1") dual("PSW_ICMP_REDIRECT", "meta l4proto icmpv6 " + src + " ip6 daddr", black6, "counter redirect comment " + quote_comment(remarks), "psw_black6_static");
				if (use_gfw == "1") nft("add rule " + TABLE + " PSW_ICMP_REDIRECT meta l4proto icmpv6 " + src + " ip6 daddr @" + gfw6 + " counter redirect comment " + quote_comment(remarks));
				if (chn_mode != "0") dual("PSW_ICMP_REDIRECT", "meta l4proto icmpv6 " + src + " ip6 daddr", "psw_chn6", jump(chn_mode, "counter redirect") + " comment " + quote_comment(remarks));
				if (tcp_mode != "disable") nft("add rule " + TABLE + " PSW_ICMP_REDIRECT meta l4proto icmpv6 " + src + " counter redirect comment " + quote_comment(remarks));
				nft("add rule " + TABLE + " PSW_ICMP_REDIRECT meta l4proto icmpv6 " + src + " counter return comment " + quote_comment(remarks));
			}
			if (tcp_drop != "disable") {
				options.proxy_mode = tcp_mode;
				add_list_rules(tproxy ? "PSW_MANGLE" : "PSW_NAT", "PSW_MANGLE_V6", "tcp", tcp_drop, "counter reject", "counter reject", remarks, src, options);
			}
			if (udp_drop != "disable") {
				options.proxy_mode = udp_mode;
				add_list_rules("PSW_MANGLE", "PSW_MANGLE_V6", "udp", udp_drop, "counter reject", "counter reject", remarks, src, options);
			}
			if (tcp_mode != "") {
				let action = tproxy ? "counter jump PSW_RULE" : redirect(redir);
				options.proxy_mode = tcp_mode;
				add_list_rules(tproxy ? "PSW_MANGLE" : "PSW_NAT", "PSW_MANGLE_V6", "tcp", tcp_ports, action, "counter jump PSW_RULE", remarks, src, options);
				if (tproxy)
					nft("add rule " + TABLE + " PSW_MANGLE ip protocol tcp " + src + " " + redirect(redir, "TPROXY4") + " comment " + quote_comment(remarks));
				if (e("PROXY_IPV6") == "1" && !ipv4_only)
					nft("add rule " + TABLE + " PSW_MANGLE_V6 meta l4proto tcp " + src + " " + redirect(redir, "TPROXY") + " comment " + quote_comment(remarks));
			}
			nft("add rule " + TABLE + " " + (tproxy ? "PSW_MANGLE" : "PSW_NAT") + " ip protocol tcp " + src + " counter return comment " + quote_comment(remarks));
			if (udp_mode != "") {
				options.proxy_mode = udp_mode;
				add_list_rules("PSW_MANGLE", "PSW_MANGLE_V6", "udp", udp_ports, "counter jump PSW_RULE", "counter jump PSW_RULE", remarks, src, options);
				nft("add rule " + TABLE + " PSW_MANGLE ip protocol udp " + src + " " + redirect(redir, "TPROXY4") + " comment " + quote_comment(remarks));
				if (e("PROXY_IPV6") == "1" && !ipv4_only)
					nft("add rule " + TABLE + " PSW_MANGLE_V6 meta l4proto udp " + src + " " + redirect(redir, "TPROXY") + " comment " + quote_comment(remarks));
			}
			nft("add rule " + TABLE + " PSW_MANGLE ip protocol udp " + src + " counter return comment " + quote_comment(remarks));
		}
	});
}

function add_output_rules(tproxy) {
	if (e("ENABLED_DEFAULT_ACL") != "1")
		return;
	let tcp_chain = tproxy ? "PSW_OUTPUT_MANGLE" : "PSW_OUTPUT_NAT";
	if (e("TCP_NO_REDIR_PORTS") != "disable")
		nft("add rule " + TABLE + " " + tcp_chain + " ip protocol tcp " + factor(e("TCP_NO_REDIR_PORTS"), "tcp dport") + " counter return");
	if (e("UDP_NO_REDIR_PORTS") != "disable")
		nft("add rule " + TABLE + " PSW_OUTPUT_MANGLE ip protocol udp " + factor(e("UDP_NO_REDIR_PORTS"), "udp dport") + " counter return");
	if (e("TCP_PROXY_DROP_PORTS") != "disable")
		add_list_rules(tcp_chain, "PSW_OUTPUT_MANGLE_V6", "tcp", e("TCP_PROXY_DROP_PORTS"), "counter reject", "counter reject", "本机");
	if (e("UDP_PROXY_DROP_PORTS") != "disable")
		add_list_rules("PSW_OUTPUT_MANGLE", "PSW_OUTPUT_MANGLE_V6", "udp", e("UDP_PROXY_DROP_PORTS"), "counter reject", "counter reject", "本机");
	for (let endpoint in split(e("IPT_APPEND_DNS"), ",")) {
		endpoint = trim(endpoint);
		if (endpoint == "")
			continue;
		let pos = index(endpoint, "#");
		let address = pos >= 0 ? substr(endpoint, 0, pos) : endpoint;
		let port = pos >= 0 ? substr(endpoint, pos + 1) : "53";
		address = replace(replace(address, /^\[/, ""), /\]$/, "");
		if (index(address, ":") >= 0) {
			nft("add rule " + TABLE + " PSW_OUTPUT_MANGLE_V6 meta l4proto udp ip6 daddr " + address + " " + factor(port, "udp dport") + " counter return");
			nft("add rule " + TABLE + " PSW_OUTPUT_MANGLE_V6 meta l4proto tcp ip6 daddr " + address + " " + factor(port, "tcp dport") + " counter return");
		} else {
			nft("add rule " + TABLE + " PSW_OUTPUT_MANGLE ip protocol udp ip daddr " + address + " " + factor(port, "udp dport") + " counter return");
			nft("add rule " + TABLE + " PSW_OUTPUT_MANGLE ip protocol tcp ip daddr " + address + " " + factor(port, "tcp dport") + " counter return");
			if (!tproxy)
				nft("add rule " + TABLE + " PSW_OUTPUT_NAT ip protocol tcp ip daddr " + address + " " + factor(port, "tcp dport") + " counter return");
		}
	}
	if (e("DNS_REDIRECT_PORT") != "") {
		nft("add rule " + TABLE + " nat_output meta l4proto udp oif lo udp dport 53 counter redirect to :" + e("DNS_REDIRECT_PORT") + " comment \"PSW_DNS\"");
		nft("add rule " + TABLE + " nat_output meta l4proto tcp oif lo tcp dport 53 counter redirect to :" + e("DNS_REDIRECT_PORT") + " comment \"PSW_DNS\"");
	}
	for (let endpoint in split(replace(e("REMOTE_DNS"), /[ ,]+/g, ","), ",")) {
		if (endpoint == "")
			continue;
		let address = endpoint, port = "53";
		if (substr(endpoint, 0, 1) == "[") {
			let end = index(endpoint, "]");
			if (end > 0) {
				address = substr(endpoint, 1, end - 1);
				if (substr(endpoint, end + 1, 1) == "#" || substr(endpoint, end + 1, 1) == ":")
					port = substr(endpoint, end + 2);
			}
		} else if (index(endpoint, "#") >= 0) {
			let parts = split(endpoint, "#");
			address = parts[0];
			port = parts[1] ?? "53";
		}
		let ipv6 = index(address, ":") >= 0;
		let direct_set = ipv6 ? "psw_lan6" : "psw_lan";
		if (quiet_status(["nft", "get", "element", "inet", "passwall", direct_set, "{", address, "}"]) == 0)
			continue;
		if (e("TCP_PROXY_DNS") == "1") {
			if (ipv6) {
				nft("insert rule " + TABLE + " PSW_OUTPUT_MANGLE_V6 meta l4proto tcp ip6 daddr " + address + " tcp dport " + port + " counter jump PSW_RULE");
				nft("insert rule " + TABLE + " PSW_MANGLE_V6 meta l4proto tcp iif lo tcp dport " + port + " ip6 daddr " + address + " " + redirect(e("REDIR_PORT"), "TPROXY6") + " comment \"本机\"");
			} else if (tproxy) {
				nft("insert rule " + TABLE + " PSW_OUTPUT_MANGLE ip protocol tcp ip daddr " + address + " tcp dport " + port + " counter jump PSW_RULE");
				nft("insert rule " + TABLE + " PSW_MANGLE ip protocol tcp iif lo tcp dport " + port + " ip daddr " + address + " " + redirect(e("REDIR_PORT"), "TPROXY4") + " comment \"本机\"");
			} else {
				nft("insert rule " + TABLE + " PSW_OUTPUT_NAT ip protocol tcp ip daddr " + address + " tcp dport " + port + " " + redirect(e("REDIR_PORT")));
			}
		}
		if (e("UDP_PROXY_DNS") != "") {
			if (ipv6) {
				nft("insert rule " + TABLE + " PSW_OUTPUT_MANGLE_V6 meta l4proto udp ip6 daddr " + address + " udp dport " + port + " counter jump PSW_RULE");
				nft("insert rule " + TABLE + " PSW_MANGLE_V6 meta l4proto udp iif lo ip6 daddr " + address + " " + redirect(e("REDIR_PORT"), "TPROXY6") + " comment \"本机\"");
			} else {
				nft("insert rule " + TABLE + " PSW_OUTPUT_MANGLE ip protocol udp ip daddr " + address + " udp dport " + port + " counter jump PSW_RULE");
				nft("insert rule " + TABLE + " PSW_MANGLE ip protocol udp iif lo ip daddr " + address + " " + redirect(e("REDIR_PORT"), "TPROXY4") + " comment \"本机\"");
			}
		}
	}
	if (e("LOCALHOST_TCP_PROXY_MODE") != "") {
		let action = tproxy ? "counter jump PSW_RULE" : redirect(e("REDIR_PORT"));
		add_list_rules(tcp_chain, "PSW_OUTPUT_MANGLE_V6", "tcp", e("TCP_REDIR_PORTS"), action, "counter jump PSW_RULE", "本机");
		if (tproxy)
			nft("add rule " + TABLE + " PSW_MANGLE ip protocol tcp iif lo " + redirect(e("REDIR_PORT"), "TPROXY4") + " comment \"本机\"");
	}
	if (e("LOCALHOST_UDP_PROXY_MODE") != "") {
		add_list_rules("PSW_OUTPUT_MANGLE", "PSW_OUTPUT_MANGLE_V6", "udp", e("UDP_REDIR_PORTS"), "counter jump PSW_RULE", "counter jump PSW_RULE", "本机");
		nft("add rule " + TABLE + " PSW_MANGLE ip protocol udp iif lo " + redirect(e("REDIR_PORT"), "TPROXY4") + " comment \"本机\"");
	}
	nft("add rule " + TABLE + " PSW_MANGLE ip protocol udp iif lo counter return comment \"本机\"");
	if (tproxy)
		nft("add rule " + TABLE + " PSW_MANGLE ip protocol tcp iif lo counter return comment \"本机\"");
	nft("add rule " + TABLE + " mangle_output ip protocol udp counter jump PSW_OUTPUT_MANGLE comment \"PSW_OUTPUT_MANGLE\"");
	if (tproxy)
		nft("add rule " + TABLE + " mangle_output ip protocol tcp counter jump PSW_OUTPUT_MANGLE comment \"PSW_OUTPUT_MANGLE\"");
	else
		nft("add rule " + TABLE + " nat_output ip protocol tcp counter jump PSW_OUTPUT_NAT");
	nft("add rule " + TABLE + " mangle_output oif lo counter return comment \"PSW_OUTPUT_MANGLE\"");
	nft("add rule " + TABLE + " mangle_output meta mark " + MARK + " counter return comment \"PSW_OUTPUT_MANGLE\"");
	for (let iface in fs.lsdir(TMP + "/iface") ?? []) {
		nft("add rule " + TABLE + " " + tcp_chain + " oif " + quote_comment(iface) + " counter return");
		nft("add rule " + TABLE + " PSW_OUTPUT_MANGLE_V6 oif " + quote_comment(iface) + " counter return");
	}
}

function setup_icmp() {
	let accept4 = cfg("@global_forwarding[0]", "accept_icmp", "0") == "1";
	let accept6 = cfg("@global_forwarding[0]", "accept_icmpv6", "0") == "1";
	if (!accept4 && !accept6)
		return;
	chain("PSW_ICMP_REDIRECT");
	nft("add rule " + TABLE + " PSW_ICMP_REDIRECT ip daddr @psw_lan counter return");
	nft("add rule " + TABLE + " PSW_ICMP_REDIRECT ip daddr @psw_vps counter return");
	if (accept6) {
		nft("add rule " + TABLE + " PSW_ICMP_REDIRECT ip6 daddr @psw_lan6 counter return");
		nft("add rule " + TABLE + " PSW_ICMP_REDIRECT ip6 daddr @psw_vps6 counter return");
	}
	if (accept4) {
		nft("add rule " + TABLE + " dstnat meta l4proto icmp counter jump PSW_ICMP_REDIRECT");
		nft("add rule " + TABLE + " nat_output meta l4proto icmp counter jump PSW_ICMP_REDIRECT");
	}
	if (accept6) {
		nft("add rule " + TABLE + " dstnat meta l4proto icmpv6 counter jump PSW_ICMP_REDIRECT");
		nft("add rule " + TABLE + " nat_output meta l4proto icmpv6 counter jump PSW_ICMP_REDIRECT");
	}
}

add_icmp_rules = function() {
	let accept4 = cfg("@global_forwarding[0]", "accept_icmp", "0") == "1";
	let accept6 = cfg("@global_forwarding[0]", "accept_icmpv6", "0") == "1";
	if (accept4) {
		if (e("USE_DIRECT_LIST") == "1") dual("PSW_ICMP_REDIRECT", "ip daddr", "psw_white", "counter return");
		if (e("USE_FAKEDNS") == "1") nft("add rule " + TABLE + " PSW_ICMP_REDIRECT ip protocol icmp ip daddr 198.18.0.0/16 counter redirect");
		if (e("USE_PROXY_LIST") == "1") dual("PSW_ICMP_REDIRECT", "ip protocol icmp ip daddr", "psw_black", "counter redirect");
		if (e("USE_GFW_LIST") == "1") nft("add rule " + TABLE + " PSW_ICMP_REDIRECT ip protocol icmp ip daddr @psw_gfw counter redirect");
		if (e("CHN_LIST") != "0") dual("PSW_ICMP_REDIRECT", "ip protocol icmp ip daddr", "psw_chn", jump(e("CHN_LIST"), "counter redirect"));
		if (e("TCP_PROXY_MODE") != "disable") nft("add rule " + TABLE + " PSW_ICMP_REDIRECT ip protocol icmp counter redirect");
		nft("add rule " + TABLE + " PSW_ICMP_REDIRECT ip protocol icmp counter return");
	}
	if (accept6) {
		if (e("USE_DIRECT_LIST") == "1") dual("PSW_ICMP_REDIRECT", "ip6 daddr", "psw_white6", "counter return");
		if (e("USE_FAKEDNS") == "1") nft("add rule " + TABLE + " PSW_ICMP_REDIRECT meta l4proto icmpv6 ip6 daddr 2001:2::/48 counter redirect");
		if (e("USE_PROXY_LIST") == "1") dual("PSW_ICMP_REDIRECT", "meta l4proto icmpv6 ip6 daddr", "psw_black6", "counter redirect");
		if (e("USE_GFW_LIST") == "1") nft("add rule " + TABLE + " PSW_ICMP_REDIRECT meta l4proto icmpv6 ip6 daddr @psw_gfw6 counter redirect");
		if (e("CHN_LIST") != "0") dual("PSW_ICMP_REDIRECT", "meta l4proto icmpv6 ip6 daddr", "psw_chn6", jump(e("CHN_LIST"), "counter redirect"));
		if (e("TCP_PROXY_MODE") != "disable") nft("add rule " + TABLE + " PSW_ICMP_REDIRECT meta l4proto icmpv6 counter redirect");
		nft("add rule " + TABLE + " PSW_ICMP_REDIRECT meta l4proto icmpv6 counter return");
	}
};

function base_rules(tproxy) {
	chain("PSW_DIVERT");
	nft("add rule " + TABLE + " PSW_DIVERT meta l4proto tcp socket transparent 1 mark set " + MARK + " counter accept");
	chain("PSW_DNS");
	if (cfg("@global[0]", "dns_redirect", "1") == "0") {
		nft("insert rule " + TABLE + " dstnat ip saddr @psw_lan ip daddr @psw_local jump PSW_DNS");
		nft("insert rule " + TABLE + " dstnat ip6 saddr @psw_lan6 ip6 daddr @psw_local6 jump PSW_DNS");
	} else {
		nft("insert rule " + TABLE + " dstnat ip saddr @psw_lan jump PSW_DNS");
		nft("insert rule " + TABLE + " dstnat ip6 saddr @psw_lan6 jump PSW_DNS");
	}
	chain("PSW_RULE");
	nft("add rule " + TABLE + " PSW_RULE counter meta mark set ct mark");
	nft("add rule " + TABLE + " PSW_RULE meta mark " + MARK + " counter return");
	nft("add rule " + TABLE + " PSW_RULE tcp flags & (fin|syn|rst|ack) == syn counter meta mark set " + MARK);
	nft("add rule " + TABLE + " PSW_RULE meta l4proto udp ct state { new, related } counter meta mark set " + MARK);
	nft("add rule " + TABLE + " PSW_RULE counter ct mark set mark");

	chain("PSW_MANGLE");
	nft("add rule " + TABLE + " PSW_MANGLE ip daddr @psw_lan counter return");
	nft("add rule " + TABLE + " PSW_MANGLE ip daddr @psw_vps counter return");
	nft("add rule " + TABLE + " PSW_MANGLE ct direction reply counter return");
	chain("PSW_OUTPUT_MANGLE");
	nft("add rule " + TABLE + " PSW_OUTPUT_MANGLE ip daddr @psw_lan counter return");
	nft("add rule " + TABLE + " PSW_OUTPUT_MANGLE ip daddr @psw_vps counter return");
	if (e("USE_BLOCK_LIST") == "1")
		dual("PSW_OUTPUT_MANGLE", "ip daddr", "psw_block", "counter reject");
	if (e("USE_DIRECT_LIST") == "1")
		dual("PSW_OUTPUT_MANGLE", "ip daddr", "psw_white", "counter return");
	nft("add rule " + TABLE + " PSW_OUTPUT_MANGLE ct direction reply counter return");
	nft("add rule " + TABLE + " PSW_OUTPUT_MANGLE meta mark and 0xff == 0xff counter return");
	nft("add rule " + TABLE + " mangle_prerouting counter jump PSW_DIVERT");
	nft("add rule " + TABLE + " mangle_prerouting ip protocol udp counter jump PSW_MANGLE");
	if (tproxy)
		nft("add rule " + TABLE + " mangle_prerouting ip protocol tcp counter jump PSW_MANGLE");

	if (!tproxy) {
		chain("PSW_NAT");
		nft("add rule " + TABLE + " PSW_NAT ip daddr @psw_lan counter return");
		nft("add rule " + TABLE + " PSW_NAT ip daddr @psw_vps counter return");
		nft("add rule " + TABLE + " dstnat ip protocol tcp counter jump PSW_NAT");
		chain("PSW_OUTPUT_NAT");
		nft("add rule " + TABLE + " PSW_OUTPUT_NAT ip daddr @psw_lan counter return");
		nft("add rule " + TABLE + " PSW_OUTPUT_NAT ip daddr @psw_vps counter return");
		if (e("USE_BLOCK_LIST") == "1")
			dual("PSW_OUTPUT_NAT", "ip daddr", "psw_block", "counter reject");
		if (e("USE_DIRECT_LIST") == "1")
			dual("PSW_OUTPUT_NAT", "ip daddr", "psw_white", "counter return");
		nft("add rule " + TABLE + " PSW_OUTPUT_NAT meta mark and 0xff == 0xff counter return");
	}
	nft("add rule " + TABLE + " " + (tproxy ? "PSW_MANGLE" : "PSW_NAT") + " ip daddr @psw_wan counter return comment \"WAN_IP_RETURN\"");

	chain("PSW_MANGLE_V6");
	nft("add rule " + TABLE + " PSW_MANGLE_V6 ip6 daddr @psw_lan6 counter return");
	nft("add rule " + TABLE + " PSW_MANGLE_V6 ip6 daddr @psw_vps6 counter return");
	nft("add rule " + TABLE + " PSW_MANGLE_V6 ct direction reply counter return");
	chain("PSW_OUTPUT_MANGLE_V6");
	nft("add rule " + TABLE + " PSW_OUTPUT_MANGLE_V6 ip6 daddr @psw_lan6 counter return");
	nft("add rule " + TABLE + " PSW_OUTPUT_MANGLE_V6 ip6 daddr @psw_vps6 counter return");
	if (e("USE_BLOCK_LIST") == "1")
		dual("PSW_OUTPUT_MANGLE_V6", "ip6 daddr", "psw_block6", "counter reject");
	if (e("USE_DIRECT_LIST") == "1")
		dual("PSW_OUTPUT_MANGLE_V6", "ip6 daddr", "psw_white6", "counter return");
	nft("add rule " + TABLE + " PSW_OUTPUT_MANGLE_V6 ct direction reply counter return");
	nft("add rule " + TABLE + " PSW_OUTPUT_MANGLE_V6 meta mark and 0xff == 0xff counter return");
	if (e("PROXY_IPV6") == "1") {
		nft("add rule " + TABLE + " mangle_prerouting meta nfproto ipv6 counter jump PSW_MANGLE_V6");
		nft("add rule " + TABLE + " mangle_output meta nfproto ipv6 counter jump PSW_OUTPUT_MANGLE_V6 comment \"PSW_OUTPUT_MANGLE\"");
		nft("add rule " + TABLE + " PSW_MANGLE_V6 ip6 daddr @psw_wan6 counter return comment \"WAN6_IP_RETURN\"");
	}
	setup_icmp();
}

function set_sysctl() {
	run(["sysctl", "-w", "net.ipv4.conf.all.rp_filter=0"], true);
	run(["sysctl", "-w", "net.ipv4.conf.default.rp_filter=0"], true);
	for (let name in fs.lsdir("/proc/sys/net/ipv4/conf") ?? [])
		write("/proc/sys/net/ipv4/conf/" + name + "/rp_filter", "0\n");
}

function add_routes() {
	run(["ip", "rule", "add", "fwmark", MARK, "table", "999", "priority", "999"], true);
	run(["ip", "route", "add", "local", "0.0.0.0/0", "dev", "lo", "table", "999"], true);
	if (e("PROXY_IPV6") == "1") {
		run(["ip", "-6", "rule", "add", "fwmark", MARK, "table", "999", "priority", "999"], true);
		run(["ip", "-6", "route", "add", "local", "::/0", "dev", "lo", "table", "999"], true);
	}
}

function delete_routes() {
	quiet_status(["ip", "rule", "del", "fwmark", MARK]);
	quiet_status(["ip", "route", "del", "local", "0.0.0.0/0", "dev", "lo", "table", "999"]);
	quiet_status(["ip", "-6", "rule", "del", "fwmark", MARK]);
	quiet_status(["ip", "-6", "route", "del", "local", "::/0", "dev", "lo", "table", "999"]);
}

wan_addresses = function(family) {
	let out = [];
	let data = output(["ubus", "call", "network.interface", "dump"]);
	let decoded;
	try { decoded = json(data); } catch (err) { return out; }
	for (let iface in decoded.interface ?? []) {
		if (match(iface.interface ?? "", /lan/) != null || !length(iface.route ?? []))
			continue;
		let key = family == 6 ? "ipv6-address" : "ipv4-address";
		for (let item in iface[key] ?? []) {
			let address = item.address;
			if (address != null && address != "" && address != "0.0.0.0" && address != "::" && substr(address, 0, 5) != "fe80:")
				push(out, address);
		}
	}
	return out;
};

function update_wan_sets(do_log) {
	if (!table_exists())
		return 0;
	let lock = fs.open("/var/lock/passwall_update_wan_sets.lock", "w");
	if (lock != null && !lock.lock("x"))
		return 1;
	let ip4 = wan_addresses(4);
	let ip6 = wan_addresses(6);
	add_elements("psw_wan", ip4);
	add_elements("psw_wan6", ip6);
	let rc = nft_flush(false);
	if (do_log == "log") {
		for (let ip in ip4)
			log("  - 加入WAN IPv4到nftset[psw_wan]：" + ip);
		for (let ip in ip6)
			log("  - 加入WAN IPv6到nftset[psw_wan6]：" + ip);
	}
	if (lock != null)
		lock.close();
	return rc;
}

function filter_server_port(address, port, stream, tproxy) {
	let proto = lc(stream);
	let pexpr = factor(replace(port, /:/g, "-"), proto + " dport");
	let comment = quote_comment(address + ":" + replace(port, /:/g, "-") + ":" + proto);
	let chain4 = (proto == "udp" || tproxy) ? "PSW_OUTPUT_MANGLE" : "PSW_OUTPUT_NAT";
	if (index(nft_output(["list", "chain", "inet", "passwall", chain4]), "comment " + comment) < 0)
		nft("insert rule " + TABLE + " " + chain4 + " meta l4proto " + proto + " ip daddr " + address + " " + pexpr + " return comment " + comment);
	if (index(nft_output(["list", "chain", "inet", "passwall", "PSW_OUTPUT_MANGLE_V6"]), "comment " + comment) < 0)
		nft("insert rule " + TABLE + " PSW_OUTPUT_MANGLE_V6 meta l4proto " + proto + " ip6 daddr " + address + " " + pexpr + " return comment " + comment);
}

function filter_node(node, stream, tproxy) {
	let address = cfg(node, "address");
	let port = cfg(node, "port");
	let hop = cfg(node, "hysteria2_hop");
	if (address == "" || port == "" || match(address, /^(0\.0\.0\.0|127\.0\.0\.1|1\.1\.1\.[12]|8\.8\.[48]\.8|9\.9\.9\.9)$/) != null)
		return;
	if (hop != "")
		port += "," + hop;
	filter_server_port(address, port, stream, tproxy);
}

function filter_direct_node_list() {
	if (!exists(TMP + "/direct_node_list") || !table_exists())
		return 0;
	let seen = {};
	let tproxy = cfg("@global_forwarding[0]", "tcp_proxy_way", "redirect") == "tproxy";
	for (let node in lines(read(TMP + "/direct_node_list"))) {
		if (seen[node])
			continue;
		seen[node] = true;
		filter_node(node, "tcp", tproxy);
		filter_node(node, "udp", true);
	}
	return nft_flush(true);
}

function mwan3_stop() {
	let listing = quiet_output(["nft", "-a", "list", "chain", "ip", "mangle", "mwan3_hook"]);
	for (let line in split(listing, "\n")) {
		if (index(line, MARK) < 0 && index(line, "passwall") < 0)
			continue;
		let m = match(line, /# handle ([0-9]+)/);
		if (m != null)
			run(["nft", "delete", "rule", "ip", "mangle", "mwan3_hook", "handle", m[1]], true);
	}
	return 0;
}

function mwan3_start() {
	if (quiet_status(["nft", "list", "chain", "ip", "mangle", "mwan3_hook"]) != 0)
		return 0;
	mwan3_stop();
	let rc = run(["nft", "insert", "rule", "ip", "mangle", "mwan3_hook", "ct", "mark", MARK, "counter", "return", "comment", "passwall"], true);
	if (rc != 0)
		run(["logger", "-t", "passwall", "mwan3: failed to add " + MARK + " exemption rule to mangle/mwan3_hook"], true);
	return rc;
}

function update_mwan3(add) {
	let path = "/etc/init.d/mwan3";
	if (!exists(path))
		return;
	let data = read(path);
	let kept = [];
	for (let line in split(data, "\n")) {
		if (index(line, "passwall/nftables.uc mwan3_") < 0 &&
		    index(line, "passwall/nftables.sh mwan3_") < 0)
			push(kept, line);
	}
	data = join("\n", kept);
	if (add) {
		data = replace(data, /(start_service\(\)[^{]*\{[\s\S]*?\n)\}/, "$1    " + LIBEXEC + " mwan3_start\n}");
		data = replace(data, /(stop_service\(\)[^{]*\{\n)/, "$1    " + LIBEXEC + " mwan3_stop\n");
	}
	write(path, data);
}

function destroy_nftset(...names) {
	nft_flush(true);
	for (let name in names) {
		run(["nft", "flush", "set", "inet", "passwall", name], true);
		run(["nft", "delete", "set", "inet", "passwall", name], true);
	}
}

function del_firewall_rule() {
	if (table_exists())
		flush_table();
	delete_routes();
}

function flush_nftset() {
	let listing = output(["nft", "list", "table", "inet", "passwall"]);
	for (let line in split(listing, "\n")) {
		let m = match(line, /^[[:space:]]*set (psw_[A-Za-z0-9_]+)/);
		if (m != null)
			destroy_nftset(m[1]);
	}
}

flush_table = function() {
	quiet_status(["nft", "flush", "table", "inet", "passwall"]);
	quiet_status(["nft", "delete", "table", "inet", "passwall"]);
};

function flush_include() {
	let path = include_path();
	write(path, "#!/bin/sh\nexit 0\n");
	fs.chmod(path, 0o755);
}

function rules_loaded() {
	return index(quiet_output(["nft", "list", "chain", "inet", "passwall", "mangle_prerouting"]), "PSW_DIVERT") >= 0;
}

function fw4_reload() {
	load_env();
	let snapshot = TMP + "/PSW_RULE.nft";
	if (!rules_loaded() && exists(snapshot))
		run(["nft", "-f", snapshot], true);
	update_wan_sets();
	return 0;
}

function gen_include() {
	let snapshot = TMP + "/PSW_RULE.nft";
	write(snapshot, nft_output(["list", "table", "inet", "passwall"]));
	let path = include_path();
	write(path, "#!/bin/sh\nexec /usr/bin/ucode " + LIBEXEC + " fw4_reload\n");
	fs.chmod(path, 0o755);
}

function start() {
	load_env();
	if (e("ENABLED_DEFAULT_ACL") == "0" && e("ENABLED_ACLS") == "0")
		return 0;
	log("开始加载 nftables 防火墙规则...");
	ensure_table();
	set_sysctl();
	populate_sets();
	update_wan_sets("log");
	let tproxy = e("TCP_PROXY_WAY", "redirect") == "tproxy";
	base_rules(tproxy);
	load_acls(tproxy);
	if (e("ENABLED_DEFAULT_ACL") == "1")
		add_default_rules(tproxy);
	add_output_rules(tproxy);
	nft("insert rule " + TABLE + " mangle_output meta skgid 9911 counter return comment \"PSW_DIRECT\"");
	nft("insert rule " + TABLE + " nat_output meta skgid 9911 counter return comment \"PSW_DIRECT\"");
	let rc = nft_flush(false);
	if (rc != 0)
		return rc;
	add_routes();
	update_mwan3(true);
	mwan3_start();
	filter_direct_node_list();
	gen_include();
	log("防火墙规则加载完成！");
	return 0;
}

function stop() {
	load_env();
	mwan3_stop();
	update_mwan3(false);
	del_firewall_rule();
	if (cfg("@global[0]", "flush_set_on_reboot", "0") == "1" || cfg("@global[0]", "flush_set", "0") == "1") {
		api.uci_del_c("@global[0]", "flush_set");
		api.uci_save_c(true);
		flush_nftset();
		for (let name in fs.lsdir("/tmp/etc/passwall_tmp") ?? [])
			if (match(name, /^(singbox|dnsmasq)/) != null || name == "geo_output" || name == "user_rules")
				run(["rm", "-rf", "/tmp/etc/passwall_tmp/" + name], true);
	}
	flush_include();
	log("删除 nftables 规则完成。");
	return 0;
}

function main(argv) {
	let action = argv[0] ?? "";
	let rc = 1;
	if (action == "start")
		rc = start();
	else if (action == "stop")
		rc = stop();
	else if (action == "update_wan_sets")
		rc = update_wan_sets(argv[1]);
	else if (action == "filter_direct_node_list")
		rc = filter_direct_node_list();
	else if (action == "mwan3_start")
		rc = mwan3_start();
	else if (action == "mwan3_stop")
		rc = mwan3_stop();
	else if (action == "fw4_reload")
		rc = fw4_reload();
	exit(rc ?? 0);
}

export { main };
