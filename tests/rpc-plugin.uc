'use strict';

// Loads the same file rpcd compiles for ubus object luci.passwall, then calls
// the methods the settings page needs. A syntax error in any imported module
// makes rpcd skip the object, and LuCI reports that as
// "luci.passwall/capabilities ... Object not found".

import * as fs from 'fs';
import * as proc_mod from 'passwall.proc';
import * as monitor_mod from 'passwall.monitor';
import * as app_mod from 'passwall.app';
import * as haproxy_mod from 'passwall.haproxy';
import * as xray_mod from 'passwall.util_xray';
import { cmdline_of, background } from 'passwall.proc';

let failed = 0;
let pids = [];
let work = "";
let cache_path = "/tmp/etc/passwall/var";
let cache_before = null;
let cache_existed = false;

function fail(name, detail) {
	failed++;
	print("FAIL " + name);
	if (detail != null && detail != "")
		print("\n " + detail);
	print("\n");
}

function eq(name, got, want) {
	if (sprintf("%J", got) !== sprintf("%J", want))
		fail(name, "got: " + sprintf("%J", got) + "\n want: " + sprintf("%J", want));
}

function track(pid) {
	if (match("" + (pid ?? ""), /^[0-9]+$/) != null)
		push(pids, "" + pid);
}

function repo_root() {
	let script = sourcepath() ?? "";
	let at = rindex(script, "/tests/");
	if (at >= 0)
		return substr(script, 0, at);
	return ".";
}

function wait_text(path) {
	for (let i = 0; i < 50; i++) {
		let text = fs.readfile(path);
		if (type(text) == "string" && trim(text) != "")
			return trim(text);
		system(["sleep", "0.1"]);
	}
	return "";
}

function write_cache(map) {
	fs.writefile(cache_path, sprintf("%J", map) + "\n");
}

function call_method(methods, name) {
	let spec = methods[name];
	if (type(spec) != "object" || type(spec.call) != "function") {
		fail(name + " is not registered", "");
		return null;
	}
	return spec.call();
}

function listen_port() {
	let script = work + "/listen.py";
	let port_file = work + "/port";
	let body = "import socket, sys, time\n"
		+ "s = socket.socket()\n"
		+ "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
		+ "s.bind(('127.0.0.1', 0))\n"
		+ "s.listen(1)\n"
		+ "fh = open(sys.argv[1], 'w')\n"
		+ "fh.write(str(s.getsockname()[1]))\n"
		+ "fh.close()\n"
		+ "time.sleep(30)\n";
	fs.writefile(script, body);
	let started = background("exec python3 " + script + " " + port_file);
	track(started.pid);
	let port = wait_text(port_file);
	if (match(port, /^[0-9]+$/) == null)
		fail("listen port", "python did not bind, pid " + started.pid);
	return port;
}

function start_core(name) {
	let bin_dir = "/tmp/etc/passwall/bin";
	system(["mkdir", "-p", bin_dir]);
	let bin = bin_dir + "/" + name;
	system(["cp", "-f", "/bin/sleep", bin]);
	system(["chmod", "755", bin]);
	let started = background("exec " + bin + " 30");
	track(started.pid);
	let cmd = "";
	for (let i = 0; i < 20; i++) {
		cmd = cmdline_of(started.pid);
		if (index(cmd, name) >= 0)
			break;
		system(["sleep", "0.1"]);
	}
	if (index(cmd, name) < 0)
		fail("core cmdline", "pid " + started.pid + " cmdline " + sprintf("%J", cmd));
	return started.pid;
}

function stop_tracked() {
	for (let pid in pids)
		system("kill -9 " + pid + " >/dev/null 2>&1");
	pids = [];
}

function restore_cache() {
	if (cache_existed)
		fs.writefile(cache_path, cache_before ?? "");
	else
		fs.unlink(cache_path);
}

function cleanup() {
	stop_tracked();
	restore_cache();
	fs.unlink("/tmp/etc/passwall/bin/naive-default-global");
	if (work != "")
		system(["rm", "-rf", work]);
}

function load_plugin() {
	let path = repo_root() + "/luci-app-passwall/root/usr/share/rpcd/ucode/luci.passwall";
	let entry = loadfile(path);
	if (type(entry) != "function") {
		fail("plugin compile", "loadfile returned " + type(entry));
		return null;
	}
	let plugin = entry();
	if (type(plugin) != "object" || type(plugin["luci.passwall"]) != "object") {
		fail("plugin object", "rpcd would not register luci.passwall");
		return null;
	}
	return plugin["luci.passwall"];
}

function check_capabilities(methods) {
	let caps = call_method(methods, "capabilities");
	if (type(caps) != "object") {
		fail("capabilities result", type(caps));
		return;
	}
	eq("capabilities.prefer_nft", caps.prefer_nft, true);
	eq("capabilities.nodes", type(caps.nodes), "array");
	eq("capabilities.components", type(caps.components), "array");
	if (type(caps.components) == "array" && length(caps.components) == 0)
		fail("capabilities.components", "empty");
	for (let key in [ "singbox", "xray", "hysteria", "geoview", "haproxy", "smartdns", "node_list" ])
		if (!(key in caps))
			fail("capabilities." + key, "missing");
}

function check_idle(methods) {
	fs.unlink(cache_path);
	let status = call_method(methods, "index_status");
	if (type(status) != "object") {
		fail("index_status idle", type(status));
		return;
	}
	eq("idle dns", status.dns_mode_status, false);
	eq("idle tcp", status.tcp_status, null);
	eq("idle udp", status.udp_status, null);
	if (match("" + (status.haproxy_status ?? ""), /^(-1|[01])$/) == null)
		fail("idle haproxy", sprintf("%J", status.haproxy_status));
	let node = call_method(methods, "get_now_use_node");
	eq("idle node", node, {});
}

function check_listening(methods, port) {
	write_cache({
		ENABLED_DEFAULT_ACL: "1",
		HAS_TPROXY: "1",
		ACL_GLOBAL_redir_port: port,
		ACL_default_dns_port: port,
		ACL_GLOBAL_node: "node-e2e"
	});
	let status = call_method(methods, "index_status");
	eq("listen tcp", status.tcp_status, true);
	eq("listen udp", status.udp_status, true);
	eq("listen dns", status.dns_mode_status, true);
	let node = call_method(methods, "get_now_use_node");
	eq("listen node", node.global, "node-e2e");
}

function check_naive(methods) {
	start_core("naive-default-global");
	let status = call_method(methods, "index_status");
	// The command line is visible, so Naive must not be reported as UDP.
	eq("naive tcp", status.tcp_status, true);
	eq("naive udp", status.udp_status, false);
	eq("naive dns", status.dns_mode_status, true);
}

function check_down(methods) {
	stop_tracked();
	system(["sleep", "0.2"]);
	let status = call_method(methods, "index_status");
	eq("down tcp", status.tcp_status, false);
	eq("down udp", status.udp_status, false);
	eq("down dns", status.dns_mode_status, false);
}

function check_detach() {
	let started = background("exec /bin/sleep 30");
	track(started.pid);
	let cmd = "";
	for (let i = 0; i < 20; i++) {
		cmd = cmdline_of(started.pid);
		if (index(cmd, "sleep") >= 0)
			break;
		system(["sleep", "0.1"]);
	}
	if (index(cmd, "sleep") < 0) {
		fail("detach cmdline", sprintf("%J", cmd));
		return;
	}
	system("kill -HUP " + started.pid + " >/dev/null 2>&1");
	system(["sleep", "0.2"]);
	let still = cmdline_of(started.pid);
	if (index(still, "sleep") < 0)
		fail("detach survives SIGHUP", sprintf("%J", still));
	system("kill -9 " + started.pid + " >/dev/null 2>&1");
}

function check_modules() {
	// import already compiled these. require() would reject their export statements.
	for (let name, mod in {
		"passwall.proc": proc_mod,
		"passwall.monitor": monitor_mod,
		"passwall.app": app_mod,
		"passwall.haproxy": haproxy_mod,
		"passwall.util_xray": xray_mod
	}) {
		if (type(mod) != "object")
			fail(name, "did not load");
	}
}

function main() {
	system(["mkdir", "-p", "/tmp/etc/passwall", "/tmp/log"]);
	cache_before = fs.readfile(cache_path);
	cache_existed = type(cache_before) == "string";
	let self = match(fs.readfile("/proc/self/stat") ?? "", /^([0-9]+)/);
	work = "/tmp/passwall-e2e-" + time() + "-" + (self == null ? "0" : self[1]);
	system(["mkdir", "-p", work]);

	let methods = load_plugin();
	if (methods == null)
		return;
	check_capabilities(methods);
	check_idle(methods);
	let port = listen_port();
	if (match(port, /^[0-9]+$/) != null) {
		check_listening(methods, port);
		check_naive(methods);
		check_down(methods);
	}
	check_detach();
	check_modules();
}

try {
	main();
}
catch (err) {
	fail("uncaught", sprintf("%J", err));
}
cleanup();

if (failed == 0)
	print("ok\n");
else
	exit(1);
