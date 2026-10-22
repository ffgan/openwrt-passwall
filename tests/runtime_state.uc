'use strict';

import {
	parse_runtime, render_runtime, parse_nft_state, render_nft_state,
	parse_proc_record, render_proc_record, launch_script
} from 'passwall.state';

let failed = 0;

function eq(name, got, want) {
	if (got !== want) {
		failed++;
		print("FAIL " + name + "\n got: " + sprintf("%J", got) + "\n want: " + sprintf("%J", want) + "\n");
	}
}

function same_map(name, got, want) {
	eq(name + " json", sprintf("%J", got), sprintf("%J", want));
}

let legacy = "ENABLED_DEFAULT_ACL='1'\nNODE='a'\\''b'\nEMPTY=\n";
let parsed = parse_runtime(legacy);
eq("legacy acl", parsed.ENABLED_DEFAULT_ACL, "1");
eq("legacy quote", parsed.NODE, "a'b");
eq("legacy empty", parsed.EMPTY, "");

let rendered = render_runtime({ ENABLED_DEFAULT_ACL: "1", NODE: "a'b", EMPTY: "", SKIP: null });
let again = parse_runtime(rendered);
eq("json acl", again.ENABLED_DEFAULT_ACL, "1");
eq("json quote", again.NODE, "a'b");
eq("json drops empty", again.EMPTY, null);
eq("render skips empty", index(rendered, "EMPTY"), -1);

let nft = parse_nft_state(render_nft_state({ ENABLED: "0", TCP_PROXY_MODE: "", NODE: "x'y" }));
eq("nft keeps empty", nft.TCP_PROXY_MODE, "");
eq("nft quote", nft.NODE, "x'y");
eq("nft enabled", nft.ENABLED, "0");
eq("legacy nft", parse_nft_state("TCP_PROXY_WAY='tproxy'\n").TCP_PROXY_WAY, "tproxy");
eq("bad json falls back", parse_runtime("{not json\nMODE='direct'\n").MODE, "direct");
let mixed = parse_runtime("{\"FOO\":\"old\"}\nFOO='new'\nBAR=1\n");
eq("mixed override", mixed.FOO, "new");
eq("mixed extra", mixed.BAR, "1");
eq("empty runtime", length(keys(parse_runtime(""))), 0);
eq("empty render", render_runtime({}), "");

let old_proc = "4321\n999\nulimit -n 65535; exec '/bin/xray' 'run'\n";
let old = parse_proc_record(old_proc);
eq("old pid", old.pid, "4321");
eq("old time", old.starttime, "999");
eq("old script", old.script, "ulimit -n 65535; exec '/bin/xray' 'run'");
eq("old file", old.file, "");

let rec = {
	pid: "7",
	starttime: "8",
	file: "/tmp/etc/passwall/bin/xray",
	args: [ "run", "-c", "/tmp/a'b" ],
	output: "/tmp/log",
	env: { XRAY_LOCATION_ASSET: "/usr/share/v2ray", NO_REC_PROCESS: "1", "bad-key": "no" }
};
let stored = parse_proc_record(render_proc_record(rec));
eq("proc pid", stored.pid, "7");
eq("proc arg", stored.args[2], "/tmp/a'b");
eq("proc env", stored.env.XRAY_LOCATION_ASSET, "/usr/share/v2ray");
eq("proc drops norec", stored.env.NO_REC_PROCESS, null);
eq("proc drops bad key", stored.env["bad-key"], null);
eq("proc output", stored.output, "/tmp/log");

let script = launch_script("/bin/xray", [ "run", "-c", "/tmp/a'b" ], "/tmp/log", {
	XRAY_LOCATION_ASSET: "/usr/share/v2ray",
	NO_REC_PROCESS: "1"
});
eq("launch has exec", index(script, "exec '/bin/xray' 'run' '-c' '/tmp/a'\\''b' >'/tmp/log' 2>&1") >= 0, true);
eq("launch exports asset", index(script, "export XRAY_LOCATION_ASSET='/usr/share/v2ray'") >= 0, true);
eq("launch skips norec", index(script, "NO_REC_PROCESS") < 0, true);
eq("launch ulimit", index(script, "ulimit -n 65535 2>/dev/null; ") == 0, true);

if (failed != 0) {
	print(failed + " failed\n");
	exit(1);
}
print("ok\n");
