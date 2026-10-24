'use strict';

import {
	truth, lua_or, to_number, leading_int, lua_quote, gmatch, lines_of,
	awk_field, host_port, processor_count, df_available_kb, du_kb, 	quoted_option_blob, proc_net_ports
} from 'passwall.text';

let failed = 0;

function eq(name, got, want) {
	if (sprintf("%J", got) !== sprintf("%J", want)) {
		failed++;
		print("FAIL " + name + "\n got: " + sprintf("%J", got) + "\n want: " + sprintf("%J", want) + "\n");
	}
}

eq("truth empty", truth(""), true);
eq("truth zero", truth(0), true);
eq("truth false", truth(false), false);
eq("truth null", truth(null), false);
eq("lua or empty", lua_or("", "fallback"), "");
eq("lua or false", lua_or(false, "fallback"), "fallback");
eq("number int", to_number("10"), 10);
eq("number zero", to_number("0"), 0);
eq("number float", to_number("1.5"), 1.5);
eq("number exp", to_number("1e2"), 100.0);
eq("number space", to_number(" 1"), 1);
eq("number word", to_number("abc"), null);
eq("number false", to_number(false), null);
eq("leading", leading_int("60s"), 60);
eq("leading miss", leading_int("s60"), null);
eq("quote", lua_quote("a\"b\\c\n"), "\"a\\\"b\\\\c\\n\"");
eq("quote null", lua_quote(null), "\"\"");
eq("gmatch", gmatch("a,b,c", /[^,]+/g), ["a", "b", "c"]);
eq("gmatch null", gmatch(null, /a/g), []);
eq("lines", lines_of("a\nb\n"), ["a", "b"]);
eq("lines blank", lines_of("\n"), [""]);
eq("lines missing", lines_of(null), null);
eq("host port", host_port("1.2.3.4:443"), ["1.2.3.4", "443"]);
eq("host hash", host_port("dns.example#53"), ["dns.example", "53"]);
eq("host v6", host_port("[::1]:443"), ["[::1]", "443"]);
eq("host bare", host_port("example.com"), ["example.com", ""]);
eq("host colon", host_port("example.com:"), ["example.com:", ""]);
eq("cpu", processor_count("processor\t: 0\nvendor_id\t: x\nprocessor\t: 1\n"), 2);
eq("df", df_available_kb("Filesystem 1K-blocks Used Available Use% Mounted on\n/dev/root 10 2 7 20% /\n"), 7);
eq("du", du_kb("12\t/tmp/a\n"), 12);
eq("awk colon", awk_field("Private key: aaa\nPublic key: bbb\n", ": "), ["aaa", "bbb"]);
eq("awk word", awk_field("PrivateKey: aaa\nPublicKey: bbb\n", null), ["aaa", "bbb"]);
eq("uci blob", quoted_option_blob("passwall.b.download_address='two'\npasswall.a.address='one'\npasswall.c.port='9'\n"), "one\ntwo\n");
eq("uci address", quoted_option_blob("passwall.b.download_address='two'\npasswall.a.address='one'\n", "address"), "one\n");
eq("uci empty", quoted_option_blob(""), "");
eq("proc empty", proc_net_ports("", true), {});
eq("proc header", proc_net_ports("sl local_address rem_address st\n", true), {});
eq("tcp listen", proc_net_ports("  sl  local_address rem_address   st\n   0: 00000000:0035 00000000:0000 0A 00000000:00000000\n   1: 0100007F:01BB 00000000:0000 01 00000000:00000000\n", true), { "53": true });
eq("udp bind", proc_net_ports("  sl  local_address rem_address   st\n   0: 00000000:14E9 00000000:0000 07\n", false), { "5353": true });

if (failed == 0)
	print("ok\n");
else
	exit(1);
