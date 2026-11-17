'use strict';

// Clash subscription conversion runs in /usr/bin/passwall-tools.
// stdout is the share-link document parseClashNode used to return.
// stderr and --log carry the same discard messages api.log used to write.

import * as api from 'passwall.api';
import { readfile, unlink, writefile } from 'fs';
import { read_cmd } from 'passwall.proc';

let BIN = "/usr/bin/passwall-tools";

function tool() {
	return api.fs.access(BIN, "x") == true ? BIN : null;
}

function lines_of(text) {
	let rows = [];
	if (type(text) != "string" || text == "")
		return rows;
	let start = 0;
	let n = length(text);
	for (let i = 0; i <= n; i++) {
		if (i == n || ord(text, i) == 10) {
			let row = substr(text, start, i - start);
			if (length(row) > 0 && ord(row, length(row) - 1) == 13)
				row = substr(row, 0, length(row) - 1);
			if (row != "")
				push(rows, row);
			start = i + 1;
		}
	}
	return rows;
}

function run(args, input) {
	let bin = tool();
	if (bin == null)
		return null;
	let id = api.gen_random_char(12);
	if (id == "")
		id = "fallback";
	let in_path = "/tmp/passwall-clash-in-" + id;
	let log_path = "/tmp/passwall-clash-log-" + id;
	if (writefile(in_path, input ?? "") == null) {
		unlink(in_path);
		return null;
	}
	let argv = [bin, "clash"];
	for (let arg in args)
		push(argv, arg);
	push(argv, "--input", in_path, "--log", log_path);
	let got = read_cmd(argv);
	let logged = readfile(log_path);
	unlink(in_path);
	unlink(log_path);
	for (let row in lines_of(logged))
		api.log(row);
	if (got == null || got.rc != 0)
		return null;
	return got.out;
}

let parseClashNode = function(raw, remark) {
	if (raw === null || raw === false)
		return "";
	if (type(raw) != "string")
		raw = "" + raw;
	let out = run(["convert"], raw);
	if (out === null) {
		api.log("订阅转换 → 未找到 " + BIN + "，按原始订阅处理");
		return raw;
	}
	return out;
};

let parse_clash_sub_info = function(headers) {
	if (type(headers) != "string")
		return null;
	let out = run(["subinfo"], headers);
	if (out === null || trim(out) == "")
		return null;
	let obj = api.jsonc.parse(trim(out));
	if (type(obj) != "object" || obj === null)
		return null;
	if (type(obj.rem_traffic) != "string" || type(obj.expired_date) != "string")
		return null;
	return {
		rem_traffic: obj.rem_traffic,
		expired_date: obj.expired_date
	};
};

export { parseClashNode, parse_clash_sub_info };
