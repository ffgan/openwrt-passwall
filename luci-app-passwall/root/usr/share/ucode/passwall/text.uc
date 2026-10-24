'use strict';

// Shared string and number helpers. No imports: OpenWrt 25.12 ucode can load
// this module without the fs, uci, or digest plugins.

export function truth(v) {
	return v != null && v !== false;
};

export function lua_or(a, b) {
	if (a == null || a === false)
		return b;
	return a;
};

export function to_number(v) {
	if (type(v) == "int")
		return v;
	if (type(v) == "double")
		return (v == v) ? v : null;
	if (type(v) != "string")
		return null;
	let s = trim(v);
	if (match(s, /^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$/) == null)
		return null;
	if (index(s, ".") >= 0 || index(lc(s), "e") >= 0)
		return s * 1;
	return int(s);
};

export function leading_int(v) {
	let m = match("" + v, /^[0-9]+/);
	if (m == null)
		return null;
	return to_number(m[0]);
};

export function lua_quote(s) {
	if (s == null || s === false)
		s = "";
	else
		s = "" + s;
	let out = "\"";
	for (let i = 0; i < length(s); i++) {
		let c = substr(s, i, 1);
		let b = ord(s, i);
		if (c == "\\" || c == "\"")
			out += "\\" + c;
		else if (c == "\n")
			out += "\\n";
		else if (c == "\r")
			out += "\\r";
		else if (b < 32)
			out += sprintf("\\%03d", b);
		else
			out += c;
	}
	return out + "\"";
};

export function gmatch(s, pattern) {
	if (s == null || s === false)
		return [];
	let found = match("" + s, pattern);
	if (found == null)
		return [];
	let out = [];
	for (let m in found) {
		if (type(m) == "array")
			push(out, m[0]);
		else
			push(out, m);
	}
	return out;
};

// File contents, not a path. A missing file is null from readfile and stays null.
export function lines_of(data) {
	if (data == null)
		return null;
	if (data == "")
		return [];
	if (substr(data, -1) == "\n")
		data = substr(data, 0, length(data) - 1);
	if (data == "")
		return [""];
	return split(data, "\n");
};

export function whitespace_fields(line) {
	let parts = [];
	let cur = "";
	line = line == null ? "" : ("" + line);
	let n = length(line);
	for (let i = 0; i < n; i++) {
		let c = ord(line, i);
		if (c == 32 || c == 9 || c == 13) {
			if (cur != "") {
				push(parts, cur);
				cur = "";
			}
		} else {
			cur += substr(line, i, 1);
		}
	}
	if (cur != "")
		push(parts, cur);
	return parts;
};

// awk '{print $2}' when sep is null, otherwise awk -F sep '{print $2}'.
export function awk_field(text, sep) {
	let out = [];
	if (type(text) != "string" || text == "")
		return out;
	let body = text;
	if (substr(body, -1) == "\n")
		body = substr(body, 0, length(body) - 1);
	for (let line in split(body, "\n")) {
		if (sep == null) {
			let fields = whitespace_fields(line);
			push(out, fields[1] ?? "");
		} else {
			let at = index(line, sep);
			if (at < 0) {
				push(out, "");
			} else {
				let rest = substr(line, at + length(sep));
				let cut = index(rest, sep);
				push(out, cut < 0 ? rest : substr(rest, 0, cut));
			}
		}
	}
	return out;
};

// sed -n 's/^.*[:#]\([0-9]*\)$/\1/p' plus the shell suffix strip.
// An empty port leaves the original string in place.
export function host_port(value) {
	let str = (value == null || value === false) ? "" : ("" + value);
	let n = length(str);
	let i = n;
	while (i > 0) {
		let b = ord(str, i - 1);
		if (b < 48 || b > 57)
			break;
		i--;
	}
	if (i == 0 || i == n)
		return [str, ""];
	let sep = substr(str, i - 1, 1);
	if (sep != ":" && sep != "#")
		return [str, ""];
	let port = substr(str, i);
	if (port == "")
		return [str, ""];
	return [substr(str, 0, i - 1), port];
};

export function processor_count(text) {
	if (type(text) != "string" || text == "")
		return 0;
	let n = 0;
	for (let line in split(text, "\n")) {
		if (index(line, "processor") >= 0)
			n++;
	}
	return n;
};

// First data row of `df -k`, Available column.
export function df_available_kb(text) {
	if (type(text) != "string" || text == "")
		return null;
	let header = true;
	for (let line in split(text, "\n")) {
		if (trim(line) == "")
			continue;
		if (header) {
			header = false;
			continue;
		}
		let fields = whitespace_fields(line);
		if (length(fields) < 4)
			return null;
		let n = int(fields[3]);
		if (n != n)
			return null;
		return n;
	}
	return null;
};

// First field of `du -k`.
export function du_kb(text) {
	if (type(text) != "string" || text == "")
		return null;
	let line = split(text, "\n")[0] ?? "";
	let fields = whitespace_fields(line);
	if (length(fields) < 1)
		return null;
	let n = int(fields[0]);
	if (n != n)
		return null;
	return n;
};

// `uci show` lines, cut -d "'" -f 2, sort -u.
// kind "address" keeps only .address. Any other kind also keeps .download_address.
export function quoted_option_blob(text, kind) {
	let vals = [];
	let seen = {};
	if (type(text) != "string" || text == "")
		return "";
	for (let line in split(text, "\n")) {
		if (kind == "address") {
			if (match(line, /\.address=/) == null)
				continue;
		} else if (match(line, /\.(address|download_address)=/) == null) {
			continue;
		}
		let parts = split(line, "'");
		let val = length(parts) > 1 ? parts[1] : "";
		if (seen[val] == true)
			continue;
		seen[val] = true;
		push(vals, val);
	}
	sort(vals);
	if (length(vals) == 0)
		return "";
	return join("\n", vals) + "\n";
};

function hex_port(text) {
	if (type(text) != "string" || text == "")
		return null;
	let n = 0;
	for (let i = 0; i < length(text); i++) {
		let c = ord(text, i);
		let digit = null;
		if (c >= 48 && c <= 57)
			digit = c - 48;
		else if (c >= 97 && c <= 102)
			digit = c - 87;
		else if (c >= 65 && c <= 70)
			digit = c - 55;
		if (digit == null)
			return null;
		n = n * 16 + digit;
		if (n > 65535)
			return null;
	}
	return n;
}

// Rows from /proc/net/tcp or /proc/net/udp. TCP keeps state 0A (LISTEN).
// UDP keeps every bound local port. Keys are decimal port strings.
export function proc_net_ports(text, tcp) {
	let ports = {};
	if (type(text) != "string" || text == "")
		return ports;
	for (let line in split(text, "\n")) {
		let fields = whitespace_fields(line);
		if (length(fields) < 4)
			continue;
		let local = fields[1];
		let colon = rindex(local, ":");
		if (colon < 1)
			continue;
		let port = hex_port(substr(local, colon + 1));
		if (port == null || port <= 0)
			continue;
		if (tcp && lc(fields[3]) != "0a")
			continue;
		ports["" + port] = true;
	}
	return ports;
};
