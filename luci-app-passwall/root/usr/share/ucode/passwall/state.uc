'use strict';

// Runtime files shared by ucode and LuCI. JSON is the on-disk form.
// Assignment files written by older builds are still accepted.

function decode_shell(value) {
	if (length(value) >= 2 && substr(value, 0, 1) == "'" && substr(value, -1) == "'") {
		value = substr(value, 1, length(value) - 2);
		value = replace(value, /'\\''/g, "'");
	}
	return value;
}

function split_lines(text) {
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
			push(rows, row);
			start = i + 1;
		}
	}
	return rows;
}

function ident(key) {
	return type(key) == "string" && match(key, /^[A-Za-z_][A-Za-z0-9_]*$/) != null;
}

function as_text(value) {
	if (value === null || value === false)
		return "";
	if (type(value) == "string")
		return value;
	return "" + value;
}

function parse_json_object(text) {
	if (type(text) != "string")
		return null;
	let trimmed = trim(text);
	if (trimmed == "" || substr(trimmed, 0, 1) != "{")
		return null;
	try {
		let obj = json(trimmed);
		if (type(obj) == "object" && obj != null)
			return obj;
	} catch (e) {}
	return null;
}

function parse_assignments(text) {
	let out = {};
	for (let line in split_lines(text ?? "")) {
		let m = match(line, /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/);
		if (m != null)
			out[m[1]] = decode_shell(m[2]);
	}
	return out;
}

function string_map(obj, drop_empty) {
	let out = {};
	if (type(obj) != "object" || obj == null)
		return out;
	for (let key, value in obj) {
		if (!ident(key))
			continue;
		let text = as_text(value);
		if (drop_empty && text == "")
			continue;
		out[key] = text;
	}
	return out;
}

export function parse_runtime(text) {
	let obj = parse_json_object(text);
	if (obj != null)
		return string_map(obj, false);
	return parse_assignments(text);
};

export function render_runtime(map) {
	let clean = string_map(map, true);
	if (length(keys(clean)) == 0)
		return "";
	return sprintf("%J", clean);
};

export function parse_nft_state(text) {
	return parse_runtime(text);
};

export function render_nft_state(map) {
	return sprintf("%J", string_map(map, false));
};

function string_args(value) {
	let args = [];
	if (type(value) != "array")
		return args;
	for (let arg in value)
		push(args, as_text(arg));
	return args;
}

export function parse_proc_record(text) {
	if (type(text) != "string" || trim(text) == "")
		return null;
	let obj = parse_json_object(text);
	if (obj != null) {
		let output = as_text(obj.output);
		return {
			pid: as_text(obj.pid),
			starttime: as_text(obj.starttime),
			file: as_text(obj.file),
			args: string_args(obj.args),
			output: output == "" ? "/dev/null" : output,
			env: string_map(obj.env, false),
			script: as_text(obj.script)
		};
	}
	let rows = split_lines(text);
	if (length(rows) < 3)
		return null;
	let script = "";
	for (let i = 2; i < length(rows); i++) {
		if (i > 2)
			script += "\n";
		script += rows[i];
	}
	while (length(script) > 0 && (ord(script, length(script) - 1) == 10 || ord(script, length(script) - 1) == 13))
		script = substr(script, 0, length(script) - 1);
	return {
		pid: rows[0],
		starttime: rows[1],
		file: "",
		args: [],
		output: "/dev/null",
		env: {},
		script: script
	};
};

export function shell_quote(s) {
	if (s === null || s === false)
		s = "";
	else
		s = "" + s;
	return "'" + replace(s, "'", "'\\''") + "'";
};

export function launch_script(file, args, output, env) {
	let parts = [ "ulimit -n 65535 2>/dev/null" ];
	if (type(env) == "object" && env != null) {
		for (let key, value in env) {
			if (!ident(key) || key == "NO_REC_PROCESS")
				continue;
			push(parts, "export " + key + "=" + shell_quote(value));
		}
	}
	let exec = "exec " + shell_quote(file);
	if (type(args) == "array") {
		for (let arg in args)
			exec += " " + shell_quote(arg);
	}
	if (output === null || output === false || output == "")
		output = "/dev/null";
	exec += " >" + shell_quote(output) + " 2>&1";
	push(parts, exec);
	return join("; ", parts);
};

export function render_proc_record(spec) {
	spec = spec ?? {};
	let env = {};
	if (type(spec.env) == "object" && spec.env != null) {
		for (let key, value in spec.env) {
			if (!ident(key) || key == "NO_REC_PROCESS")
				continue;
			env[key] = as_text(value);
		}
	}
	let obj = {
		v: 1,
		pid: as_text(spec.pid),
		starttime: as_text(spec.starttime),
		file: as_text(spec.file),
		args: string_args(spec.args),
		output: as_text(spec.output) == "" ? "/dev/null" : as_text(spec.output),
		env: env
	};
	if (obj.file == "" && as_text(spec.script) != "")
		obj.script = as_text(spec.script);
	return sprintf("%J", obj);
};
