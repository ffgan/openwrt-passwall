#!/usr/bin/ucode
'use strict';

import * as api from 'passwall.api';
let join_sp, emit;

join_sp = function(arr) {
	let s = '';
	for (let i = 0; i < length(arr); i++) {
		if (i > 0)
			s += ' ';
		if (arr[i] != null)
			s += arr[i];
	}
	return s;
};

emit = function(v) {
	if (v == null)
		print('nil');
	else if (type(v) == 'bool')
		print(v ? 'true' : 'false');
	else if (type(v) == 'array')
		print(join_sp(v));
	else
		print(v);
};

let expr = ARGV[0];
if (expr == null || expr == '') {
	print('nil');
	exit(0);
}
let m = match(expr, /^([A-Za-z_][A-Za-z0-9_]*)\((.*)\)\s*$/);
if (m == null || type(api[m[1]]) != 'function') {
	print('nil');
	exit(0);
}
let raw = m[2];
let arg = raw;
if (length(raw) >= 2) {
	let q0 = substr(raw, 0, 1);
	let q1 = substr(raw, length(raw) - 1, 1);
	if ((q0 == '"' && q1 == '"') || (q0 == "'" && q1 == "'"))
		arg = substr(raw, 1, length(raw) - 2);
}
emit(api[m[1]](arg));
