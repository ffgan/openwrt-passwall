'use strict';
export function proc_lines(pattern) { return global.ensure_processes; };
export function uci_get_c(section, option) {
	if (section == '@global_haproxy[0]')
		return option == 'balancing_enable' ? (global.ensure_balancing ?? null) : null;
	if (section == '@global[0]') return option == 'enabled' ? '1' : 'node';
	return { '.type': 'nodes' };
};
export function exec_call(command) {
	if (global.ensure_allow_exec) {
		global.ensure_exec = (global.ensure_exec ?? '') + command + '\n';
		return 0;
	}
	die('Healthy core triggered recovery: ' + command);
};
export function log(message) {
	if (global.ensure_allow_exec) {
		global.ensure_exec = (global.ensure_exec ?? '') + message + '\n';
		return;
	}
	die('Healthy core was declared missing: ' + message);
};
