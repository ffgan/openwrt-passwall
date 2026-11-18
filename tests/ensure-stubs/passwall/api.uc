'use strict';
export function proc_lines(pattern) { return global.ensure_processes; };
export function uci_get_c(section, option) {
	if (section == '@global[0]') return option == 'enabled' ? '1' : 'node';
	return { '.type': 'nodes' };
};
export function exec_call(command) { die('Healthy core triggered recovery: ' + command); };
export function log(message) { die('Healthy core was declared missing: ' + message); };
