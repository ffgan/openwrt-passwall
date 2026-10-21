#!/usr/bin/ucode
'use strict';

import * as u from 'passwall.utils';
import * as api from 'passwall.api';

function emit(value) {
	if (value == null)
		return;
	if (type(value) == 'array')
		print(join('\n', value));
	else if (type(value) == 'object')
		print(sprintf('%J', value));
	else
		print(value);
}

let action = ARGV[0] ?? '';
let args = [];
for (let i = 1; i < length(ARGV); i++)
	push(args, ARGV[i]);

if (action == 'log') api.log(join(' ', args));
else if (action == 'clean_log') u.clean_log();
else if (action == 'pkg_installed') exit(u.pkg_installed(args[0]) ? 0 : 1);
else if (action == 'config_get_type') emit(u.config_get_type(args[0], args[1]));
else if (action == 'config_n_get') emit(u.config_n_get(args[0], args[1], args[2]));
else if (action == 'config_t_get') emit(u.config_t_get(args[0], args[1], args[2], args[3]));
else if (action == 'del_cache_var') u.del_cache_var(args[0]);
else if (action == 'set_cache_var') u.set_cache_var(args[0], args[1]);
else if (action == 'get_cache_var') emit(u.get_cache_var(args[0]));
else if (action == 'first_type') emit(u.first_type(args[0], args[1]));
else if (action == 'get_enabled_anonymous_secs') emit(u.get_enabled_anonymous_secs(args[0]));
else if (action == 'get_geoip') emit(u.get_geoip(args[0], args[1]));
else if (action == 'get_host_ip') emit(u.get_host_ip(args[0], args[1], args[2]));
else if (action == 'get_node_host_ip') emit(u.get_node_host_ip(args[0]));
else if (action == 'parse_doh') emit(u.parse_doh(args[0])?.[args[1]]);
else if (action == 'host_from_url') emit(u.host_from_url(args[0]));
else if (action == 'check_host') exit(u.check_host(args[0]) ? 0 : 1);
else if (action == 'normalize_dns') emit(u.normalize_dns(args[0], args[1]));
else if (action == 'format_dns') emit(u.format_dns(args[0], args[1]));
else if (action == 'check_port_exists') emit(u.check_port_exists(args[0], args[1]) ? 1 : 0);
else if (action == 'get_new_port') emit(u.get_new_port(args[0], args[1]));
else if (action == 'check_ver') emit(u.check_ver(args[0], args[1]));
else if (action == 'has_1_65535') exit(u.has_1_65535(args[0]) ? 0 : 1);
else if (action == 'add_ip2route') exit(u.add_ip2route(args[0], args[1]));
else if (action == 'delete_ip2route') u.delete_ip2route();
else if (action == 'get_process_start_time') emit(u.get_process_start_time(args[0]));
else if (action == 'gen_lanlist') emit(u.gen_lanlist(args[0]));
else if (action == 'get_wan_ips') emit(u.get_wan_ips(args[0]));
else if (action == 'get_local_ips') emit(u.get_local_ips(args[0]));
else exit(1);
