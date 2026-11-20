'use strict';

import { ports_in_config, same_ports } from 'passwall.reload_backend';

let text = '	bind 127.0.0.1:1181\n'
	+ '	server M1-198.51.100.10:443 127.0.0.1:2001 weight 5 check\n'
	+ '	server B1-198.51.100.20:32579 127.0.0.1:2005 weight 5 check backup\n';
let ports = ports_in_config(text);
if (!same_ports(ports, ['2001', '2005']))
	die('server ports ' + sprintf('%J', ports));
if (same_ports(ports, ['2001']))
	die('missing port matched');
if (!same_ports(['2001', '2001'], ['2001']))
	die('duplicate server lines should compare as a set');
let bind_only = ports_in_config('	bind 127.0.0.1:1181\n');
if (length(bind_only) != 0)
	die('frontend bind was treated as a backend');
print('reload backend port matching passed\n');
