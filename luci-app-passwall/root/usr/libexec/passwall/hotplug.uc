#!/usr/bin/ucode
'use strict';
import * as hotplug from 'passwall.hotplug';
let action = ARGV[0] ?? '';
if (action == 'iface')
	exit(hotplug.iface(ARGV[1], ARGV[2], ARGV[3]) ?? 0);
if (action == 'ntp')
	exit(hotplug.ntp(ARGV[1]) ?? 0);
exit(1);
