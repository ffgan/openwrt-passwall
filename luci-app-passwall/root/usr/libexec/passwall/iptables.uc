#!/usr/bin/ucode
'use strict';
import { main } from 'passwall.iptables';
exit(main(ARGV) ?? 0);
