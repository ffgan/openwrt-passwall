#!/usr/bin/ucode
'use strict';

import { main } from 'passwall.reload_backend';

exit(main(ARGV) ?? 0);
