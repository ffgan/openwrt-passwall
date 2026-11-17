'use strict';

import { main } from 'passwall.nftables';

exit(main([ARGV[0] ?? 'start']) ?? 0);
