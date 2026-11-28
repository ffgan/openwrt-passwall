'use strict';
import * as fs from 'fs';
import { instance_spec } from 'passwall.core_service';
let dir = fs.mkdtemp('/tmp/passwall-core-test.XXXXXX');
if (dir == null) die('Cannot create test directory');
let payload = 'literal; touch ' + dir + '/injected';
let spec = instance_spec('/usr/bin/printf', ['%s', payload], dir + '/log with spaces', {TEST:'value'});
if (system(spec.command) != 0) die('Launch command failed');
if (fs.readfile(dir + '/log with spaces') != payload || fs.stat(dir + '/injected') != null) die('Argument or output quoting failed');
if (spec.respawn[1] != 5 || spec.respawn[2] != 0 || spec.env.TEST != 'value' || spec.term_timeout != 5) die('Supervisor policy lost');
if (spec.limits.nofile != '8192 8192') die('Managed core descriptor budget lost');
let rejected = false;
try { instance_spec('relative-xray', [], '', {}); } catch (e) { rejected = true; }
if (!rejected) die('Relative executable accepted');
fs.unlink(dir + '/log with spaces');
fs.rmdir(dir);
print('Core supervision spec and shell quoting passed\n');
