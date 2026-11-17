#!/usr/bin/env python3
"""Run the production supervisor against controlled ubus response sequences."""
import os
import subprocess
import tempfile
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
with tempfile.TemporaryDirectory() as folder:
    root = Path(folder)
    module = root / 'passwall'
    module.mkdir()
    (module / 'core_service.uc').write_text((ROOT / 'luci-app-passwall/root/usr/share/ucode/passwall/core_service.uc').read_text())
    (module / 'api.uc').write_text("export function log(s) {}; export function shellquote(s) { return s; };")
    (module / 'utils.uc').write_text('''
export function run(argv, quiet) { return 0; };
export function ubus_call(object, method, args) {
 push(global.calls, method);
 if (method == 'set') { global.spec = args.instances.global; return null; }
 if (method == 'list') return shift(global.responses);
 return null;
};
''')
    script = root / 'test.uc'
    script.write_text('''
import { start } from 'passwall.core_service';
function healthy() { return {passwall_core:{instances:{global:{running:true,pid:42,respawn:{threshold:3600,timeout:5,retry:0}}}}}; }
function test(responses, success) {
 global.responses = responses; global.calls = [];
 let ok = true;
 try { start('/usr/bin/xray', [], '/dev/null', {}); } catch (e) { ok = false; }
 if (ok != success) die('Unexpected readiness result');
 if (!ok && global.calls[length(global.calls)-1] != 'delete') die('Failed instance not cleaned');
 if (type(global.spec.respawn) != 'array' || global.spec.respawn[1] !== '5') die('Incorrect procd wire format');
}
test([healthy()], true); // empty successful set response is valid
test([null, healthy()], true); // asynchronous registration
test([{passwall_core:{}}], false); // service name alone is insufficient
let missing = healthy(); delete missing.passwall_core.instances.global.respawn;
test([missing], false);
let stopped = healthy(); stopped.passwall_core.instances.global.running = false;
test([stopped], false);
test([null], false);
print('6 ubus readiness regressions passed\\n');
''')
    subprocess.run([os.environ.get('UCODE', '/tmp/passwall-ucode-wrapper'), '-L', str(root), str(script)], check=True)
