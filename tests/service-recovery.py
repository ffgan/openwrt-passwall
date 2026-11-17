#!/usr/bin/env python3
"""Exercise the real restart orchestrator with failed child starts and private files."""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
UCODE = os.environ.get('UCODE', '/tmp/passwall-ucode-wrapper')
with tempfile.TemporaryDirectory(prefix='passwall-recovery-') as directory:
    root = Path(directory)
    modules = root / 'passwall'
    modules.mkdir()
    source = (ROOT / 'luci-app-passwall/root/usr/share/ucode/passwall/service.uc').read_text()
    for original, replacement in [('/etc/config/passwall', str(root / 'config')),
                                  ('/etc/passwall/last-good.conf', str(root / 'good')),
                                  ('/tmp/passwall-failed.conf', str(root / 'failed')),
                                  ('/var/lock', str(root / 'lock'))]:
        source = source.replace(original, replacement)
    (modules / 'service.uc').write_text(source)
    (root / 'uci.uc').write_text('export function cursor() { return {get:function(){return null;}}; };')
    (modules / 'api.uc').write_text('export function log(message) { };')
    (modules / 'xray_preflight.uc').write_text('export function preflight(server) { return global.preflight_ok; };')
    (modules / 'utils.uc').write_text('''
export function run(argv, quiet) {
    if (argv[2] == 'stop') { push(global.calls, 'stop'); return 0; }
    if (argv[2] == 'start') { push(global.calls, 'start'); return shift(global.starts); }
    return 0;
};
''')
    script = r'''
import * as fs from 'fs';
import { client } from 'passwall.service';
let base = ARGV[0];
function expect(ok, message) { if (!ok) die(message); }
fs.writefile(base + '/config', 'candidate');
fs.writefile(base + '/good', 'known-good');
global.calls = [];
global.starts = [1, 0];
global.preflight_ok = true;
expect(client('restart', ['restart']) == 1, 'Failed apply must report failure even after recovery');
expect(fs.readfile(base + '/config') == 'known-good', 'Restore old configuration');
expect(fs.readfile(base + '/failed') == 'candidate', 'Preserve rejected candidate');
expect(fs.stat(base + '/failed').mode == 0o600, 'Candidate credentials must be private');
expect(fs.stat(base + '/lock/passwall_ready.lock') != null, 'Restored instance must be ready');
expect(join(',', global.calls) == 'stop,start,stop,start', 'Ordered rollback');
global.calls = [];
global.preflight_ok = false;
expect(client('restart', ['restart']) == 1 && length(global.calls) == 0, 'Preflight failure must retain running instance');
global.preflight_ok = true;
global.starts = [0];
fs.writefile(base + '/config', 'new-good');
expect(client('restart', ['restart']) == 0, 'Successful apply');
expect(fs.readfile(base + '/good') == 'new-good', 'Promote successful configuration');
expect(fs.stat(base + '/good').mode == 0o600, 'Snapshot credentials must be private');
global.starts = [1, 1];
global.calls = [];
expect(client('restart', ['restart']) == 1, 'Recovery failure must be reported');
expect(fs.stat(base + '/lock/passwall_ready.lock') == null, 'Failed recovery cannot be ready');
expect(join(',', global.calls) == 'stop,start,stop,start,stop', 'Clean failed rollback');
print('13 service recovery assertions passed\n');
'''
    (root / 'test.uc').write_text(script)
    subprocess.run([UCODE, '-L', str(root), str(root / 'test.uc'), str(root)], check=True)
