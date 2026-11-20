#!/usr/bin/env python3
"""Run the shipped guard with isolated UCI, curl and restart commands."""
import json
import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parent.parent
source = (root / 'luci-app-passwall/root/usr/libexec/passwall/reality_guard.sh').read_text()
with tempfile.TemporaryDirectory(prefix='reality-guard-') as directory:
    work = Path(directory)
    bins = work / 'bin'
    bins.mkdir()
    state = work / 'state.json'
    ready = work / 'ready'
    ready.touch()
    restart = work / 'restart'
    restart.write_text('#!/bin/sh\necho restarted >> "$GUARD_TEST_DIR/restarts"\n')
    restart.chmod(0o755)
    runner = source.replace('while :; do', 'for iteration in 1 2 3 4 5 6; do')
    runner = runner.replace('/var/lock/passwall_ready.lock', str(ready))
    runner = runner.replace('/etc/init.d/passwall restart', str(restart))
    (work / 'guard.sh').write_text(runner)
    (bins / 'uci').write_text("""#!/usr/bin/python3
import json,os,sys
from pathlib import Path
path=Path(os.environ['GUARD_TEST_DIR'])/'state.json'
state=json.loads(path.read_text()); args=[v for v in sys.argv[1:] if v!='-q']
if args[0]=='get':
 value=state.get(args[1])
 if value is None: sys.exit(1)
 print(value)
elif args[0]=='set':
 key,value=args[1].split('=',1); state[key]=value; path.write_text(json.dumps(state))
elif args[0]=='show':
 for key,value in state.items():
  if key.endswith('.type'): print(key+"='"+value+"'")
""")
    (bins / 'curl').write_text("""#!/bin/sh
if [ "$PROBE_MODE" = one_good ]; then
 case "$*" in *cloudflare*) exit 0;; esac
fi
exit 1
""")
    for name in ['sleep', 'logger']:
        (bins / name).write_text('#!/bin/sh\nexit 0\n')
    (bins / 'timeout').write_text('#!/bin/sh\nshift\nexec "$@"\n')
    (bins / 'nc').write_text('#!/bin/sh\n[ "$1" = "198.51.100.8" ] && exit 0\nexit 1\n')
    for path in bins.iterdir():
        path.chmod(0o755)
    base = {
        'passwall.@global[0].enabled':'1',
        'passwall.@global[0].reality_auto_fallback':'1',
        'passwall.@global[0].node':'native',
        'passwall.@global[0].reality_fallback_node':'stale_subscription_id',
        'passwall.native.type':'Reality',
        'passwall.ss.type':'SS-Rust',
    }
    for mode, changes, expect in [
        ('failed', {}, 'ss'),
        ('one_good', {}, 'native'),
        ('failed', {'passwall.@global[0].node':'ss'}, 'ss'),
        ('failed', {'passwall.@global[0].node':'ss',
                    'passwall.native.address':'198.51.100.8',
                    'passwall.native.port':'443'}, 'native'),
        ('failed', {'passwall.@global[0].enabled':'0'}, 'native'),
        ('failed', {'passwall.@global[0].reality_auto_fallback':'0'}, 'native'),
    ]:
        config = base | changes
        state.write_text(json.dumps(config))
        (work / 'restarts').unlink(missing_ok=True)
        env = os.environ | {'PATH':str(bins)+':'+os.environ['PATH'],
                           'GUARD_TEST_DIR':str(work), 'PROBE_MODE':mode}
        subprocess.run(['sh',str(work/'guard.sh')],env=env,check=True,timeout=5)
        result = json.loads(state.read_text())
        assert result['passwall.@global[0].node']==expect, (mode,result)
        switched = config['passwall.@global[0].node']!=expect
        assert (work/'restarts').exists()==switched
    print('6 fallback scenarios passed (REALITY to SS, and dead SS to an open REALITY port)')
