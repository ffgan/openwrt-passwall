#!/usr/bin/env python3
"""Direct-DNS node address refresh, isolated from the live router."""
import json
import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parent.parent
script = root / 'luci-app-passwall/root/usr/libexec/passwall/refresh_node_addresses.sh'


def run(case):
    with tempfile.TemporaryDirectory(prefix='node-refresh-') as directory:
        work = Path(directory)
        bins = work / 'bin'
        bins.mkdir()
        state = {
            'passwall.@global[0].enabled': case['enabled'],
            'passwall.@global[0].node': case['active'],
            'passwall.ss': 'nodes',
            'passwall.ss.remarks': 'JMS-1@c71s1.example.com:32579',
            'passwall.ss.address': case['address'],
            'passwall.ss.port': '32579',
            'passwall.other': 'nodes',
            'passwall.other.remarks': 'DirectGame',
            'passwall.other.address': '1.2.3.4',
            'passwall.other.port': '443',
        }
        (work / 'state.json').write_text(json.dumps(state))
        (work / 'dns').write_text(case['dns'] + '\n')
        (work / 'open').write_text('\n'.join(case['open']) + '\n')
        (bins / 'uci').write_text(r"""#!/usr/bin/python3
import json, os, sys
from pathlib import Path
path = Path(os.environ['REFRESH_TEST_DIR']) / 'state.json'
state = json.loads(path.read_text())
args = [v for v in sys.argv[1:] if v != '-q']
if args[0] == 'get':
    value = state.get(args[1])
    if value is None:
        sys.exit(1)
    print(value)
elif args[0] == 'set':
    key, value = args[1].split('=', 1)
    state[key] = value
    path.write_text(json.dumps(state))
elif args[0] == 'commit':
    (Path(os.environ['REFRESH_TEST_DIR']) / 'committed').write_text('1')
elif args[0] == 'show':
    for key, value in state.items():
        if key.count('.') == 1:
            print(key + '=' + value)
""")
        (bins / 'nslookup').write_text(r"""#!/bin/sh
dns=$(cat "$REFRESH_TEST_DIR/dns")
echo "Server: $2"
echo "Address: $2:53"
echo "Name: $1"
echo "Address: $dns"
""")
        (bins / 'timeout').write_text('#!/bin/sh\nshift\nexec "$@"\n')
        (bins / 'nc').write_text(r"""#!/bin/sh
while read -r open; do
    [ "$open" = "$1:$2" ] && exit 0
done < "$REFRESH_TEST_DIR/open"
exit 1
""")
        (bins / 'logger').write_text(
            '#!/bin/sh\necho "$@" >> "$REFRESH_TEST_DIR/log"\n')
        restart = work / 'restart'
        restart.write_text('#!/bin/sh\necho restarted >> "$REFRESH_TEST_DIR/restarts"\n')
        restart.chmod(0o755)
        for path in bins.iterdir():
            path.chmod(0o755)
        env = os.environ | {
            'PATH': str(bins) + ':' + os.environ['PATH'],
            'REFRESH_TEST_DIR': str(work),
            'NODE_REFRESH_LOCKED': '1',
            'PASSWALL_RESTART': str(restart),
        }
        result = subprocess.run(
            ['sh', str(script)], env=env, check=False, timeout=5,
            capture_output=True, text=True)
        saved = json.loads((work / 'state.json').read_text())
        return result.returncode, saved, (work / 'restarts').exists(), (work / 'committed').exists()


cases = [
    ('same address', dict(enabled='1', active='ss', address='198.51.100.10',
                          dns='198.51.100.10', open=['198.51.100.10:32579']),
     '198.51.100.10', 0, False),
    ('old port still open', dict(enabled='1', active='ss', address='198.51.100.10',
                                 dns='198.51.100.20', open=['198.51.100.10:32579', '198.51.100.20:32579']),
     '198.51.100.10', 0, False),
    ('replace closed active node', dict(enabled='1', active='ss', address='198.51.100.10',
                                        dns='198.51.100.20', open=['198.51.100.20:32579']),
     '198.51.100.20', 2, True),
    ('replace closed inactive node', dict(enabled='1', active='other', address='198.51.100.10',
                                          dns='198.51.100.20', open=['198.51.100.20:32579']),
     '198.51.100.20', 0, False),
    ('both ports closed', dict(enabled='1', active='ss', address='198.51.100.10',
                               dns='198.51.100.20', open=[]),
     '198.51.100.10', 0, False),
    ('disabled does not restart', dict(enabled='0', active='ss', address='198.51.100.10',
                                       dns='198.51.100.20', open=['198.51.100.20:32579']),
     '198.51.100.20', 0, False),
]
for name, case, address, code, restarted in cases:
    got_code, saved, did_restart, committed = run(case)
    assert saved['passwall.ss.address'] == address, (name, saved)
    assert saved['passwall.other.address'] == '1.2.3.4', name
    assert got_code == code, (name, got_code)
    assert did_restart == restarted, name
    assert committed == (address != case['address']), name
print(f'{len(cases)} node address refresh scenarios passed')
