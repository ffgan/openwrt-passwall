#!/usr/bin/env python3
"""Run merge assertions and real-core checks with disposable fixture credentials."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import importlib.util
import sys

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parent.parent
UCODE = os.environ.get('UCODE', 'ucode')
XRAY = os.environ.get('XRAY', 'xray')


def run_ucode(script, *args):
    paths = [ROOT / 'tests/xray-stubs', ROOT / 'tests/stubs',
             ROOT / 'luci-app-passwall/root/usr/share/ucode']
    if os.environ.get('UCODE_LIB'):
        paths.append(Path(os.environ['UCODE_LIB']))
    argv = [UCODE]
    for path in paths:
        argv.extend(['-L', str(path)])
    subprocess.run([*argv, str(ROOT / 'tests' / script), *map(str, args)], check=True, timeout=120)


def main():
    run_ucode('xray-config.uc')
    results = []
    with tempfile.TemporaryDirectory(prefix='passwall-xray-fixtures-') as folder:
        run_ucode('xray-fixtures.uc', folder, XRAY)
        for config in sorted(Path(folder).glob('*.json')):
            result = subprocess.run([XRAY, 'run', '-test', '-c', str(config)],
                                    capture_output=True, text=True, timeout=30)
            results.append({'fixture': config.name, 'passed': result.returncode == 0})
            if result.returncode:
                # Fixtures contain only public disposable test credentials.
                print(config.name, result.stdout, result.stderr)
        # Network smoke checks use only local processes and temporary test credentials.
        spec = importlib.util.spec_from_file_location('xray_smoke', ROOT / 'tests/xray-smoke.py')
        smoke = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(smoke)
        results.extend(smoke.roundtrip(XRAY, folder))
    Path('/tmp/passwall-xray-results.json').write_text(json.dumps(results, indent=2) + '\n')
    failures = sum(not r['passed'] for r in results)
    print(f'{len(results)} core configuration/roundtrip checks; {failures} failures')
    if failures:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
