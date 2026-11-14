#!/usr/bin/env python3
"""Download the newest published official Xray Release, including prereleases."""
import argparse
import hashlib
import io
import json
import os
import re
import tarfile
from pathlib import Path
import urllib.request
import zipfile

BASELINE = 'v26.11.9'
API = 'https://api.github.com/repos/XTLS/Xray-core/releases'


def fetch(url):
    headers = {'User-Agent': 'PassWall-Xray-compatibility'}
    token = os.environ.get('GH_TOKEN')
    if token and url.startswith('https://api.github.com/'):
        headers['Authorization'] = 'Bearer ' + token
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=120) as response:
        return response.read()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', default='latest')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.version == 'latest':
        releases = json.loads(fetch(API + '?per_page=100'))
        release = max((r for r in releases if not r['draft'] and r.get('published_at')),
                      key=lambda r: r['published_at'])
    else:
        release = json.loads(fetch(API + '/tags/' + args.version))
    asset = next(a for a in release['assets'] if a['name'] == 'Xray-linux-64.zip')
    payload = fetch(asset['browser_download_url'])
    digest = asset.get('digest', '')
    if not digest or not digest.startswith('sha256:'):
        raise RuntimeError('Official asset has no SHA-256 digest; refusing unverified download')
    if hashlib.sha256(payload).hexdigest() != digest.split(':', 1)[1]:
        raise RuntimeError('Xray archive SHA-256 mismatch')
    args.output.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        binary = archive.read('xray')
    executable = args.output / 'xray'
    executable.write_bytes(binary)
    executable.chmod(0o755)
    metadata = {k: release[k] for k in ('tag_name', 'prerelease', 'published_at', 'html_url', 'target_commitish')}
    metadata['asset_digest'] = digest
    commit = json.loads(fetch('https://api.github.com/repos/XTLS/Xray-core/commits/' + release['tag_name']))['sha']
    metadata['commit'] = commit
    source = fetch('https://codeload.github.com/XTLS/Xray-core/tar.gz/' + commit)
    inventory = {}
    with tarfile.open(fileobj=io.BytesIO(source), mode='r:gz') as archive:
        for entry in archive.getmembers():
            name = entry.name.split('/', 1)[-1]
            if name.startswith('infra/conf/') and name.endswith('.go') and not name.endswith('_test.go'):
                content = archive.extractfile(entry).read().decode()
                fields = sorted(set(re.findall(r'json:"([^",]+)', content)))
                if fields:
                    inventory[name] = fields
    (args.output / 'config-inventory.json').write_text(json.dumps(inventory, indent=2, sort_keys=True) + '\n')
    (args.output / 'release.json').write_text(json.dumps(metadata, indent=2) + '\n')
    print(json.dumps(metadata))


if __name__ == '__main__':
    main()
