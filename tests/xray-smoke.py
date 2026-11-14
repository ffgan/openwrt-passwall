"""Local SOCKS -> generated Xray client/server -> HTTP round trips.

This deliberately removes TProxy and SO_MARK from the disposable configurations;
OpenWrt nftables/UDP/IPv6 tests remain separate integration requirements.
"""
import http.server
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'passwall-xray-roundtrip'
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def receive(sock, count):
    data = b''
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise RuntimeError('Unexpected EOF')
        data += chunk
    return data


def roundtrip(binary, folder):
    fixture_path = Path(folder)
    results = []
    service = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=service.serve_forever, daemon=True).start()
    try:
        names = ['client-vless-' + t for t in ['raw', 'mkcp', 'ws', 'grpc', 'httpupgrade', 'xhttp', 'xdrive']]
        names += ['client-' + p + '-raw' for p in ['vmess', 'trojan', 'shadowsocks']]
        for name in names:
            client = json.loads((fixture_path / (name + '.json')).read_text())
            protocol = name.split('-')[1]
            server_name = 'server-' + protocol + ('-' + name.split('-')[2] if not name.endswith('-raw') else '')
            server = json.loads((fixture_path / (server_name + '.json')).read_text())
            server_port, socks_port = port(), port()
            outbound = next(o for o in client['outbounds'] if o['tag'] == 'node')
            settings = outbound['settings']
            if protocol in ('vless', 'vmess'):
                settings['vnext'][0]['port'] = server_port
            else:
                settings['port'] = server_port
            for item in client['outbounds']:
                item.get('streamSettings', {}).get('sockopt', {}).pop('mark', None)
            server['inbounds'][0]['listen'] = '127.0.0.1'
            server['inbounds'][0]['port'] = server_port
            server['inbounds'][0]['streamSettings'].pop('sockopt', None)
            client['inbounds'] = [i for i in client['inbounds'] if i['tag'] == 'socks-in']
            client['inbounds'][0]['port'] = socks_port
            client['log'] = server['log'] = {'loglevel': 'error'}
            processes = []
            error = None
            with tempfile.TemporaryDirectory(prefix='passwall-xray-smoke-') as work:
                if name.endswith('-xdrive'):
                    shared = str(Path(work) / 'drive')
                    for config in (outbound, server['inbounds'][0]):
                        config['streamSettings']['xdriveSettings']['remoteFolder'] = shared
                    server['inbounds'][0]['settings']['decryption'] = 'mlkem768x25519plus.native.600s.wMlRKRTz7bfF5PxJeEz6xNCOBQqGp7TcNiQsNEIu5Gs'
                try:
                    for label, config in [('server', server), ('client', client)]:
                        path = Path(work) / (label + '.json')
                        path.write_text(json.dumps(config))
                        path.chmod(0o600)
                        processes.append(subprocess.Popen([binary, 'run', '-c', str(path)],
                                                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
                    deadline = time.monotonic() + 5
                    while True:
                        try:
                            sock = socket.create_connection(('127.0.0.1', socks_port), timeout=0.2)
                            break
                        except OSError:
                            if time.monotonic() >= deadline or any(p.poll() is not None for p in processes):
                                raise RuntimeError('Core did not start')
                            time.sleep(0.05)
                    with sock:
                        sock.settimeout(15)
                        sock.sendall(b'\x05\x01\x00')
                        if receive(sock, 2) != b'\x05\x00':
                            raise RuntimeError('SOCKS authentication failed')
                        sock.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01' + service.server_port.to_bytes(2, 'big'))
                        reply = receive(sock, 4)
                        if reply[1] != 0:
                            raise RuntimeError('SOCKS CONNECT failed')
                        length = {1: 4, 4: 16}.get(reply[3])
                        if length is None:
                            length = receive(sock, 1)[0]
                        receive(sock, length + 2)
                        sock.sendall(b'GET / HTTP/1.0\r\nHost: localhost\r\n\r\n')
                        data = b''
                        while b'passwall-xray-roundtrip' not in data:
                            chunk = sock.recv(4096)
                            if not chunk:
                                raise RuntimeError('HTTP response truncated')
                            data += chunk
                except (OSError, RuntimeError) as exc:
                    error = str(exc)
                finally:
                    for process in processes:
                        process.terminate()
                    for process in processes:
                        try:
                            process.wait(timeout=3)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait()
            results.append({'roundtrip': name, 'passed': error is None, 'error': error})
            print(name, 'roundtrip passed' if error is None else error)
    finally:
        service.shutdown()
        service.server_close()
    return results
