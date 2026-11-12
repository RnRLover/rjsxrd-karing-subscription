"""Exercise the DNS direct socket's production IPv4/IPv6 TCP fallback locally."""
import argparse
import copy
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import threading
import time

from check_subscription import receive
from incy import load_configs, ROOT


def fixture(family, label):
    server = socket.socket(family, socket.SOCK_STREAM)
    server.bind(('127.0.0.1' if family == socket.AF_INET else '::1', 0))
    server.listen()
    def worker():
        while True:
            try:
                conn, _ = server.accept()
                with conn:
                    conn.settimeout(3)
                    if conn.recv(4096):
                        conn.sendall(label)
            except OSError:
                return
    threading.Thread(target=worker, daemon=True).start()
    return server


def main(xray):
    config = copy.deepcopy(load_configs(ROOT / 'subscription.json')[0])
    ipv4 = fixture(socket.AF_INET, b'IPv4')
    ipv6 = fixture(socket.AF_INET6, b'IPv6')
    config['dns']['hosts'].update({
        'ipv4-only.fixture-domain.ru': ['127.0.0.1', '::1'],
        'ipv6-only.fixture-domain.ru': ['127.0.0.1', '::1']})
    # Only the DNS transport goes directly in production. Send fixture requests
    # through its real Freedom socket, preserving its DNS and Happy Eyeballs.
    config['routing']['rules'].insert(0, {'type': 'field',
        'domain': ['full:ipv4-only.fixture-domain.ru', 'full:ipv6-only.fixture-domain.ru'],
        'outboundTag': 'direct'})
    config['burstObservatory']['subjectSelector'] = ['unused-test-subject']
    for inbound in config['inbounds']:
        with socket.socket() as held:
            held.bind(('127.0.0.1', 0))
            inbound['port'] = held.getsockname()[1]
    port = config['inbounds'][0]['port']
    config['log'] = {'loglevel': 'debug'}
    env = {**os.environ, 'XRAY_LOCATION_ASSET': str(ROOT / '.runtime')}
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory, 'config.json')
        path.write_text(json.dumps(config))
        with Path(directory, 'core.log').open('w+') as log:
            process = subprocess.Popen([str(Path(xray).resolve()), 'run', '-c', str(path)],
                                       stdout=log, stderr=log, env=env)
            try:
                deadline = time.monotonic() + 5
                while True:
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=.1):
                            break
                    except OSError:
                        if process.poll() is not None or time.monotonic() > deadline:
                            raise RuntimeError('dual-stack fixture core did not start')
                        time.sleep(.05)
                def request(host, dest_port):
                    with socket.create_connection(('127.0.0.1', port), timeout=3) as conn:
                        conn.settimeout(4)
                        conn.sendall(b'\x05\x01\x00')
                        assert receive(conn, 2) == b'\x05\x00'
                        encoded = host.encode()
                        conn.sendall(b'\x05\x01\x00\x03' + bytes([len(encoded)]) + encoded
                                     + struct.pack('!H', dest_port))
                        assert receive(conn, 10)[:2] == b'\x05\x00'
                        conn.sendall(b'GET / HTTP/1.1\r\nHost: ' + encoded + b'\r\n\r\n')
                        return conn.recv(16)
                assert request('ipv4-only.fixture-domain.ru', ipv4.getsockname()[1]) == b'IPv4'
                # There is no IPv4 listener on the IPv6 fixture's port. The
                # production IPv4-first Happy Eyeballs must try IPv6 next.
                assert request('ipv6-only.fixture-domain.ru', ipv6.getsockname()[1]) == b'IPv6'
                print(json.dumps({'direct_builtin_dns_used': True, 'IPv4_connected': True,
                                  'IPv6_connected_after_IPv4_failure': True}))
            except Exception:
                log.flush()
                print(Path(directory, 'core.log').read_text()[-5000:])
                raise
            finally:
                process.terminate()
                process.wait(timeout=5)
                ipv4.close()
                ipv6.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--xray', required=True)
    main(parser.parse_args().xray)
