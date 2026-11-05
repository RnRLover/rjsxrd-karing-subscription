"""Exercise real leastPing selection and failover using local HTTP fixtures."""
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
from generate import xray_validate

ROOT = Path(__file__).resolve().parent


def fixture(label, delay):
    state = {'healthy': True, 'probes': 0}
    server = socket.socket()
    server.bind(('127.0.0.1', 0))
    server.listen()
    def worker():
        while True:
            try:
                conn, _ = server.accept()
                with conn:
                    conn.settimeout(2)
                    data = conn.recv(4096)
                    if data.startswith((b'HEAD ', b'GET ')):
                        state['probes'] += 1
                        time.sleep(delay)
                        if state['healthy']:
                            conn.sendall(b'HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
                    elif data:
                        conn.sendall(label)
            except OSError:
                return
    threading.Thread(target=worker, daemon=True).start()
    return server, state


def main(xray):
    original = json.loads((ROOT / 'subscription.json').read_bytes())[0]
    config = copy.deepcopy(original)
    proxies = [o for o in config['outbounds'] if o['protocol'] in ('vless','vmess','trojan','shadowsocks')][:2]
    assert len(proxies) == 2
    fast, first = fixture(b'FAST', .01)
    backup, second = fixture(b'BACKUP', .15)
    selected = [o['tag'] for o in proxies]
    config['outbounds'] = [o for o in config['outbounds'] if o['protocol'] not in ('vless','vmess','trojan','shadowsocks')]
    for node, server in zip(proxies, (fast, backup)):
        config['outbounds'].append({'tag': node['tag'], 'protocol': 'freedom',
                                   'settings': {'redirect': f'127.0.0.1:{server.getsockname()[1]}'}})
    balancer = config['routing']['balancers'][0]
    assert balancer['strategy'] == {'type': 'leastPing'}
    balancer['selector'] = selected
    config['burstObservatory'] = {'subjectSelector': selected, 'pingConfig': {
        'destination': 'http://8.8.8.8/probe', 'interval': '10s', 'sampling': 1, 'timeout': '1s'}}
    config.pop('geodata', None)
    config['log'] = {'loglevel': 'info'}
    for inbound in config['inbounds']:
        with socket.socket() as held:
            held.bind(('127.0.0.1', 0))
            inbound['port'] = held.getsockname()[1]
    port = next(i['port'] for i in config['inbounds'] if i['protocol'] == 'socks')
    os.environ['XRAY_LOCATION_ASSET'] = str(ROOT / '.runtime')
    xray_validate(xray, config)
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory, 'config.json')
        path.write_text(json.dumps(config))
        log_path = Path(directory, 'core.log')
        with log_path.open('w') as log:
            process = subprocess.Popen([str(Path(xray).resolve()), 'run', '-c', str(path)], stdout=log, stderr=log)
            def request():
                with socket.create_connection(('127.0.0.1', port), timeout=2) as conn:
                    conn.settimeout(2)
                    conn.sendall(b'\x05\x01\x00')
                    assert receive(conn, 2) == b'\x05\x00'
                    conn.sendall(b'\x05\x01\x00\x01' + socket.inet_aton('8.8.4.4') + struct.pack('!H', 443))
                    assert receive(conn, 10)[:2] == b'\x05\x00'
                    conn.sendall(b'PING')
                    return conn.recv(16)
            def wait_for(label, seconds):
                deadline = time.monotonic() + seconds
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        raise RuntimeError('Xray stopped')
                    try:
                        if request() == label and first['probes'] and second['probes']:
                            return
                    except OSError:
                        pass
                    time.sleep(.2)
                raise AssertionError('Balancer did not select ' + label.decode())
            try:
                wait_for(b'FAST', 15)
                first['healthy'] = False
                wait_for(b'BACKUP', 25)
                print(json.dumps({'leastPing_selected_fast': True, 'failed_fast_switched_to_backup': True,
                                  'probe_counts': [first['probes'], second['probes']],
                                  'fixture_probe_interval': '10s', 'production_probe_interval': '30s'}, ensure_ascii=False))
            except Exception:
                log.flush()
                print(log_path.read_text()[-6000:])
                raise
            finally:
                process.terminate()
                process.wait(timeout=5)
                fast.close()
                backup.close()


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--xray', required=True)
    main(parser.parse_args().xray)
