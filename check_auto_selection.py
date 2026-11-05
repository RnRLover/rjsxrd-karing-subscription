"""Exercise live technology ranking and member/group failover in real Xray."""
import copy
import json
import os
from pathlib import Path
from socketserver import BaseRequestHandler, ThreadingTCPServer
import socket
import struct
import subprocess
import tempfile
import threading
import time
from check_subscription import receive
from generate import xray_validate
from russia_config import build, read_policy
from technology_selection import PROXY_PROTOCOLS

ROOT = Path(__file__).resolve().parent


def fixture(label, delay):
    state = {'healthy': True, 'delay': delay, 'probes': 0}
    class Handler(BaseRequestHandler):
        def handle(self):
            try:
                self.request.settimeout(2)
                data = self.request.recv(4096)
                if not state['healthy']:
                    return
                if data.startswith((b'HEAD ', b'GET ')):
                    state['probes'] += 1
                    time.sleep(state['delay'])
                    self.request.sendall(b'HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
                elif data:
                    self.request.sendall(label)
            except OSError:
                pass
    server = ThreadingTCPServer(('127.0.0.1', 0), Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, state


def main(xray):
    original = json.loads((ROOT / 'subscription.json').read_bytes())[0]
    base = copy.deepcopy(original)
    # Two technologies, with two members each. Production routing and the
    # selection builder stay active; node transports become local fixtures.
    base['outbounds'] = [
        {'tag': tag, 'protocol': protocol,
         'streamSettings': {'network': 'tcp', 'security': security}}
        for tag, protocol, security in [('fixture-a1', 'vless', 'reality'),
                                         ('fixture-a2', 'vless', 'reality'),
                                         ('fixture-b1', 'trojan', 'tls'),
                                         ('fixture-b2', 'trojan', 'tls')]]
    config = build(base, read_policy())
    # Only technology-specific rules differ when the pool has different groups.
    regular_rules = lambda c: [r for r in c['routing']['rules']
                               if not r.get('inboundTag', [''])[0].startswith('technology-in-')]
    assert regular_rules(config) == regular_rules(original)
    fixtures = [fixture(label, delay) for label, delay in
                [(b'A1', .01), (b'A2', .14), (b'B1', .07), (b'B2', .24)]]
    state = {label: item[1] for label, item in zip(('A1', 'A2', 'B1', 'B2'), fixtures)}
    proxies = [o for o in config['outbounds'] if o['protocol'] in PROXY_PROTOCOLS]
    for outbound, (server, _) in zip(proxies, fixtures):
        tag = outbound['tag']
        outbound.clear()
        outbound.update(tag=tag, protocol='freedom',
                        settings={'redirect': f'127.0.0.1:{server.server_address[1]}'})
    assert len(config['routing']['balancers']) == 3
    config['burstObservatory']['pingConfig'] = {
        'destination': 'http://8.8.8.8/probe', 'interval': '10s',
        'sampling': 1, 'timeout': '1s', 'httpMethod': 'HEAD'}
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
            def wait_for(label, seconds=45):
                deadline = time.monotonic() + seconds
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        raise RuntimeError('Xray stopped')
                    try:
                        if request() == label and all(s['probes'] for s in state.values()):
                            return
                    except (OSError, RuntimeError):
                        pass
                    time.sleep(.2)
                raise AssertionError('Balancer did not select ' + label.decode())
            try:
                wait_for(b'A1')
                print('Technology check: fastest member selected', flush=True)
                # A remains healthy but its fastest member is now slower
                # than B1. A fixed fallback chain would fail this check.
                state['A1']['delay'] = .35
                wait_for(b'B1')
                print('Technology check: priority moved to faster technology', flush=True)
                state['B1']['healthy'] = False
                wait_for(b'A2')
                print('Technology check: priority recalculated after member failure', flush=True)
                state['A1']['healthy'] = state['A2']['healthy'] = False
                wait_for(b'B2')
                print('Technology check: unavailable group bypassed; backup member selected', flush=True)
                state['A2']['healthy'] = True
                wait_for(b'A2')
                print(json.dumps({'fastest_member_selected': True,
                                  'technology_priority_changed_with_latency': True,
                                  'failed_member_replaced': True,
                                  'failed_group_replaced': True,
                                  'recovered_group_reranked': True,
                                  'probe_counts': {k: s['probes'] for k, s in state.items()},
                                  'fixture_probe_interval': '10s',
                                  'production_probe_interval': read_policy()['probe']['interval']}, ensure_ascii=False))
            except Exception:
                log.flush()
                print(log_path.read_text()[-6000:])
                raise
            finally:
                process.terminate()
                process.wait(timeout=5)
                for server, _ in fixtures:
                    server.shutdown()
                    server.server_close()


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--xray', required=True)
    main(parser.parse_args().xray)
