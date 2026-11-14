"""Exercise published routing in Xray using isolated TCP/UDP transport fixtures.

Production rules, sniffing and balancer selectors stay unchanged. Only outbound
transports, inbound ports, probe subjects and the test DNS resolver are replaced.
The fixture resolver and redirects are never written to the subscription.
All production routing rules remain active, including reference geosite blocking.
"""
import argparse
import copy
import ipaddress
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import threading
import time

from incy import xray_validate, load_configs

ROOT = Path(__file__).resolve().parent


def receive(sock, count):
    data = b''
    while len(data) < count:
        part = sock.recv(count - len(data))
        if not part:
            raise RuntimeError('unexpected EOF')
        data += part
    return data


def tcp_fixture(label):
    server = socket.socket()
    server.bind(('127.0.0.1', 0))
    server.listen()
    def worker():
        while True:
            try:
                conn, _ = server.accept()
                with conn:
                    conn.settimeout(5)
                    if conn.recv(4096):
                        conn.sendall(label)
            except OSError:
                return
    threading.Thread(target=worker, daemon=True).start()
    return server


def check_profile(args):
    original = load_configs(ROOT / args.config)
    if isinstance(original, list):
        original = original[args.profile_index]
    assert 'dns' in original and 'fakedns' not in original
    assert original['routing']['domainStrategy'] == 'AsIs'
    assert not any(o['protocol'] in ('dns', 'loopback') for o in original['outbounds'])
    assert original['routing']['rules'][-1] == {
        'type': 'field', 'network': 'tcp,udp', 'balancerTag': 'balancer'}
    config = copy.deepcopy(original)
    direct = tcp_fixture(b'DIRECT')
    proxy = tcp_fixture(b'PROXY')
    dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dns.bind(('127.0.0.1', direct.getsockname()[1]))
    dns_queries = []
    def dns_worker():
        while True:
            try:
                request, addr = dns.recvfrom(4096)
                pos, parts = 12, []
                while request[pos]:
                    length = request[pos]
                    parts.append(request[pos+1:pos+1+length].decode())
                    pos += length + 1
                name = '.'.join(parts)
                dns_queries.append(name)
                address = ('0.0.0.0' if name in ('doubleclick.net', 'ads.adfox.ru') else
                           '77.88.8.8' if name == 'geoip-only.fixture-domain.com' else '8.8.8.8')
                answer = (request[:2] + b'\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00'
                          + request[12:pos+5] + b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'
                          + socket.inet_aton(address))
                if struct.unpack('!H', request[pos+1:pos+3])[0] == 28:
                    # No IPv6 address in this routing fixture; still return a
                    # valid empty AAAA response when dual-stack DNS asks.
                    answer = request[:2] + b'\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00' + request[12:pos+5]
                dns.sendto(answer, addr)
            except OSError:
                return
    threading.Thread(target=dns_worker, daemon=True).start()
    for outbound in config['outbounds']:
        if outbound['tag'] == 'block' or outbound['protocol'] == 'dns':
            continue
        port = (direct if outbound['tag'] == 'direct' else proxy).getsockname()[1]
        tag = outbound['tag']
        outbound.clear()
        outbound.update(tag=tag, protocol='freedom',
                        settings={'redirect': f'127.0.0.1:{port}'})
    for inbound in config['inbounds']:
        with socket.socket() as held:
            held.bind(('127.0.0.1', 0))
            inbound['port'] = held.getsockname()[1]
    config['dns']['servers'] = [{'address': '127.0.0.1', 'port': dns.getsockname()[1],
                                 'tag': 'dns-remote'}]
    config['burstObservatory']['subjectSelector'] = ['unused-test-subject']
    config['log'] = {'loglevel': 'debug'}
    assert config['routing'] == original['routing']
    port = next(i['port'] for i in config['inbounds'] if i['protocol'] == 'socks')
    with tempfile.TemporaryDirectory() as directory:
        directory = Path(directory)
        for name in ('geoip.dat', 'geosite.dat'):
            (directory / name).write_bytes((ROOT / '.runtime' / name).read_bytes())
        os.environ['XRAY_LOCATION_ASSET'] = str(directory)
        xray = str(Path(args.xray).resolve())
        xray_validate(xray, config)
        path = directory / 'config.json'
        path.write_text(json.dumps(config), encoding='utf-8')
        with (directory / 'xray.log').open('w') as log:
            process = subprocess.Popen([xray, 'run', '-config', str(path)], stdout=log, stderr=log)
            try:
                for _ in range(100):
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=.2):
                            break
                    except OSError:
                        if process.poll() is not None:
                            raise RuntimeError('Xray stopped before probe')
                        time.sleep(.05)
                def request(host, payload=b'PING'):
                    with socket.create_connection(('127.0.0.1', port), timeout=5) as conn:
                        conn.settimeout(5)
                        conn.sendall(b'\x05\x01\x00')
                        assert receive(conn, 2) == b'\x05\x00'
                        try:
                            ip = ipaddress.ip_address(host)
                            address = bytes([1 if ip.version == 4 else 4]) + ip.packed
                        except ValueError:
                            encoded = host.encode('idna')
                            address = b'\x03' + bytes([len(encoded)]) + encoded
                        conn.sendall(b'\x05\x01\x00' + address + struct.pack('!H', 443))
                        assert receive(conn, 10)[:2] == b'\x05\x00'
                        conn.sendall(payload)
                        try:
                            value = conn.recv(16)
                        except ConnectionResetError:
                            value = b''
                        return value.decode() if value else 'BLOCK'
                cases = [
                    ('RU service', 'vk.com', 'DIRECT'),
                    ('Yandex', 'yandex.ru', 'DIRECT'),
                    ('Proxy exception before RU category', 'habr.com', 'PROXY'),
                    ('Russian proxy exception', 'theins.ru', 'PROXY'),
                    ('SU proxy exception', 'jut.su', 'PROXY'),
                    ('Apple direct category', 'apple.com', 'DIRECT'),
                    ('Twitch direct category', 'twitch.tv', 'DIRECT'),
                    ('Private domain', 'localhost', 'DIRECT'),
                    ('GitHub now follows the reference default', 'github.com', 'PROXY'),
                    ('GitHub raw', 'raw.githubusercontent.com', 'PROXY'),
                    ('RU IP', '77.88.8.8', 'DIRECT'),
                    ('RU IPv6 literal', '2a02:6b8::1', 'DIRECT'),
                    ('AsIs does not resolve a hostname for GeoIP', 'geoip-only.fixture-domain.com', 'PROXY'),
                    ('LAN IPv4', '192.168.1.1', 'DIRECT'),
                    ('LAN IPv6 literal', 'fd00::1', 'DIRECT'),
                    ('Foreign IP', '8.8.8.8', 'PROXY'),
                    ('Foreign domain', 'foreign.fixture-domain.com', 'PROXY'),
                    ('Geosite ad block', 'doubleclick.net', 'BLOCK'),
                    ('Windows telemetry block', 'vortex.data.microsoft.com', 'BLOCK')]
                results = []
                for label, host, expected in cases:
                    actual = request(host)
                    results.append({'case': label, 'destination': host,
                                    'expected': expected, 'actual': actual})
                actual = request('8.8.8.8', b'GET / HTTP/1.1\r\nHost: vk.com\r\n\r\n')
                results.append({'case': 'Sniffed RU host', 'expected': 'DIRECT', 'actual': actual})
                actual = request('8.8.8.8', b'GET / HTTP/1.1\r\nHost: raw.githubusercontent.com\r\n\r\n')
                results.append({'case': 'Sniffed GitHub host', 'expected': 'PROXY', 'actual': actual})
                actual = request('8.8.8.8', b'\x13BitTorrent protocol' + b'\x00' * 48)
                results.append({'case': 'BitTorrent direct', 'expected': 'DIRECT', 'actual': actual})
                assert 'geoip-only.fixture-domain.com' not in dns_queries
                print(json.dumps({'routing_rules_unchanged': True, 'loyalsoldier_categories_checked': True,
                                  'reference_AsIs_and_protocol_routes_checked': True,
                                  'results': results}, ensure_ascii=False))
                assert all(r['actual'] == r['expected'] for r in results), 'Routing regression'
            except Exception:
                log.flush()
                print((directory / 'xray.log').read_text()[-12000:])
                raise
            finally:
                process.terminate()
                process.wait(timeout=5)
                dns.close()
                direct.close()
                proxy.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--xray', required=True)
    parser.add_argument('--config', default='subscription.json')
    parser.add_argument('--profile-index', type=int, default=None)
    args = parser.parse_args()
    content = load_configs(ROOT / args.config)
    indices = ([args.profile_index] if args.profile_index is not None else
               range(len(content)) if isinstance(content, list) else [0])
    for index in indices:
        print('Checking profile', index, flush=True)
        check_profile(argparse.Namespace(xray=args.xray, config=args.config, profile_index=index))


if __name__ == '__main__':
    main()
