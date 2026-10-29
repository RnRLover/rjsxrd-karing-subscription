"""Isolated UDP DNS, LAN TCP and domain GeoIP checks for the common config.

Only this test injects a local resolver. It is never written to the subscription.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import threading
import time
ROOT = Path(__file__).resolve().parent
parser = argparse.ArgumentParser()
parser.add_argument('--xray', required=True)
parser.add_argument('--config', default='subscription.json')
parser.add_argument('--profile-index', type=int, default=0)
args = parser.parse_args()
from generate import xray_validate

def receive(sock, count):
    data = b''
    while len(data) < count:
        part = sock.recv(count - len(data))
        if not part:
            raise RuntimeError('unexpected EOF')
        data += part
    return data
dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
dns.bind(('127.0.0.1', 0))
echo = socket.socket()
echo.bind(('127.0.0.1', 0))
echo.listen()
real_queries = []

def dns_worker(server, queries):
    while True:
        try:
            request, addr = server.recvfrom(4096)
            queries.append(request)
            response = request[:2] + b'\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00' + request[12:] + b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00<\x00\x04' + socket.inet_aton('127.0.0.1')
            server.sendto(response, addr)
        except OSError:
            return

def echo_worker():
    conn, _ = echo.accept()
    with conn:
        conn.settimeout(10)
        if receive(conn, 4) != b'PING':
            raise RuntimeError('wrong TCP payload')
        conn.sendall(b'PONG')
threading.Thread(target=dns_worker, args=(dns, real_queries), daemon=True).start()
threading.Thread(target=echo_worker, daemon=True).start()
for alias in ('ru-karing-incy.txt', 'ru-karing-happ.txt'):
    assert (ROOT / alias).read_bytes() == (ROOT / 'subscription.json').read_bytes(), alias
text = (ROOT / args.config).read_text(encoding='utf-8')
config = json.loads(text)
if isinstance(config, list):
    config = config[args.profile_index]
assert 'dns' not in config and 'fakedns' not in config
assert config['routing']['domainStrategy'] == 'IPOnDemand'
assert not any((o.get('protocol') == 'dns' for o in config['outbounds']))
assert any((r.get('port') == '53' and r.get('outboundTag') == 'direct' for r in config['routing']['rules']))
for rule in config['routing']['rules']:
    if rule.get('port') == '53':
        rule['port'] = str(dns.getsockname()[1])
config['dns'] = {'servers': [{'address': '127.0.0.1', 'port': dns.getsockname()[1], 'tag': 'dns-bootstrap'}]}
config['routing']['rules'].insert(0, {'type': 'field', 'inboundTag': ['dns-bootstrap'], 'outboundTag': 'direct'})
config['log'] = {'loglevel': 'debug'}
config.pop('burstObservatory', None)
config['routing'].pop('balancers', None)
for rule in config['routing']['rules']:
    if 'balancerTag' in rule:
        rule.pop('balancerTag')
        rule['outboundTag'] = 'block'
for outbound in config['outbounds']:
    if outbound['tag'] == 'direct':
        outbound['settings'] = {'domainStrategy': 'UseIPv4'}
config['routing']['rules'].insert(3, {'type': 'field', 'domain': ['full:music.yandex.ru'], 'outboundTag': 'direct'})
for inbound in config['inbounds']:
    with socket.socket() as held:
        held.bind(('127.0.0.1', 0))
        inbound['port'] = held.getsockname()[1]
port = config['inbounds'][0]['port']
with tempfile.TemporaryDirectory() as temp:
    temp = Path(temp)
    needs_geo = any((value.startswith(('geoip:', 'geosite:', 'ext:')) for rule in config['routing']['rules'] for key in ('domain', 'ip') for value in rule.get(key, [])))
    if needs_geo:
        for name in ('geoip.dat', 'geosite.dat'):
            (temp / name).write_bytes((ROOT / '.runtime' / name).read_bytes())
    os.environ['XRAY_LOCATION_ASSET'] = str(temp)
    xray = Path(args.xray).resolve()
    xray_validate(xray, config)
    path = temp / 'config.json'
    path.write_text(json.dumps(config), encoding='utf-8')
    log = (temp / 'xray.log').open('w', encoding='utf-8')
    process = subprocess.Popen([str(xray), 'run', '-config', str(path)], stdout=log, stderr=log)
    try:
        control = None
        for _ in range(300):
            if process.poll() is not None:
                break
            try:
                control = socket.create_connection(('127.0.0.1', port), timeout=5)
                break
            except OSError:
                time.sleep(0.1)
        if control is None:
            log.flush()
            raise RuntimeError('Xray did not start: ' + (temp / 'xray.log').read_text(encoding='utf-8'))
        control.sendall(b'\x05\x01\x00')
        assert receive(control, 2) == b'\x05\x00'
        control.sendall(b'\x05\x03\x00\x01' + b'\x00' * 6)
        reply = receive(control, 10)
        assert reply[:4] == b'\x05\x00\x00\x01', reply
        relay = (socket.inet_ntoa(reply[4:8]), struct.unpack('!H', reply[8:])[0])
        query = b'\x124\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05music\x06yandex\x02ru\x00\x00\x01\x00\x01'
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.settimeout(5)
            destination = ('127.0.0.1', dns.getsockname()[1])
            udp.sendto(b'\x00\x00\x00\x01' + socket.inet_aton(destination[0]) + struct.pack('!H', destination[1]) + query, relay)
            response = udp.recv(4096)
        resolved_ip = socket.inet_ntoa(response[-4:])
        assert resolved_ip == '127.0.0.1', resolved_ip
        with socket.create_connection(('127.0.0.1', port), timeout=10) as tcp:
            tcp.sendall(b'\x05\x01\x00')
            assert receive(tcp, 2) == b'\x05\x00'
            tcp.sendall(b'\x05\x01\x00\x01' + socket.inet_aton(resolved_ip) + struct.pack('!H', echo.getsockname()[1]))
            assert receive(tcp, 10)[:2] == b'\x05\x00'
            tcp.sendall(b'PING')
            assert receive(tcp, 4) == b'PONG'
        threading.Thread(target=echo_worker, daemon=True).start()
        with socket.create_connection(('127.0.0.1', port), timeout=10) as tcp:
            tcp.sendall(b'\x05\x01\x00')
            assert receive(tcp, 2) == b'\x05\x00'
            domain = b'geoip-only.invalid'
            tcp.sendall(b'\x05\x01\x00\x03' + bytes([len(domain)]) + domain + struct.pack('!H', echo.getsockname()[1]))
            assert receive(tcp, 10)[:2] == b'\x05\x00'
            tcp.sendall(b'PING')
            assert receive(tcp, 4) == b'PONG'
        assert any((b'geoip-only' in query for query in real_queries)), 'GeoIP domain lookup was not exercised'
        assert real_queries, 'local DNS exchange was not exercised'
        print(json.dumps({'client_dns_destination_preserved': True, 'LAN_tcp_roundtrip': True, 'domain_geoip_roundtrip': True}))
        control.close()
    except Exception:
        log.flush()
        print((temp / 'xray.log').read_text(encoding='utf-8')[-18000:])
        raise
    finally:
        process.terminate()
        process.wait(timeout=5)
        log.close()
dns.close()
echo.close()
