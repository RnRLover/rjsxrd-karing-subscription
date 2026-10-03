"""Local integration probe: UDP FakeDNS then TCP to its synthetic address."""
import argparse
import json
import ipaddress
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parent
parser = argparse.ArgumentParser()
parser.add_argument('--xray', required=True)
args = parser.parse_args()
from karing import automatic_config, with_fakedns
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


def dns_worker():
    while True:
        try:
            request, addr = dns.recvfrom(4096)
            real_queries.append(request)
            response = request[:2] + b'\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00' + request[12:] + b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04' + socket.inet_aton('127.0.0.1')
            dns.sendto(response, addr)
        except OSError:
            return


def echo_worker():
    conn, _ = echo.accept()
    with conn:
        conn.settimeout(10)
        if receive(conn, 4) != b'PING':
            raise RuntimeError('wrong TCP payload')
        conn.sendall(b'PONG')


threading.Thread(target=dns_worker, daemon=True).start()
threading.Thread(target=echo_worker, daemon=True).start()
config = with_fakedns(automatic_config(json.loads((ROOT / 'ru-karing.json').read_bytes())))
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
config['dns']['servers'][1] = {'address': '127.0.0.1', 'port': dns.getsockname()[1]}
config['routing']['rules'].insert(2, {'type': 'field', 'domain': ['full:fake.test'], 'outboundTag': 'direct'})
for inbound in config['inbounds']:
    with socket.socket() as held:
        held.bind(('127.0.0.1', 0))
        inbound['port'] = held.getsockname()[1]
port = config['inbounds'][0]['port']
with tempfile.TemporaryDirectory() as temp:
    temp = Path(temp)
    for name in ('geoip.dat', 'geosite.dat'):
        (temp / name).write_bytes((ROOT / ('karing-' + name)).read_bytes())
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
        query = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x04fake\x04test\x00\x00\x01\x00\x01'
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.settimeout(5)
            udp.sendto(b'\x00\x00\x00\x01' + socket.inet_aton('1.1.1.1') + b'\x00\x35' + query, relay)
            response = udp.recv(4096)
        fake_ip = socket.inet_ntoa(response[-4:])
        assert ipaddress.ip_address(fake_ip) in ipaddress.ip_network('198.18.0.0/15'), fake_ip
        with socket.create_connection(('127.0.0.1', port), timeout=10) as tcp:
            tcp.sendall(b'\x05\x01\x00')
            assert receive(tcp, 2) == b'\x05\x00'
            tcp.sendall(b'\x05\x01\x00\x01' + socket.inet_aton(fake_ip) + struct.pack('!H', echo.getsockname()[1]))
            assert receive(tcp, 10)[:2] == b'\x05\x00'
            tcp.sendall(b'PING')
            assert receive(tcp, 4) == b'PONG'
        assert real_queries, 'internal real DNS fallback was not exercised'
        print(json.dumps({'fake_ip': fake_ip, 'tcp_payload_roundtrip': True, 'internal_real_dns_fallback': True}))
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

