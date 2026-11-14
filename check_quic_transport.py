"""Verify that the published ordinary Vision matches the supplied reference.

Both Xray ends and the TCP/UDP echo targets are local. This checks core relay
behavior, not HTTP/3 handshakes or the live providers' UDP availability.
"""
import argparse
import copy
import json
from pathlib import Path
import socket
from socketserver import BaseRequestHandler, ThreadingTCPServer, ThreadingUDPServer
import struct
import subprocess
import tempfile
import threading
import time

from check_subscription import receive
from incy import build, xray_validate

UUID = '123e4567-e89b-12d3-a456-426614174000'


def free_port():
    with socket.socket() as held:
        held.bind(('127.0.0.1', 0))
        return held.getsockname()[1]


def socks(port, command, destination_port):
    conn = socket.create_connection(('127.0.0.1', port), timeout=2)
    conn.settimeout(2)
    try:
        conn.sendall(b'\x05\x01\x00')
        assert receive(conn, 2) == b'\x05\x00'
        address = '0.0.0.0' if command == 3 else '127.0.0.1'
        conn.sendall(bytes([5, command, 0, 1]) + socket.inet_aton(address)
                     + struct.pack('!H', destination_port))
        reply = receive(conn, 10)
        assert reply[:2] == b'\x05\x00', reply
        return conn, (socket.inet_ntoa(reply[4:8]), struct.unpack('!H', reply[8:])[0])
    except Exception:
        conn.close()
        raise


def exercise(xray, directory, cert, key, tcp_port, udp_port, published):
    server_port, client_port = free_port(), free_port()
    original = {'tag': 'vision', 'protocol': 'vless', 'settings': {'vnext': [{
        'address': '127.0.0.1', 'port': server_port, 'users': [{
            'id': UUID, 'encryption': 'none', 'flow': 'xtls-rprx-vision'}]}]},
        'streamSettings': {'network': 'tcp', 'security': 'tls', 'tlsSettings': {
            'serverName': 'vision.fixture.test', 'minVersion': '1.3',
            'certificates': [{'certificateFile': str(cert), 'usage': 'verify'}]}}}
    before = copy.deepcopy(original)
    outbound = build([original])['outbounds'][0] if published else copy.deepcopy(original)
    assert original == before, 'building must not modify source parameters'
    outbound['tag'] = 'vision'
    config = {'log': {'loglevel': 'info'}, 'inbounds': [
        {'tag': 'client', 'listen': '127.0.0.1', 'port': client_port,
         'protocol': 'socks', 'settings': {'udp': True}},
        {'tag': 'server', 'listen': '127.0.0.1', 'port': server_port, 'protocol': 'vless',
         'settings': {'decryption': 'none', 'clients': [{'id': UUID, 'flow': 'xtls-rprx-vision'}]},
         'streamSettings': {'network': 'tcp', 'security': 'tls', 'tlsSettings': {
             'minVersion': '1.3', 'certificates': [
                 {'certificateFile': str(cert), 'keyFile': str(key)}]}}}],
        'outbounds': [outbound,
            {'tag': 'udp-echo', 'protocol': 'freedom',
             'settings': {'redirect': f'127.0.0.1:{udp_port}', 'finalRules': [
                 {'action': 'allow', 'network': 'udp', 'ip': ['127.0.0.1/32'],
                  'port': str(udp_port)}]}},
            {'tag': 'tcp-echo', 'protocol': 'freedom',
             'settings': {'redirect': f'127.0.0.1:{tcp_port}', 'finalRules': [
                 {'action': 'allow', 'network': 'tcp', 'ip': ['127.0.0.1/32'],
                  'port': str(tcp_port)}]}}],
        'routing': {'rules': [
            {'type': 'field', 'inboundTag': ['server'], 'network': 'udp', 'outboundTag': 'udp-echo'},
            {'type': 'field', 'inboundTag': ['server'], 'network': 'tcp', 'outboundTag': 'tcp-echo'},
            {'type': 'field', 'inboundTag': ['client'], 'outboundTag': 'vision'}]}}
    xray_validate(xray, config)
    name = 'published' if published else 'baseline'
    path, log_path = directory / (name + '.json'), directory / (name + '.log')
    path.write_text(json.dumps(config))
    with log_path.open('w') as log:
        process = subprocess.Popen([str(Path(xray).resolve()), 'run', '-c', str(path)],
                                   stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 5
            while True:
                try:
                    with socket.create_connection(('127.0.0.1', client_port), timeout=.1):
                        break
                except OSError:
                    if process.poll() is not None or time.monotonic() > deadline:
                        raise RuntimeError('local Xray fixture did not start')
                    time.sleep(.05)
            with socks(client_port, 1, 8443)[0] as conn:
                conn.sendall(b'VISION TCP')
                assert receive(conn, 10) == b'VISION TCP'
            for target in [8443, 443]:
                control, relay = socks(client_port, 3, 0)
                with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                    udp.settimeout(1)
                    payload = f'VISION UDP {target}'.encode()
                    udp.sendto(b'\x00\x00\x00\x01' + socket.inet_aton('127.0.0.1')
                               + struct.pack('!H', target) + payload, relay)
                    if target == 443:
                        try:
                            udp.recvfrom(4096)
                        except socket.timeout:
                            pass
                        else:
                            raise AssertionError('plain Vision unexpectedly relayed UDP/443')
                        log.flush()
                        assert 'XTLS rejected UDP/443 traffic' in log_path.read_text()
                    else:
                        reply, _ = udp.recvfrom(4096)
                        assert reply.endswith(payload), reply
        except Exception:
            log.flush()
            print(log_path.read_text()[-6000:])
            raise
        finally:
            process.terminate()
            process.wait(timeout=5)


def main(xray):
    class TCP(BaseRequestHandler):
        def handle(self):
            self.request.settimeout(3)
            data = self.request.recv(4096)
            if data:
                self.request.sendall(data)

    class UDP(BaseRequestHandler):
        def handle(self):
            data, connection = self.request
            connection.sendto(data, self.client_address)

    with ThreadingTCPServer(('127.0.0.1', 0), TCP) as tcp, \
            ThreadingUDPServer(('127.0.0.1', 0), UDP) as udp, \
            tempfile.TemporaryDirectory() as temporary:
        tcp.daemon_threads = udp.daemon_threads = True
        for server in [tcp, udp]:
            threading.Thread(target=server.serve_forever, daemon=True).start()
        directory = Path(temporary)
        cert, key = directory / 'cert.pem', directory / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(key), '-out', str(cert), '-days', '1',
                        '-subj', '/CN=vision.fixture.test',
                        '-addext', 'subjectAltName=DNS:vision.fixture.test',
                        '-addext', 'basicConstraints=critical,CA:TRUE'],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for published in [False, True]:
                exercise(xray, directory, cert, key, tcp.server_address[1],
                         udp.server_address[1], published)
        finally:
            tcp.shutdown()
            udp.shutdown()
    print(json.dumps({'baseline_blocks_udp443': True, 'published_blocks_udp443_as_reference': True,
                      'published_relays_other_udp': True, 'published_relays_tcp': True,
                      'tls_verified': True}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--xray', required=True)
    main(parser.parse_args().xray)
