"""Check the exact reference DNS, production routes and Cloudflare failover.
Only transport destinations are redirected. Upstream DoH URLs and tags stay intact.
The temporary certificate is trusted only by the test process, never by clients.
"""
import argparse
import copy
from socketserver import BaseRequestHandler, ThreadingTCPServer
import json
import ipaddress
import os
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time
from check_subscription import receive
from incy import CLOUDFLARE_DOH, CLOUDFLARE_UDP, YANDEX_DOH, load_configs

ROOT = Path(__file__).resolve().parent


def question(data):
    pos, parts = 12, []
    while data[pos]:
        size = data[pos]
        parts.append(data[pos + 1:pos + 1 + size].decode())
        pos += size + 1
    return '.'.join(parts), pos + 5


def answer(data, ip):
    _, end = question(data)
    qtype = struct.unpack('!H', data[end-4:end-2])[0]
    if qtype == 28:
        ip = '::' if ip == '0.0.0.0' else '2001:4860:4860::8888'
    packed = ipaddress.ip_address(ip).packed
    return (data[:2] + b'\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00'
            + data[12:end] + b'\xc0\x0c' + struct.pack('!HHIH', qtype, 1, 60, len(packed))
            + packed)


def main(xray):
    config = copy.deepcopy(load_configs(ROOT / 'subscription.json')[0])
    # Keep this fixture independent of whether the upstream happens to publish
    # any hostname endpoints in this particular run.
    bootstrap = 'bootstrap.fixture-domain.com'
    assert [server['address'] for server in config['dns']['servers']] == [YANDEX_DOH, CLOUDFLARE_DOH, CLOUDFLARE_UDP]
    assert 'hosts' not in config['dns'] and 'tag' not in config['dns']
    # The reference leaves VPN DNS interception to INCY. Add a test-only DNS
    # gateway to exercise the exact production built-in DNS and service route.
    config['outbounds'].append({'tag': 'fixture-dns-out', 'protocol': 'dns'})
    config['routing']['rules'].insert(0, {'type': 'field', 'inboundTag': ['socks', 'http'],
        'port': '53', 'network': 'tcp,udp', 'outboundTag': 'fixture-dns-out'})
    state = {'doh': [], 'plain': [], 'healthy': True, 'yandex_healthy': True}
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    def udp_worker():
        while True:
            try:
                data, addr = udp.recvfrom(4096)
                state['plain'].append(question(data)[0])
                udp.sendto(answer(data, '7.7.7.7'), addr)
            except OSError:
                return
    with tempfile.TemporaryDirectory() as directory:
        directory = Path(directory)
        cert, key = directory / 'cert.pem', directory / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(key), '-out', str(cert), '-days', '1',
                        '-subj', '/CN=DNS transport fixture',
                        '-addext', 'subjectAltName=IP:1.1.1.1,IP:77.88.8.8',
                        '-addext', 'basicConstraints=critical,CA:TRUE'],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        class Handler(BaseRequestHandler):
            def handle(self):
                conn = self.request
                conn.settimeout(5)
                # Minimal HTTP/2 peer for Xray's DoH transport. The fixture
                # needs no HPACK decoder: it only consumes POST DATA frames.
                def frame(kind, flags, stream, payload=b''):
                    conn.sendall(len(payload).to_bytes(3, 'big') + bytes([kind, flags])
                                 + stream.to_bytes(4, 'big') + payload)
                try:
                    assert receive(conn, 24) == b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
                    frame(4, 0, 0)
                    bodies = {}
                    while True:
                        header = receive(conn, 9)
                        length = int.from_bytes(header[:3], 'big')
                        kind, flags = header[3:5]
                        stream = int.from_bytes(header[5:], 'big') & 0x7fffffff
                        data = receive(conn, length)
                        if kind == 4 and not flags & 1:
                            frame(4, 1, 0)
                        elif kind == 6 and not flags & 1:
                            frame(6, 1, 0, data)
                        elif kind == 0:
                            bodies[stream] = bodies.get(stream, b'') + data
                            if not flags & 1:
                                continue
                            request = bodies.pop(stream)
                            provider = self.server.provider
                            name = question(request)[0]
                            state['doh'].append([provider, name])
                            ip = '77.88.8.8' if provider == 'yandex' else '9.9.9.9'
                            healthy = state['yandex_healthy'] if provider == 'yandex' else state['healthy']
                            payload = answer(request, ip) if healthy else b''
                            # HPACK static :status 200; literal :status 503.
                            frame(1, 4, stream, b'\x88' if payload else b'\x08\x03503')
                            frame(0, 1, stream, payload)
                except (OSError, RuntimeError):
                    return
        https = ThreadingTCPServer(('127.0.0.1', 0), Handler)
        proxy_https = ThreadingTCPServer(('127.0.0.1', 0), Handler)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert, key)
        tls.set_alpn_protocols(['h2'])
        for server, provider in ((https, 'yandex'), (proxy_https, 'cloudflare')):
            server.daemon_threads = True
            server.provider = provider
            server.socket = tls.wrap_socket(server.socket, server_side=True)
            threading.Thread(target=server.serve_forever, daemon=True).start()
        # Cloudflare's unencrypted fallback follows the same production proxy
        # path as Cloudflare DoH. Both protocols use the proxy stand-in port.
        udp.bind(('127.0.0.1', proxy_https.server_address[1]))
        threading.Thread(target=udp_worker, daemon=True).start()
        for outbound in config['outbounds']:
            if outbound['protocol'] in ('loopback', 'blackhole', 'dns'):
                continue
            tag = outbound['tag']
            dest_port = https.server_address[1] if tag == 'direct' else proxy_https.server_address[1]
            outbound.clear()
            outbound.update(tag=tag, protocol='freedom',
                            settings={'redirect': f'127.0.0.1:{dest_port}'})
        # Keep production DNS URLs and routing: Yandex reaches the direct TLS
        # stand-in, Cloudflare reaches the proxy TLS/UDP stand-ins.
        config['burstObservatory']['subjectSelector'] = ['unused-test-subject']
        config.pop('geodata', None)
        for inbound in config['inbounds']:
            inbound['listen'] = '127.0.0.1'
            with socket.socket() as held:
                held.bind(('127.0.0.1', 0))
                inbound['port'] = held.getsockname()[1]
        port = next(i['port'] for i in config['inbounds'] if i['protocol'] == 'socks')
        config['log'] = {'loglevel': 'debug'}
        env = {**os.environ, 'SSL_CERT_FILE': str(cert), 'XRAY_LOCATION_ASSET': str(ROOT / '.runtime')}
        path = directory / 'config.json'
        path.write_text(json.dumps(config))
        process = None
        log_path = directory / 'core.log'
        with log_path.open('w') as log:
            try:
                process = subprocess.Popen([str(Path(xray).resolve()), 'run', '-c', str(path)],
                                           env=env, stdout=log, stderr=log)
                for _ in range(100):
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=.2):
                            break
                    except OSError:
                        if process.poll() is not None:
                            raise RuntimeError('Xray failed to start')
                        time.sleep(.05)
                with socket.create_connection(('127.0.0.1', port), timeout=3) as conn:
                    conn.sendall(b'\x05\x01\x00')
                    assert receive(conn, 2) == b'\x05\x00'
                    conn.sendall(b'\x05\x03\x00\x01' + b'\x00' * 6)
                    reply = receive(conn, 10)
                    relay = (socket.inet_ntoa(reply[4:8]), struct.unpack('!H', reply[8:])[0])
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                        client.settimeout(12)
                        def query(host, qtype=1):
                            encoded = b''.join(bytes([len(p)]) + p.encode() for p in host.split('.'))
                            data = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' + encoded + b'\x00' + struct.pack('!HH', qtype, 1)
                            client.sendto(b'\x00\x00\x00\x01' + socket.inet_aton('9.9.9.9') + struct.pack('!H', 53) + data, relay)
                            return client.recv(4096)[10:]
                        assert socket.inet_ntoa(query('yandex-first.fixture-domain.com')[-4:]) == '77.88.8.8'
                        assert state['doh'] == [['yandex', 'yandex-first.fixture-domain.com']], state
                        state['yandex_healthy'] = False
                        assert socket.inet_ntoa(query(bootstrap)[-4:]) == '9.9.9.9'
                        assert socket.inet_ntoa(query('vk.com')[-4:]) == '9.9.9.9'
                        for host in ('doubleclick.net', 'ads.adfox.ru'):
                            assert socket.inet_ntoa(query(host)[-4:]) == '9.9.9.9'
                            assert ['cloudflare', host] in state['doh'], state
                        ipv6 = query('ipv6.fixture-domain.com', 28)
                        assert ipv6[6:8] == b'\x00\x00', 'IPv4 DNS policy must not return AAAA records'
                        assert state['plain'] == [], state
                        state['healthy'] = False
                        assert socket.inet_ntoa(query('udp-fallback.fixture-domain.com')[-4:]) == '7.7.7.7'
                        assert state['plain'] == ['udp-fallback.fixture-domain.com'], state
                        state['healthy'] = True
                        assert socket.inet_ntoa(query('recovery.fixture-domain.com')[-4:]) == '9.9.9.9'
                print(json.dumps({'Yandex_remains_first_including_non_RU_names': True,
                                  'Cloudflare_DoH_used_after_Yandex_failure': True,
                                  'Cloudflare_DNS_does_not_filter_ads': True, 'TLS_verified': True,
                                  'IPv4_DNS_policy_checked': True,
                                  'Cloudflare_plain_UDP_fallback_checked': True,
                                  'Yandex_direct_Cloudflare_via_pool': True,
                                  'fixture_only_DNS_gateway_not_published': True}))
            except Exception:
                log.flush()
                print(log_path.read_text()[-14000:])
                raise
            finally:
                if process is not None:
                    process.terminate()
                    process.wait(timeout=5)
                https.shutdown()
                https.server_close()
                proxy_https.shutdown()
                proxy_https.server_close()
                udp.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--xray', required=True)
    main(parser.parse_args().xray)
