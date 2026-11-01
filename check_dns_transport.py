"""Run production DNS tags and routing against local UDP and trusted TLS DoH fixtures.
Only proxy/direct transports are redirected. Upstream DoH URLs and tags stay intact.
The temporary certificate is trusted only by the test process, never by clients.
"""
import argparse
import copy
from socketserver import BaseRequestHandler, ThreadingTCPServer
import json
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
    return (data[:2] + b'\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00'
            + data[12:end] + b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'
            + socket.inet_aton(ip))


def main(xray):
    config = copy.deepcopy(json.loads((ROOT / 'subscription.json').read_bytes())[0])
    state = {'external': [], 'direct': [], 'external_healthy': True}
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(('127.0.0.1', 0))
    def udp_worker():
        while True:
            try:
                data, addr = udp.recvfrom(4096)
                state['direct'].append(question(data)[0])
                udp.sendto(answer(data, '77.88.8.8'), addr)
            except OSError:
                return
    threading.Thread(target=udp_worker, daemon=True).start()
    with tempfile.TemporaryDirectory() as directory:
        directory = Path(directory)
        cert, key = directory / 'cert.pem', directory / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(key), '-out', str(cert), '-days', '1',
                        '-subj', '/CN=DNS transport fixture',
                        '-addext', 'subjectAltName=IP:1.1.1.1,IP:8.8.8.8',
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
                            state['external'].append(question(request)[0])
                            payload = answer(request, '9.9.9.9') if state['external_healthy'] else b''
                            # HPACK static :status 200; literal :status 503.
                            frame(1, 4, stream, b'\x88' if payload else b'\x08\x03503')
                            frame(0, 1, stream, payload)
                except (OSError, RuntimeError):
                    return
        https = ThreadingTCPServer(('127.0.0.1', 0), Handler)
        https.daemon_threads = True
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert, key)
        tls.set_alpn_protocols(['h2'])
        https.socket = tls.wrap_socket(https.socket, server_side=True)
        threading.Thread(target=https.serve_forever, daemon=True).start()
        for outbound in config['outbounds']:
            if outbound['protocol'] in ('loopback', 'blackhole', 'dns'):
                continue
            tag = outbound['tag']
            dest_port = udp.getsockname()[1] if tag == 'direct' else https.server_address[1]
            outbound.clear()
            outbound.update(tag=tag, protocol='freedom',
                            settings={'redirect': f'127.0.0.1:{dest_port}'})
        # The production tags and DoH URLs are retained without +local or
        # insecure TLS options. Redirected proxy transport terminates at TLS.
        config['burstObservatory']['subjectSelector'] = ['unused-test-subject']
        config.pop('geodata', None)
        for inbound in config['inbounds']:
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
                        def query(host):
                            encoded = b''.join(bytes([len(p)]) + p.encode() for p in host.split('.'))
                            data = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' + encoded + b'\x00\x00\x01\x00\x01'
                            client.sendto(b'\x00\x00\x00\x01' + socket.inet_aton('9.9.9.9') + struct.pack('!H', 53) + data, relay)
                            return client.recv(4096)[10:]
                        assert socket.inet_ntoa(query('transport-fixture.ru')[-4:]) == '77.88.8.8'
                        bootstrap = next(d[5:] for d in config['dns']['servers'][0]['domains'] if d.startswith('full:'))
                        assert socket.inet_ntoa(query(bootstrap)[-4:]) == '77.88.8.8'
                        assert socket.inet_ntoa(query('external.fixture-domain.com')[-4:]) == '9.9.9.9'
                        assert socket.inet_ntoa(query('doubleclick.net')[-4:]) == '0.0.0.0'
                        assert state['direct'] == ['transport-fixture.ru', bootstrap], state
                        assert state['external'] == ['external.fixture-domain.com'], state
                        state['external_healthy'] = False
                        try:
                            failed = query('failed.fixture-domain.com')
                            assert failed[3] & 15, 'Expected DNS error after DoH failure'
                        except socket.timeout:
                            pass  # dns-out may drop failed queries instead of returning SERVFAIL.
                        assert state['direct'] == ['transport-fixture.ru', bootstrap], 'External DNS leaked to direct resolver'
                        assert 'failed.fixture-domain.com' in state['external']
                print(json.dumps({'ru_dns_direct': True, 'bootstrap_dns_direct': True, 'external_doh_via_proxy': True,
                                  'tls_verified': True, 'ads_no_upstream': True,
                                  'external_failure_no_direct_fallback': True}))
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
                udp.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--xray', required=True)
    main(parser.parse_args().xray)
