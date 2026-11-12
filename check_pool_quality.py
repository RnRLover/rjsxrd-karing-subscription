"""Prove admission uses real HTTP/3, rejects TCP-only relays and checks TLS.

All services and VLESS peers are local. The private test CA is trusted only by
probe calls in this process; it never appears in subscription output.
"""
import argparse
import asyncio
from dataclasses import replace
import json
from pathlib import Path
import socket
from socketserver import BaseRequestHandler, ThreadingTCPServer
import ssl
import subprocess
import tempfile
import threading
import time

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ProtocolNegotiated

from incy import xray_validate
from pool_quality import Endpoint, ProbeError, eligible_nodes, https_head, probe_nodes, quic_head


def free_port(kind=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, kind) as held:
        held.bind(('127.0.0.1', 0))
        return held.getsockname()[1]


def main(xray):
    state = {'https_heads': 0, 'http3_heads': 0}
    class HTTPS(BaseRequestHandler):
        def handle(self):
            self.request.settimeout(3)
            data = b''
            while b'\r\n\r\n' not in data:
                part = self.request.recv(1024)
                if not part or len(data) > 16_384:
                    return
                data += part
            if data.startswith(b'HEAD '):
                state['https_heads'] += 1
                self.request.sendall(b'HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')

    class HTTP3(QuicConnectionProtocol):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.http = None
        def quic_event_received(self, event):
            if isinstance(event, ProtocolNegotiated):
                self.http = H3Connection(self._quic)
            if self.http is not None:
                for request in self.http.handle_event(event):
                    if isinstance(request, HeadersReceived):
                        assert dict(request.headers)[b':method'] == b'HEAD'
                        state['http3_heads'] += 1
                        self.http.send_headers(request.stream_id, [(b':status', b'204')], end_stream=True)
                        self.transmit()

    with tempfile.TemporaryDirectory() as directory:
        directory = Path(directory)
        cert, key = directory / 'cert.pem', directory / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(key), '-out', str(cert), '-days', '1',
                        '-subj', '/CN=quality.fixture.example',
                        '-addext', 'subjectAltName=DNS:quality.fixture.example',
                        '-addext', 'basicConstraints=critical,CA:TRUE'], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        https = ThreadingTCPServer(('127.0.0.1', 0), HTTPS)
        https.daemon_threads = True
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        https.socket = context.wrap_socket(https.socket, server_side=True)
        threading.Thread(target=https.serve_forever, daemon=True).start()
        quic_port = free_port(socket.SOCK_DGRAM)
        server_configuration = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN)
        server_configuration.load_cert_chain(cert, key)
        loop = asyncio.new_event_loop()
        thread = threading.Thread(target=loop.run_forever, daemon=True)
        thread.start()
        async def start_server():
            return await serve('127.0.0.1', quic_port, configuration=server_configuration, create_protocol=HTTP3)
        quic_server = asyncio.run_coroutine_threadsafe(start_server(), loop).result(timeout=5)
        uuid = '123e4567-e89b-12d3-a456-426614174000'
        good, tcp_only = free_port(), free_port()
        config = {'log': {'loglevel': 'none'}, 'inbounds': [
            {'tag': tag, 'listen': '127.0.0.1', 'port': port, 'protocol': 'vless',
             'settings': {'clients': [{'id': uuid, 'flow': 'xtls-rprx-vision'}], 'decryption': 'none'},
             'streamSettings': {'network': 'tcp', 'security': 'tls', 'tlsSettings': {
                 'minVersion': '1.3', 'certificates': [
                     {'certificateFile': str(cert), 'keyFile': str(key)}]}}}
            for tag, port in [('good', good), ('tcp-only', tcp_only)]],
            'outbounds': [{'tag': tag, 'protocol': 'freedom', 'settings': {
                'redirect': f'127.0.0.1:{port}', 'finalRules': [
                    {'action': 'allow', 'network': network, 'ip': ['127.0.0.1/32'], 'port': str(port)}]}}
                for tag, port, network in [('https', https.server_address[1], 'tcp'), ('quic', quic_port, 'udp')]]
                + [{'tag': 'block', 'protocol': 'blackhole'}],
            'routing': {'rules': [{'type': 'field', 'inboundTag': ['tcp-only'],
                                  'network': 'udp', 'outboundTag': 'block'},
                                 {'type': 'field', 'network': 'tcp', 'outboundTag': 'https'},
                                 {'type': 'field', 'network': 'udp', 'outboundTag': 'quic'}]}}
        xray_validate(xray, config)
        path = directory / 'server.json'
        path.write_text(json.dumps(config))
        process = subprocess.Popen([str(Path(xray).resolve()), 'run', '-c', str(path)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 5
            while True:
                try:
                    with socket.create_connection(('127.0.0.1', good), timeout=.1):
                        break
                except OSError:
                    if process.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError('fixture Xray did not start')
                    time.sleep(.05)
            def node(port, label):
                return {'host': '127.0.0.1', 'label': label, 'outbound': {
                    'protocol': 'vless', 'settings': {'vnext': [{'address': '127.0.0.1', 'port': port,
                    'users': [{'id': uuid, 'encryption': 'none', 'flow': 'xtls-rprx-vision'}]}]},
                    'streamSettings': {'network': 'tcp', 'security': 'tls', 'tlsSettings': {
                        'serverName': 'quality.fixture.example', 'minVersion': '1.3',
                        'certificates': [{'certificateFile': str(cert), 'usage': 'verify'}]}}}}
            direct_tcp = Endpoint('https://quality.fixture.example/tcp', 'quality.fixture.example',
                                  '/tcp', '127.0.0.1', https.server_address[1])
            direct_udp = replace(direct_tcp, url='https://quality.fixture.example/quic',
                                 path='/quic', port=quic_port)
            https_head(direct_tcp, cafile=str(cert), timeout=2)
            quic_head(direct_udp, cafile=str(cert), timeout=2)
            try:
                quic_head(replace(direct_udp, host='wrong.fixture.example'), cafile=str(cert), timeout=2)
            except ProbeError:
                pass
            else:
                raise AssertionError('QUIC accepted a certificate for the wrong hostname')
            tcp_endpoint = replace(direct_tcp, ip='203.0.113.1', port=443)
            udp_endpoint = replace(direct_udp, ip='203.0.113.1', port=443)
            checked = probe_nodes([node(tcp_only, 'tcp-only'), node(good, 'good'), node(free_port(), 'dead')],
                                  xray, {'timeout_seconds': 1.5, 'attempts': 2, 'workers': 3},
                                  {'https': [tcp_endpoint], 'quic': [udp_endpoint]}, cafile=str(cert))
            assert checked[0]['quality']['https']['ok'], checked
            assert not checked[0]['quality']['quic']['ok']
            assert checked[0]['quality']['quic']['attempts'] == 2
            assert checked[1]['quality']['https']['ok'] and checked[1]['quality']['quic']['ok']
            assert not checked[2]['quality']['https']['ok']
            assert [node['label'] for node in eligible_nodes(checked)] == ['good']
            print(json.dumps({'real_HTTPS_and_HTTP3_through_Vision': True, 'TCP_only_node_rejected': True,
                              'UDP_destination_443': True,
                              'QUIC_has_no_TCP_fallback': True, 'wrong_certificate_rejected': True,
                              'failed_probes_retried': True, 'HEAD_only_no_test_file': True, **state}))
        finally:
            process.terminate()
            process.wait(timeout=5)
            https.shutdown()
            https.server_close()
            loop.call_soon_threadsafe(quic_server.close)
            loop.call_soon_threadsafe(loop.stop)
            thread.join(timeout=3)
            loop.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--xray', required=True)
    main(parser.parse_args().xray)
