"""Current-run HTTPS and HTTP/3 admission checks through real Xray outbounds.

HTTP/3 uses SOCKS5 UDP ASSOCIATE. There is no TCP fallback in the QUIC probe,
no test-file download, and no persisted latency history or quality ranking.
"""
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import dataclass
import copy
import ipaddress
import json
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import tempfile
import time
from urllib.parse import urlsplit

from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import ConnectionTerminated, HandshakeCompleted

from incy import PROXY_PROTOCOLS, build, vision_blocks_quic, xray_validate


class ProbeError(ValueError):
    pass


class ProbeUnavailable(RuntimeError):
    """The checking site or the whole candidate pool cannot be verified."""


@dataclass(frozen=True)
class Endpoint:
    url: str
    host: str
    path: str
    ip: str
    port: int = 443


def remaining(deadline):
    value = deadline - time.monotonic()
    if value <= 0:
        raise TimeoutError('probe deadline')
    return value


def receive(conn, count, deadline):
    data = b''
    while len(data) < count:
        conn.settimeout(remaining(deadline))
        part = conn.recv(count - len(data))
        if not part:
            raise ProbeError('unexpected SOCKS EOF')
        data += part
    return data


def address_bytes(host, port):
    ip = ipaddress.ip_address(host)
    return bytes([1 if ip.version == 4 else 4]) + ip.packed + struct.pack('!H', port)


def socks_connection(port, command, host, destination_port, deadline):
    conn = socket.create_connection(('127.0.0.1', port), timeout=remaining(deadline))
    try:
        conn.sendall(b'\x05\x01\x00')
        if receive(conn, 2, deadline) != b'\x05\x00':
            raise ProbeError('SOCKS authentication rejected')
        conn.sendall(bytes([5, command, 0]) + address_bytes(host, destination_port))
        header = receive(conn, 4, deadline)
        if header[:3] != b'\x05\x00\x00':
            raise ProbeError('SOCKS request rejected')
        if header[3] == 1:
            bound = socket.inet_ntop(socket.AF_INET, receive(conn, 4, deadline))
        elif header[3] == 4:
            bound = socket.inet_ntop(socket.AF_INET6, receive(conn, 16, deadline))
        else:
            raise ProbeError('non-IP SOCKS relay')
        bound_port = struct.unpack('!H', receive(conn, 2, deadline))[0]
        return conn, (bound, bound_port)
    except BaseException:
        conn.close()
        raise


def https_head(endpoint, proxy_port=None, timeout=4, cafile=None):
    deadline = time.monotonic() + timeout
    if proxy_port is None:
        conn = socket.create_connection((endpoint.ip, endpoint.port), timeout=remaining(deadline))
    else:
        conn, _ = socks_connection(proxy_port, 1, endpoint.ip, endpoint.port, deadline)
    with closing(conn):
        conn.settimeout(remaining(deadline))
        context = ssl.create_default_context(cafile=cafile)
        with context.wrap_socket(conn, server_hostname=endpoint.host) as secure:
            secure.settimeout(remaining(deadline))
            secure.sendall((f'HEAD {endpoint.path} HTTP/1.1\r\nHost: {endpoint.host}\r\n'
                            'User-Agent: rjsxrd-pool-check/1\r\nConnection: close\r\n\r\n').encode())
            headers = b''
            while b'\r\n\r\n' not in headers:
                secure.settimeout(remaining(deadline))
                part = secure.recv(1024)
                if not part or len(headers) + len(part) > 16_384:
                    raise ProbeError('invalid HTTPS headers')
                headers += part
            fields = headers.split(b'\r\n', 1)[0].split()
            if len(fields) < 2 or fields[0] not in (b'HTTP/1.0', b'HTTP/1.1'):
                raise ProbeError('invalid HTTPS status')
            if not 200 <= int(fields[1]) < 400:
                raise ProbeError('unsuccessful HTTPS status')


def unpack_udp(packet):
    if len(packet) < 4 or packet[:3] != b'\x00\x00\x00':
        raise ProbeError('fragmented or invalid SOCKS datagram')
    size = {1: 4, 4: 16}.get(packet[3])
    if size is None or len(packet) < size + 6:
        raise ProbeError('invalid SOCKS UDP source')
    source = str(ipaddress.ip_address(packet[4:4 + size]))
    port = struct.unpack('!H', packet[4 + size:6 + size])[0]
    return packet[6 + size:], (source, port)


def quic_head(endpoint, proxy_port=None, timeout=4, cafile=None):
    """TLS-verified HTTP/3 HEAD; all QUIC packets use UDP, including via SOCKS."""
    deadline = time.monotonic() + timeout
    configuration = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN,
                                     server_name=endpoint.host, idle_timeout=timeout,
                                     verify_mode=ssl.CERT_REQUIRED)
    if cafile:
        configuration.load_verify_locations(cafile=cafile)
    quic = QuicConnection(configuration=configuration)
    control = None
    family = socket.AF_INET6 if ':' in endpoint.ip else socket.AF_INET
    if proxy_port is not None:
        control, relay = socks_connection(proxy_port, 3, '0.0.0.0', 0, deadline)
        family = socket.AF_INET6 if ':' in relay[0] else socket.AF_INET
    udp = socket.socket(family, socket.SOCK_DGRAM)
    http, request_id, status = None, None, None
    def transmit():
        for data, target in quic.datagrams_to_send(now=time.monotonic()):
            udp.settimeout(remaining(deadline))
            udp.send(b'\x00\x00\x00' + address_bytes(*target) + data
                     if proxy_port is not None else data)

    try:
        udp.connect(relay if proxy_port is not None else (endpoint.ip, endpoint.port))
        quic.connect((endpoint.ip, endpoint.port), now=time.monotonic())
        while True:
            remaining(deadline)
            while (event := quic.next_event()) is not None:
                if isinstance(event, ConnectionTerminated):
                    raise ProbeError('QUIC terminated: ' + str(event.error_code))
                if isinstance(event, HandshakeCompleted):
                    if event.alpn_protocol not in H3_ALPN:
                        raise ProbeError('HTTP/3 was not negotiated')
                    http = H3Connection(quic)
                    request_id = quic.get_next_available_stream_id()
                    http.send_headers(request_id, [(b':method', b'HEAD'), (b':scheme', b'https'),
                                      (b':authority', endpoint.host.encode()),
                                      (b':path', endpoint.path.encode())], end_stream=True)
                if http is not None:
                    for response in http.handle_event(event):
                        if isinstance(response, HeadersReceived) and response.stream_id == request_id:
                            status = int(dict(response.headers).get(b':status', b'0'))
                            if status < 200:
                                continue
                            if status >= 400:
                                raise ProbeError('unsuccessful HTTP/3 status')
                            if response.stream_ended:
                                return
                        elif isinstance(response, DataReceived) and response.stream_id == request_id:
                            if response.data:
                                raise ProbeError('unexpected response body to HTTP/3 HEAD')
                            if response.stream_ended and status is not None and 200 <= status < 400:
                                return
            transmit()
            timer = quic.get_timer()
            now = time.monotonic()
            udp.settimeout(max(.001, min(deadline, timer if timer is not None else deadline) - now))
            try:
                packet = udp.recv(65_535)
                data, source = (unpack_udp(packet) if proxy_port is not None
                                else (packet, (endpoint.ip, endpoint.port)))
                quic.receive_datagram(data, source, now=time.monotonic())
            except socket.timeout:
                pass
            now = time.monotonic()
            timer = quic.get_timer()
            if timer is not None and timer <= now:
                quic.handle_timer(now=now)
    finally:
        # Close without waiting for a remote drain timeout after each short probe.
        try:
            quic.close()
            transmit()
        except (OSError, TimeoutError):
            pass
        udp.close()
        if control is not None:
            control.close()


def attempt(probe, endpoints, proxy_port, timeout, attempts, cafile=None):
    errors, calls, last_error = Counter(), 0, ''
    for _ in range(attempts):
        for endpoint in endpoints:
            calls += 1
            try:
                probe(endpoint, proxy_port=proxy_port, timeout=timeout, cafile=cafile)
                return {'ok': True, 'target': endpoint.url, 'attempts': calls, 'errors': dict(errors)}
            except (OSError, ValueError) as error:
                errors[type(error).__name__] += 1
                last_error = str(error)[:200]
    return {'ok': False, 'attempts': calls, 'errors': dict(errors), 'last_error': last_error}


def baseline(settings):
    timeout, attempts, workers = (settings[k] for k in ('timeout_seconds', 'attempts', 'workers'))
    if (type(attempts) is not int or not 1 <= attempts <= 3 or
            type(workers) is not int or not 1 <= workers <= 64 or not 0 < timeout <= 15):
        raise ValueError('invalid pool quality limits')
    urls = settings['targets']
    if len(urls) < 2 or len({urlsplit(url).hostname for url in urls}) != len(urls):
        raise ValueError('pool quality needs independent HTTPS target hosts')
    endpoints, unresolved = [], []
    for url in urls:
        parsed = urlsplit(url)
        if parsed.scheme != 'https' or not parsed.hostname or parsed.port not in (None, 443):
            raise ValueError('quality target must be HTTPS on port 443')
        try:
            # IPv4 target probes avoid confusing a runner with no IPv6 route
            # with a proxy that cannot relay UDP. Published dual stack stays on.
            ip = socket.getaddrinfo(parsed.hostname, 443, socket.AF_INET, socket.SOCK_DGRAM)[0][4][0]
            path = parsed.path or '/'
            endpoints.append(Endpoint(url, parsed.hostname, path + ('?' + parsed.query if parsed.query else ''), ip))
        except OSError:
            unresolved.append(url)
    tasks = [(kind, probe, endpoint) for kind, probe in [('https', https_head), ('quic', quic_head)]
             for endpoint in endpoints]
    def check(task):
        kind, probe, endpoint = task
        return kind, endpoint, attempt(probe, [endpoint], None, timeout, attempts)
    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(check, tasks))
    usable = {kind: [endpoint for k, endpoint, result in results if k == kind and result['ok']]
              for kind in ('https', 'quic')}
    evidence = {'targets': [{'protocol': kind, 'url': endpoint.url, **result}
                            for kind, endpoint, result in results], 'unresolved': unresolved}
    if not all(usable.values()):
        raise ProbeUnavailable('direct HTTPS/HTTP3 baseline unavailable; preserve published pool')
    return usable, evidence


def probe_nodes(nodes, xray, settings, usable, cafile=None):
    if not nodes:
        raise ProbeUnavailable('no candidates for quality checks; preserve published pool')
    config = build(nodes)
    proxies = [outbound for outbound in config['outbounds'] if outbound['protocol'] in PROXY_PROTOCOLS]
    config.pop('burstObservatory')
    # Admission isolates each outbound from the client routing policy. Its
    # test-only DNS bootstrap must not recurse through a not-yet-running pool.
    config['dns']['tag'] = 'quality-dns'
    config['routing'] = {'rules': [{'type': 'field', 'inboundTag': ['quality-dns'],
                                  'outboundTag': 'direct'}]}
    config['inbounds'], config['log'] = [], {'loglevel': 'none'}
    held, ports = [], []
    try:
        for index, outbound in enumerate(proxies):
            sock = socket.socket()
            sock.bind(('127.0.0.1', 0))
            held.append(sock)
            ports.append(sock.getsockname()[1])
            tag = f'quality-{index}'
            config['inbounds'].append({'tag': tag, 'listen': '127.0.0.1', 'port': ports[-1],
                                       'protocol': 'socks', 'settings': {'udp': True}})
            config['routing']['rules'].append({'type': 'field', 'inboundTag': [tag],
                                                'outboundTag': outbound['tag']})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, 'quality.json')
            path.write_text(json.dumps(config))
            xray_validate(xray, config)
            for sock in held:
                sock.close()
            process = subprocess.Popen([str(Path(xray).resolve()), 'run', '-c', str(path)],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                deadline = time.monotonic() + 5
                while True:
                    try:
                        with socket.create_connection(('127.0.0.1', ports[0]), timeout=.1):
                            break
                    except OSError:
                        if process.poll() is not None or time.monotonic() >= deadline:
                            raise ProbeUnavailable('quality probe core failed to start')
                        time.sleep(.05)
                def check(pair):
                    node, port = pair
                    tcp = attempt(https_head, usable['https'], port, settings['timeout_seconds'], settings['attempts'], cafile)
                    if not tcp['ok']:
                        udp = {'ok': False, 'skipped': 'https_failed'}
                    elif vision_blocks_quic(node):
                        udp = {'ok': False, 'required': False,
                               'skipped': 'ordinary_vision_intentionally_blocks_udp443'}
                    else:
                        udp = attempt(quic_head, usable['quic'], port, settings['timeout_seconds'], settings['attempts'], cafile)
                    return {**copy.deepcopy(node), 'quality': {'https': tcp, 'quic': udp}}
                with ThreadPoolExecutor(max_workers=settings['workers']) as executor:
                    results = list(executor.map(check, zip(nodes, ports)))
                if process.poll() is not None:
                    raise ProbeUnavailable('quality core stopped during checks')
                return results
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
    finally:
        for sock in held:
            sock.close()


def eligible_nodes(nodes):
    def eligible(node):
        quality = node.get('quality', {})
        quic = quality.get('quic', {})
        intentional = (vision_blocks_quic(node) and quic.get('required') is False and
                       quic.get('skipped') == 'ordinary_vision_intentionally_blocks_udp443')
        return quality.get('https', {}).get('ok', False) and (quic.get('ok', False) or intentional)
    return [node for node in nodes if eligible(node)]
