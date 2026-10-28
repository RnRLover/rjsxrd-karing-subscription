"""Transport authentication evidence, independent of IP reputation."""
import hashlib
import socket
import ssl
import time

CHECK_TTL = 3600
EXPIRY_WARNING = 7 * 86400


def probe_transport(node, now=None):
    now = int(time.time()) if now is None else now
    ob = node['outbound']
    stream = ob.get('streamSettings', {})
    security = stream.get('security', 'none')
    if security == 'reality':
        return {'kind': 'reality', 'status': 'requires_xray_handshake'}
    if security != 'tls':
        if ob['protocol'] != 'shadowsocks':
            raise ValueError('unsupported unprotected transport')
        return {'kind': 'none', 'status': 'not_applicable'}
    tls = stream.get('tlsSettings', {})
    if tls.get('allowInsecure') or tls.get('disableSystemRoot') or tls.get('pinnedPeerCertSha256'):
        raise ValueError('certificate verification override is not permitted')
    if tls.get('verifyPeerCertByName'):
        raise ValueError('alternate certificate verification name is not supported')
    endpoint = ob['settings'].get('servers', ob['settings'].get('vnext', []))[0]
    name = tls.get('serverName') or endpoint['address']
    context = ssl.create_default_context()
    if tls.get('alpn'):
        context.set_alpn_protocols(tls['alpn'])
    elif stream.get('network') == 'grpc':
        context.set_alpn_protocols(['h2'])
    with socket.create_connection((endpoint['address'], endpoint['port']), timeout=8) as sock:
        with context.wrap_socket(sock, server_hostname=name) as secure:
            cert = secure.getpeercert()
            expiry = int(ssl.cert_time_to_seconds(cert['notAfter']))
            if expiry <= now:
                raise ssl.SSLCertVerificationError('certificate expired')
            return {'kind': 'tls', 'status': 'passed', 'server_name': name,
                    'not_after': expiry, 'expires_soon': expiry - now <= EXPIRY_WARNING,
                    'sha256': hashlib.sha256(secure.getpeercert(binary_form=True)).hexdigest(),
                    'tls_version': secure.version(), 'trust_store': 'Python system CA'}


def complete_transport(evidence, now=None):
    """Call only after real HTTPS traffic succeeds through this Xray outbound."""
    now = int(time.time()) if now is None else now
    result = dict(evidence)
    if result['status'] == 'requires_xray_handshake':
        result['status'] = 'passed'
    result['checked_at'] = now
    result['next_check_at'] = min(now + CHECK_TTL, result.get('not_after', now + CHECK_TTL))
    return result


def reusable_transport(evidence, now):
    try:
        return (evidence['status'] in ('passed', 'not_applicable') and
                0 <= now - evidence['checked_at'] < CHECK_TTL and
                now < evidence['next_check_at'] and now < evidence.get('not_after', now + 1))
    except (KeyError, TypeError):
        return False


def transport_report(selected, failures):
    return {'policy': 'TLS chain/name/expiry via system CA plus Xray HTTPS; REALITY via Xray; SS without TLS not applicable',
            'cache_seconds': CHECK_TTL, 'expiry_warning_days': 7,
            'failure_counts': dict(failures),
            'servers': [{'tag': f'pool-{i:02d}', **n['transport_check']} for i, n in enumerate(selected, 1)]}


def transport_signature(data):
    import json
    return [{k: v for k, v in record.items() if k not in ('checked_at', 'next_check_at')}
            for record in json.loads(data).get('transport_checks', {}).get('servers', [])]
