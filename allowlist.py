"""Rank public-source allowlist candidates without claiming restricted-network tests."""
import ipaddress
import re

ROOT_URL = 'https://raw.githubusercontent.com/whoahaow/rjsxrd/main/source/config/'
WL_LABEL = re.compile(r'white\s*list|\bwl\b|бел\w*\s+списк|\bбс\b', re.I)


def load_reference(fetch):
    result = {'domains': [], 'networks': [], 'available': False}
    try:
        domains = set()
        for line in fetch(ROOT_URL + 'whitelist-all.txt').decode('utf-8-sig').splitlines():
            name = line.strip().lower().rstrip('.').removeprefix('*.').removesuffix(':443')
            if re.fullmatch(r'(?:[a-z0-9-]+\.)+[a-z0-9-]{2,63}', name):
                domains.add(name)
        networks = []
        for line in fetch(ROOT_URL + 'cidrwhitelist.txt').decode('utf-8-sig').splitlines():
            if line.strip() and not line.lstrip().startswith('#'):
                network = ipaddress.ip_network(line.strip(), strict=False)
                if network.num_addresses <= 65536:
                    networks.append(network)
        if not domains or not networks:
            raise ValueError('empty allowlist reference')
        # Collapse thousands of individual IPs before sharing input with workers.
        collapsed = [str(n) for version in (4, 6) for n in ipaddress.collapse_addresses(
            n for n in networks if n.version == version)]
        result.update(domains=sorted(domains), networks=collapsed, available=True)
    except (OSError, ValueError, UnicodeError):
        pass  # Labels remain usable; absence of reference data is not a bad node.
    return result


def annotate(nodes, reference):
    domains = set(reference.get('domains', []))
    networks = [ipaddress.ip_network(value) for value in reference.get('networks', [])]
    def domain_match(name):
        parts = name.lower().rstrip('.').split('.')
        return any('.'.join(parts[i:]) in domains for i in range(len(parts)))
    for node in nodes:
        stream = node['outbound'].get('streamSettings', {})
        tls = stream.get('realitySettings', stream.get('tlsSettings', {}))
        labels = node.get('labels', [node.get('label', '')])
        explicit = any(WL_LABEL.search(label) for label in labels)
        cidr_label = any('[*CIDR]' in label or '[CIDR]' in label for label in labels)
        ips = [ipaddress.ip_address(item['ip']) for item in node.get('entry_reputation', [])]
        ip_match = any(ip.version == net.version and ip in net for ip in ips for net in networks)
        sni_match = stream.get('security') in ('tls', 'reality') and domain_match(tls.get('serverName', ''))
        score = 5 if ip_match and sni_match else 4 if explicit else 3 if cidr_label else 2 if ip_match else 1 if sni_match else 0
        node['allowlist'] = {'priority': score, 'explicit_label': explicit, 'cidr_label': cidr_label,
                             'entry_ip_match': ip_match, 'sni_match': sni_match,
                             'reference_available': reference.get('available', False),
                             'restricted_network_verified': False}
    return nodes
