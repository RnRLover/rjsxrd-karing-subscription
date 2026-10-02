"""Minimal encoder of the documented Xray router GeoIP/GeoSite protobuf.

Schema: XTLS/Xray-core v26.3.27 app/router/config.proto, messages Domain,
CIDR, GeoIP/List and GeoSite/List. Only unfiltered matchers are generated.
Actual files must pass Xray validation before publication.
"""
import ipaddress


def varint(value):
    result = bytearray()
    while value > 127:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def field(number, value):
    if isinstance(value, int):
        return varint(number << 3) + varint(value)
    if isinstance(value, str):
        value = value.encode('utf-8')
    return varint((number << 3) | 2) + varint(len(value)) + value


def geosite(categories):
    types = {'keyword': 0, 'regexp': 1, 'domain': 2, 'full': 3}
    entries = []
    for tag, values in categories.items():
        parts = [field(1, tag.upper())]
        for value in dict.fromkeys(values):
            kind, text = value.split(':', 1)
            parts.append(field(2, field(1, types[kind]) + field(2, text)))
        entries.append(field(1, b''.join(parts)))
    return b''.join(entries)


def geoip(categories):
    entries = []
    for tag, values in categories.items():
        parts = [field(1, tag.upper())]
        for value in dict.fromkeys(values):
            net = ipaddress.ip_network(value, strict=False)
            parts.append(field(2, field(1, net.network_address.packed) + field(2, net.prefixlen)))
        entries.append(field(1, b''.join(parts)))
    return b''.join(entries)
