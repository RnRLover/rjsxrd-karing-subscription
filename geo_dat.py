"""Minimal encoder of the documented Xray router GeoIP/GeoSite protobuf.

Schema: XTLS/Xray-core v26.3.27 app/router/config.proto, messages Domain,
CIDR, GeoIP/List and GeoSite/List. Only unfiltered matchers are generated.
Actual files must pass Xray validation before publication.
"""
import ipaddress


def protobuf_fields(data):
    """Read wire fields without interpreting or modifying the upstream file."""
    offset = 0
    def read_varint():
        nonlocal offset
        value = shift = 0
        while offset < len(data) and shift < 70:
            byte = data[offset]
            offset += 1
            value |= (byte & 127) << shift
            if byte < 128:
                return value
            shift += 7
        raise ValueError('invalid protobuf varint')
    while offset < len(data):
        key = read_varint()
        number, wire = key >> 3, key & 7
        if wire == 0:
            value = read_varint()
        elif wire == 2:
            size = read_varint()
            if offset + size > len(data):
                raise ValueError('truncated protobuf field')
            value = data[offset:offset + size]
            offset += size
        elif wire in (1, 5):
            size = 8 if wire == 1 else 4
            if offset + size > len(data):
                raise ValueError('truncated protobuf field')
            value = data[offset:offset + size]
            offset += size
        else:
            raise ValueError('unsupported protobuf wire type')
        yield number, wire, value


def geoip_cidrs(data, country):
    """Export one exact GeoIP category from the Xray asset used by INCY."""
    for number, wire, value in protobuf_fields(data):
        if number != 1 or wire != 2:
            continue
        fields = list(protobuf_fields(value))
        code = next((v.decode('utf-8') for n, w, v in fields if n == 1 and w == 2), '')
        if code.lower() != country.lower():
            continue
        if any(n == 3 and w == 0 and v for n, w, v in fields):
            raise ValueError('inverse GeoIP category cannot be inlined')
        cidrs = []
        for n, w, cidr in fields:
            if n != 2 or w != 2:
                continue
            parts = dict((n, v) for n, w, v in protobuf_fields(cidr))
            address = ipaddress.ip_address(parts[1])
            prefix = parts.get(2, 0)
            cidrs.append(str(ipaddress.ip_network((address, prefix), strict=False)))
        if not cidrs:
            raise ValueError('empty GeoIP category')
        return list(dict.fromkeys(cidrs))
    raise ValueError('GeoIP category not found: ' + country)


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
