"""Embed maintained GeoSite/GeoIP JSON exports as portable Xray rules."""
import ipaddress

LOCAL_IPS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10"]

def domains(raw):
    if raw.get("version") not in (1, 2, 3):
        raise ValueError("unsupported GeoSite JSON version")
    result = []
    prefixes = {"domain": "full:", "domain_suffix": "domain:", "domain_regex": "regexp:", "domain_keyword": "keyword:"}
    for rule in raw["rules"]:
        for key, values in rule.items():
            if key not in prefixes:
                raise ValueError("unhandled GeoSite matcher: " + key)
            if isinstance(values, str): values = [values]
            if not isinstance(values, list) or any(not isinstance(v, str) or not v for v in values):
                raise ValueError("invalid GeoSite domains")
            result.extend(prefixes[key] + (v.lstrip(".") if key == "domain_suffix" else v) for v in values)
    result = list(dict.fromkeys(result))
    if not result: raise ValueError("empty GeoSite category")
    return result

def policy(russian_sites, advertisements, russian_ips):
    if not russian_sites or not advertisements or not russian_ips:
        raise ValueError("complete GeoSite/GeoIP policy required")
    # IPOnDemand is necessary: an unconditional final rule would otherwise
    # prevent IPIfNonMatch from resolving domains to check Russian IPs.
    ips = list(dict.fromkeys(str(ipaddress.ip_network(c, strict=False)) for c in russian_ips))
    return {
        "domainStrategy": "IPOnDemand",
        "balancers": [{"tag": "auto", "selector": ["pool-"], "fallbackTag": "block", "strategy": {"type": "leastPing"}}],
        "rules": [
            {"type": "field", "domain": advertisements, "outboundTag": "block"},
            {"type": "field", "ip": LOCAL_IPS, "outboundTag": "direct"},
            {"type": "field", "domain": russian_sites, "outboundTag": "direct"},
            {"type": "field", "ip": ips, "outboundTag": "direct"},
            {"type": "field", "network": "tcp,udp", "balancerTag": "auto"},
        ],
    }
