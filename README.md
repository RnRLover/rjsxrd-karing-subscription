# rjsxrd: INCY Russia

One full Xray profile, Основной, in both subscriptions. Резерв removed.

- INCY: https://raw.githubusercontent.com/RnRLover/rjsxrd-karing-subscription/refs/heads/main/ru-karing-incy.txt
- Happ: https://raw.githubusercontent.com/RnRLover/rjsxrd-karing-subscription/refs/heads/main/ru-karing-happ.txt

Routing is generated from `russia-routing.json`, adapted from the user-exported built-in INCY China profile:

- category-ads-all -> block.
- category-ru, geoip:ru, private/LAN -> direct.
- Everything else -> automatic proxy via default loopback outbound.
- IPIfNonMatch; no final catch-all rule, so GeoIP resolution can run.
- FakeDNS disabled; HTTP/TLS/QUIC sniffing enabled, routeOnly.
- Direct DNS: Yandex UDP 77.88.8.8.
- Proxy DNS: Cloudflare DoH https://cloudflare-dns.com/dns-query through balancer.
- Entry names and Observatory startup DNS use Yandex directly to avoid a dependency cycle.

Both GeoSite/GeoIP files are downloaded from the exact Loyalsoldier URLs in the profile on each build. Required categories are validated before publication. The raw category `ru` does not exist in GeoSite; `category-ru` is used. No OpenCCK or Karing rule lists are downloaded by the active builder.

GitHub Actions runs every 15 minutes at minutes 7,22,37,52. Up to 100 diverse configurations from rjsxrd; country checks and selection unchanged. Latency/failover run in the client via burstObservatory and leastPing. A failed build preserves the published subscription. Routing/DNS/profile/geodata changes trigger a commit even if the server pool is unchanged.

INCY gets full JSON plus the existing autorouting URL; Happ gets self-contained domain/IP rules with no geofile dependencies. Subscription URLs are unchanged. Update subscription and reconnect. Client import and device traffic still require a real device check.

Verification: Python unit tests; Xray -test for full config and both client formats; local SOCKS UDP DNS and TCP payload test without FakeDNS. The local test replaces upstream resolvers with local DNS stubs, and does not prove public VPN availability.

Builder: `python karing.py --xray .runtime/xray` (compatibility entry point for russia_config.py).
