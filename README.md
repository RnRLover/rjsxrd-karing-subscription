# rjsxrd: INCY Russia

One full Xray profile, Основной, in both subscriptions. Резерв removed.

- INCY: https://raw.githubusercontent.com/RnRLover/rjsxrd-karing-subscription/refs/heads/main/ru-karing-incy.txt
- Happ (server and routing profile in one subscription): https://rjsxrd-happ-routing.freedomfightertruthfinder.workers.dev/happ
- Happ pure JSON fallback (server and embedded Xray rules, without a separate UI routing profile): https://raw.githubusercontent.com/RnRLover/rjsxrd-karing-subscription/refs/heads/main/ru-karing-happ.txt
- The experimental `ru-karing-happ-routing-test.txt` is broken in Happ: it imports the routing profile but no server. Do not use it for a connection.

Happ's full-Xray JSON subscription must stay a pure JSON array for its server to appear. Its separate routing profile is delivered in the HTTP `routing` response header by `happ-worker.js`. The Worker reads the existing public GitHub files on each request and does not select or test servers. The endpoint was deployed and its response checked in Cloudflare's HTTP tool: HTTP 200, one `Основной` JSON config with 28 outbounds, and a `routing` header. Import in Happ and actual device connection still require a device check. GitHub RAW cannot set this header.

Routing is generated from `russia-routing.json`, adapted from the user-exported built-in INCY China profile:

- Policy priority: block -> direct -> proxy, driven by RouteOrder in both the client profile and embedded Xray rules. Internal DNS/loopback rules stay ahead of policy rules.
- category-ads-all -> block.
- category-ru, geoip:ru, private/LAN -> direct.
- Everything else -> automatic proxy via default loopback outbound.
- IPIfNonMatch; no final catch-all rule, so GeoIP resolution can run.
- FakeDNS enabled (198.18.0.0/15, 4096 mappings); fake-IP destinations are restored to domains with sniffing routeOnly=false. Direct connections resolve real addresses through profile DNS.
- Direct DNS: Yandex UDP 77.88.8.8.
- Proxy DNS: Cloudflare DoH https://cloudflare-dns.com/dns-query through balancer.
- Entry names and Observatory startup DNS use Yandex UDP 77.88.8.8 directly to avoid a dependency cycle.

Both GeoSite/GeoIP files are downloaded from the exact Loyalsoldier URLs in the profile on each build. Required categories are validated before publication. The raw category `ru` does not exist in GeoSite; `category-ru` is used. No OpenCCK or Karing rule lists are downloaded by the active builder.

GitHub Actions runs every 15 minutes at minutes 7,22,37,52. Up to 24 configurations from rjsxrd; foreign exit checks remain mandatory. Exit-IP reputation is the first selection priority, followed by exit/network/host/transport diversity. Latency/failover run in the client via burstObservatory and leastPing. A failed build preserves the published subscription. Routing/DNS/profile/geodata changes trigger a commit even if the server pool is unchanged.

Reputation uses the public [IPsum feed](https://github.com/stamparm/ipsum), which aggregates blacklist occurrences from 30+ sources. The score is `max(0, 100 - 20 * occurrence_count)` for the actual HTTPS exit IP, not the entry address or country label. Unlisted IPv4 exits (100) are preferred before unknown coverage, then listed exits with the fewest occurrences. Lower-ranked exits fill remaining places only if there are not enough unlisted candidates. Hosting/VPN status alone is not penalized. No listing means no known match in this feed, not a positive whitelist, safety guarantee, or proof of Gemini availability. IPv6 absence is unknown, not clean.

The feed is refreshed daily and stored in the existing private Actions exit-evidence cache, outside subscription files. Its own publication timestamp must be at most 72 hours old. On refresh failure, usable cached evidence can be used within that limit and is labelled in the report; without usable evidence the build fails and keeps the published subscription. `report.json` (a snapshot from the latest publication) and the selection-step log include source publication/fetch timestamps and hash, candidate/selected counts, and each selected tag's exit IP, score, status, and occurrence count. A reputation-score/status change for a selected exit also publishes the updated report, even when the pool itself is unchanged. The score is a pool admission preference; burstObservatory still chooses latency/failover in the client.

INCY gets full JSON plus the existing autorouting URL; Happ gets self-contained domain/IP rules with no geofile dependencies. INCY's URL is unchanged; use the new Worker URL for Happ to receive both the server and the visible routing profile. Update subscription and reconnect. Client import and device traffic still require a real device check.

Verification: Python unit tests; Xray -test for full config and both client formats; local SOCKS UDP FakeDNS and TCP payload test through restored domains. The local test replaces upstream resolvers with local DNS stubs, and does not prove public VPN availability.

Builder: `python karing.py --xray .runtime/xray` (compatibility entry point for russia_config.py).

Transport authentication is an admission gate independent of reputation. TLS nodes must pass a direct TLS handshake with Python system CAs, chain/name/time validation using the configured serverName/SNI, and a real HTTPS request through Xray. The report records server name, leaf SHA-256, expiry, TLS version, and a warning when expiry is within 7 days. The additional Python probe uses a different TLS stack/trust store than Xray and can conservatively reject nodes that work in a client. REALITY passes only after real HTTPS traffic through its configured Xray outbound; an ordinary TLS probe is not used for REALITY. Shadowsocks without TLS records not_applicable and still needs successful HTTPS egress. Failed transport/authentication probes are excluded with failure categories in the build log and report.

Successful transport evidence is cached for at most one hour and never past certificate expiry; older foreign-exit evidence alone cannot admit a node. The existing 24-hour country cache only avoids repeated checks of known RU exits. Renewed certificates and warning/status changes publish selected-node evidence without timestamp-only commits. Without enough verified nodes, a failed build preserves the prior published subscription. No provider subscription update interval is added; INCY client scheduling remains user-controlled.
