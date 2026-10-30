# Common automatic subscription for INCY and Happ

Use the same URL in both clients:

https://raw.githubusercontent.com/RnRLover/rjsxrd-karing-subscription/refs/heads/main/subscription.json

One pure JSON array, one **Основной** configuration. No provider interval, routing import command or separate routing profile is attached. Disable/remove a previously imported Russia profile in the app, or import the common URL as a new subscription.

## Routing

Embedded rules block `geosite:category-ads-all`; route `geosite:category-ru`, `geoip:ru` and private/local networks directly; route other TCP/UDP via the automatic pool. The JSON `geodata` block updates `geoip.dat` and `geosite.dat` from Loyalsoldier's official latest-release HTTPS URLs at 00:17 and 12:17 in the core's local timezone, while Xray is running. Downloads follow the existing routing and a failed reload rolls back the update. This requires a recent core with geodata support and writable, already-present asset files; it is not a first-start bootstrap or an immediate download on connection. Client builds may restrict writes or omit this core feature. CI validates against the same databases in ignored `.runtime/` files. No separate routing profile or custom DNS is imported.

The subscription supplies **no DNS configuration**, no DNS outbound and no FakeDNS. Port 53 traffic keeps its original destination and goes directly. DNS settings belong to the client. `IPIfNonMatch` first matches domains and original destination IPs, then resolves unmatched domains for a second GeoIP pass using the resolver available to Xray. Unmatched traffic enters the automatic pool through the first/default `loopback` outbound and the scoped `default-auto` inbound-tag rule. There is no unconditional proxy catch-all to suppress the second pass. This preserves an original RU destination when a sniffed hostname resolves abroad, and does not supply a resolver address. Sniffing recovers HTTP/TLS/QUIC hostnames for routing without changing the destination.

## Pool and automatic selection

The production pool contains **at most 40 nodes**. Every IPsum-listed exit is excluded; missing feed coverage is still reported as unknown. Existing certificate, authenticated Xray HTTPS egress and foreign public exit requirements remain mandatory.

Each newly tested foreign node must pass verified HTTPS requests to **both** `https://www.gstatic.com/generate_204` and `https://cp.cloudflare.com/generate_204`: two requests per destination, at least three of four successful, at least one on each destination, no redirects, HTTP 204 required, four-second request timeout. It must then receive the complete **256 KiB** response from `https://speed.cloudflare.com/__down?bytes=262144` within 12 seconds. Short, oversized, compressed, HTML or redirected responses fail. The body is discarded. Before testing nodes, the runner checks these destinations directly; a failed control stops publication without recording node failures. No Gemini or Russian-service reachability checks run.

Actual observations are retained in the existing Actions cache: the latest ten checks within seven days, with **at least 90% successful checks** required. A check is one full admission attempt, not an individual HTTP request. A successful cached result is reused for at most 15 minutes and never counted as a new observation. Failed attempts are retried after 15 minutes. Fewer than three observations is **provisional**, not established reliability. New nodes can bootstrap the pool; once ten history-qualified candidates exist, no more than eight provisional nodes enter a publication. Cache loss restarts provisional history; Actions cache is not a permanent reliability database.

Selection prefers established history, then coarse performance bands combining median HTTPS delay, spread, failed individual samples and transfer elapsed time. Within a band it spreads actual exit IPs, entry prefixes, hostnames and protocol/transport/security combinations, retaining previous membership in equal ties. Strict caps: **two nodes per exit IP, four per entry /24 IPv4 or /48 IPv6 prefix, two per hostname**. Prefixes approximate infrastructure diversity, not provider/ASN identity. The caps are never relaxed to fill forty slots. Fewer than two qualifying nodes stops publication and keeps the previous subscription; unchecked nodes are never substituted. The Android size guard remains.

Published order follows quality bands and then the existing exact median HEAD latency. Client **leastPing**, three-minute health checks, routing, DNS, geodata and startup fallback behavior remain unchanged. `report.json.quality_selection` records selected-node observations, history status, thresholds and measurement evidence; `latency_selection` retains the existing HEAD measurements. Observations are committed only as report evidence, never as response bodies or cookies. Tests run from GitHub and do not establish reachability, speed, UDP support or application availability on a user's operator.

## Admission and updates

TLS nodes still require configured SNI/name, chain and expiry verification with system CAs, plus successful HTTPS egress through the exact Xray outbound. REALITY is admitted only after an actual authenticated HTTPS request through Xray. Shadowsocks still needs successful HTTPS egress. Insecure transport flags remain rejected. Actual exits must be public and outside RU; Russian entry addresses and labels are allowed.

IPsum refreshes daily and expires after 72 hours; a usable cache may cover a feed outage. Without usable reputation evidence the build fails rather than assigning clean scores. Certificate evidence expires within one hour or at certificate expiry. Failed checks exclude candidates; failed builds keep the last published subscription. Evidence stays in the Actions cache, while `report.json` describes the selected publication.

Every GitHub Actions run resolves the latest stable official Xray release, downloads assets from that exact version, and verifies the archive's publisher SHA256 before installation. A release lookup, download or validation failure stops publication and keeps the previous subscription. This updates only the CI core, not the apps on devices. The selected version and checksum appear in the job log.

GitHub Actions runs at minutes 7, 22, 37 and 52 each hour. CI checks JSON/Xray validity plus 14 isolated routing cases covering RU domains, GeoIP, LAN, ads, foreign traffic, sniffing, conflicting original-IP/DNS destinations and DNS with the production rule order and balancer tags; it cannot confirm device connectivity on a particular mobile operator.

## Repository files

- `subscription.json`: the only client subscription URL, shared by both applications.
- `generate.py`, `rjsxrd_parser.py`, `pool_selection.py`, `certificate_checks.py`, `ip_reputation.py`, `latency_checks.py`: collect, verify, select and rank servers.
- `karing.py`, `russia_config.py`, `routing.py`, `settings.json`, `russia-routing.json`: common JSON generation and embedded routing policy.
- `ru.json`: last checked base pool, used for stable selection and routing-only rebuilds; `report.json`: selected-node verification and latency evidence.
- `setup_xray.py`, `check_subscription.py`, `publication_changed.py`, active `test_*.py` and `.github/workflows/update.yml`: reproducible validation and scheduled publication.
- `LICENSE.rjsxrd`: upstream parser licence and attribution.

Obsolete normal pools, diagnostic snapshots, separate routing/FakeDNS generators, Happ Worker, sing-box setup, experimental subscriptions and committed validation databases are removed. No history rewriting is required.
