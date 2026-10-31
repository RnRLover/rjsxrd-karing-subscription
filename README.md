# Common automatic subscription for INCY and Happ

INCY: a dedicated automatic-install candidate is published at:

https://raw.githubusercontent.com/RnRLover/rjsxrd-karing-subscription/refs/heads/main/incy.txt

It contains the unchanged single full Xray JSON followed by INCY's native autorouting command and `routing-geo-update-interval: 24`. The command installs the routing/geodata profile from `russia-routing.json` automatically and enables profile refresh. The geodata interval is separate from the subscription interval. No manual second import or Cloudflare endpoint is involved. INCY documents full JSON and body metadata, but their combination must still be confirmed in the installed client version: verify that both the one **Основной** server and the native profile appear, and that both geofiles finish downloading. Do not interpret core validation as successful client import.

The existing `subscription.json` stays a pure-JSON fallback. Its contents, routing, DNS policy and automatic server pool are unchanged. Cloudflare deployment changes are paused until the actual deployed Worker code and version history can be inspected; the repository's `happ-worker.js` is a historical copy, not a verified export of the deployed code.

Happ: a separate automatic-install candidate is published at:

https://raw.githubusercontent.com/RnRLover/rjsxrd-karing-subscription/refs/heads/main/happ.txt

It contains the unchanged full Xray JSON on the first line and `happ://routing/onadd/<base64 JSON>` on the second. The native profile carries Loyalsoldier download URLs, matching routing categories, `LastUpdated`, and `UseChunkFiles: "false"`; the databases themselves are not embedded. Both parts are regenerated together on successful builds. This file needs no custom HTTP headers or Worker.

**Observed client results:** the user tested `happ.txt` in Happ: the subscription appeared without servers, while the geofiles downloaded. This mixed-body transport therefore failed to import the full config in that tested build. Do not use it as the recommended Happ delivery URL. The same file imported successfully in INCY. After switching to the old full-JSON subscription, the routing toggle stayed enabled; no actual cross-subscription rule application has been demonstrated. The dedicated `incy.txt` autorouting variant is a different transport and has not yet been separately confirmed by that test. For Happ, the next delivery approach is a pure-JSON body plus the native `routing` HTTP header. The deployed Cloudflare Worker source still needs inspection before any deployment change.

References: [Happ routing](https://www.happ.su/main/ru/dev-docs/routing), [Happ full JSON handling](https://www.happ.su/main/ru/dev-docs/examples-of-links-and-parameters).

`LastUpdated` advances when the downloaded database hashes or routing policy change, not when servers rotate. The existing core geodata schedule remains as an additional update mechanism while running. The native metadata profile includes the same domain/IP categories as the full JSON and disables geofile trimming. No forced subscription-refresh interval or custom DNS resolver is added.

## Disposable INCY isolation check

These two files are manual test snapshots, outside the production generator and scheduled publication:

- [Isolation B — no native profile](https://raw.githubusercontent.com/RnRLover/rjsxrd-karing-subscription/refs/heads/main/isolation-b.txt)
- [Isolation A — block example.org](https://raw.githubusercontent.com/RnRLover/rjsxrd-karing-subscription/refs/heads/main/isolation-a.txt)

Both contain exactly the same single TLS/TCP Trojan node taken from the current published pool. They use ordinary share links, so a full JSON cannot hide whether native routing applies. A supplies a dedicated native profile that blocks only `example.org` (including its subdomains); B supplies no profile or routing-off command. These are diagnostic subscriptions, not replacements for the automatic pool. The shared node may later stop working. Rebuild both together with `python routing_isolation.py` when needed; this never changes production files.

1. Import **B first**, connect, and check that both `https://example.org/?isolation=B1` and `https://example.com/?isolation=B1` open. If they do not, the test is inconclusive: check connectivity or the existing active profile before continuing.
2. Import A, select its server, reconnect, and open fresh private browser tabs: `https://example.org/?isolation=A1` must fail while `https://example.com/?isolation=A1` must open. Otherwise, A was not applied and isolation cannot yet be assessed.
3. Select B again, reconnect, and open `https://example.org/?isolation=B2` in a fresh private tab. It must open. If only example.org is still blocked while example.com opens, the result is evidence that A's rules continue to affect a subscription without its own profile.
4. Return to A, reconnect, and repeat with a new query value: example.org must be blocked again. A selected profile remaining visible in settings is not itself a failed result.

Record the INCY version/platform and results. This test checks native-profile activation for ordinary subscriptions; it does not by itself prove geofile-path isolation for full JSON. After testing, remove the two diagnostic subscriptions and their diagnostic profile, then reconnect using the production subscription.

## Routing

Embedded rules block `geosite:category-ads-all`; route `geosite:category-ru`, `geoip:ru` and private/local networks directly; route other TCP/UDP via the automatic pool. The JSON `geodata` block updates `geoip.dat` and `geosite.dat` from Loyalsoldier's official latest-release HTTPS URLs at 00:17 and 12:17 in the core's local timezone, while Xray is running. Downloads follow the existing routing and a failed reload rolls back the update. This requires a recent core with geodata support and writable, already-present asset files; it is not a first-start bootstrap or an immediate download on connection. Client builds may restrict writes or omit this core feature. CI validates against the same databases in ignored `.runtime/` files. No custom DNS resolver is supplied; the automatically bundled native profile manages initial geofile installation.

The subscription supplies **no DNS configuration**, no DNS outbound and no FakeDNS. Port 53 traffic keeps its original destination and goes directly. DNS settings belong to the client. `IPIfNonMatch` first matches domains and original destination IPs, then resolves unmatched domains for a second GeoIP pass using the resolver available to Xray. Unmatched traffic enters the automatic pool through the first/default `loopback` outbound and the scoped `default-auto` inbound-tag rule. There is no unconditional proxy catch-all to suppress the second pass. This preserves an original RU destination when a sniffed hostname resolves abroad, and does not supply a resolver address. Sniffing recovers HTTP/TLS/QUIC hostnames for routing without changing the destination.

## Pool and automatic selection

The production pool contains **at most 40 nodes**. Every IPsum-listed exit is excluded; missing feed coverage is still reported as unknown. Existing certificate, authenticated Xray HTTPS egress and foreign public exit requirements remain mandatory.

Each newly tested foreign node must pass verified HTTPS requests to **both** `https://www.gstatic.com/generate_204` and `https://cp.cloudflare.com/generate_204`: two requests per destination, at least three of four successful, at least one on each destination, no redirects, HTTP 204 required, four-second request timeout. It must then receive the complete **256 KiB** response from `quality-probe.bin` served over HTTPS by this repository's raw GitHub URL, with a fixed SHA256 digest within 12 seconds. Short, oversized, compressed, HTML or redirected responses fail. The response digest must match the expected test block; the body is discarded. The deterministic test block contains no user data. Before testing nodes, the runner checks these destinations directly; a failed control stops publication without recording node failures. No Gemini or Russian-service reachability checks run.

Actual observations are retained in the existing Actions cache: the latest ten checks within seven days, with **at least 90% successful checks** required. A check is one full admission attempt, not an individual HTTP request. A successful cached result is reused for at most 15 minutes and never counted as a new observation. Failed attempts are retried after 15 minutes. Fewer than three observations is **provisional**, not established reliability. New nodes can bootstrap the pool; once ten history-qualified candidates exist, no more than eight provisional nodes enter a publication. Cache loss restarts provisional history; Actions cache is not a permanent reliability database.

Selection prefers established history, then coarse performance bands combining median HTTPS delay, spread, failed individual samples and transfer elapsed time. Within a band it spreads actual exit IPs, entry prefixes, hostnames and protocol/transport/security combinations, retaining previous membership in equal ties. Strict caps: **two nodes per exit IP, four per entry /24 IPv4 or /48 IPv6 prefix, two per hostname**. Prefixes approximate infrastructure diversity, not provider/ASN identity. The caps are never relaxed to fill forty slots. Fewer than two qualifying nodes stops publication and keeps the previous subscription; unchecked nodes are never substituted. The Android size guard remains.

Published order follows quality bands and then the existing exact median HEAD latency. Client **leastPing**, three-minute health checks, routing, DNS, geodata and startup fallback behavior remain unchanged. `report.json.quality_selection` records selected-node observations, history status, thresholds and measurement evidence; `latency_selection` retains the existing HEAD measurements. Observations are committed only as report evidence, never as response bodies or cookies. Tests run from GitHub and do not establish reachability, speed, UDP support or application availability on a user's operator.

## Admission and updates

TLS nodes still require configured SNI/name, chain and expiry verification with system CAs, plus successful HTTPS egress through the exact Xray outbound. REALITY is admitted only after an actual authenticated HTTPS request through Xray. Shadowsocks still needs successful HTTPS egress. Insecure transport flags remain rejected. Actual exits must be public and outside RU; Russian entry addresses and labels are allowed.

IPsum refreshes daily and expires after 72 hours; a usable cache may cover a feed outage. Without usable reputation evidence the build fails rather than assigning clean scores. Certificate evidence expires within one hour or at certificate expiry. Failed checks exclude candidates; failed builds keep the last published subscription. Evidence stays in the Actions cache, while `report.json` describes the selected publication.

Every GitHub Actions run resolves the latest stable official Xray release, downloads assets from that exact version, and verifies the archive's publisher SHA256 before installation. A release lookup, download or validation failure stops publication and keeps the previous subscription. This updates only the CI core, not the apps on devices. The selected version and checksum appear in the job log.

GitHub Actions runs at minutes 7, 22, 37 and 52 each hour. CI checks JSON/Xray validity plus 14 isolated routing cases covering RU domains, GeoIP, LAN, ads, foreign traffic, sniffing, conflicting original-IP/DNS destinations and DNS with the production rule order and balancer tags; it cannot confirm device connectivity on a particular mobile operator.

## Repository files

- `happ.txt`, `incy.txt`: client-specific mixed-body import candidates; device verification pending.
- `subscription.json`: pure JSON fallback; `ru-karing-happ.txt`: identical JSON consumed by the existing Worker.
- `subscription-delivery.json`: consistent config/profile/hash evidence; `subscription_delivery.py`: generates stable geofile version metadata.
- `happ-worker.js`: historical source copy; deployed version not yet verified; `test_happ_worker.mjs`: header/body compatibility tests.
- `generate.py`, `rjsxrd_parser.py`, `pool_selection.py`, `certificate_checks.py`, `ip_reputation.py`, `latency_checks.py`: collect, verify, select and rank servers.
- `karing.py`, `russia_config.py`, `routing.py`, `settings.json`, `russia-routing.json`: common JSON generation and embedded routing policy.
- `ru.json`: last checked base pool, used for stable selection and routing-only rebuilds; `report.json`: selected-node verification and latency evidence.
- `setup_xray.py`, `check_subscription.py`, `publication_changed.py`, active `test_*.py` and `.github/workflows/update.yml`: reproducible validation and scheduled publication.
- `LICENSE.rjsxrd`: upstream parser licence and attribution.

Obsolete normal pools, diagnostic snapshots, old FakeDNS generators, sing-box setup, experimental subscriptions and committed validation databases are removed. No history rewriting is required.
