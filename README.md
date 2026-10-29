# Common automatic subscription for INCY and Happ

Use the same URL in both clients:

https://raw.githubusercontent.com/RnRLover/rjsxrd-karing-subscription/refs/heads/main/subscription.json

One pure JSON array, one **Основной** configuration. The old `ru-karing-incy.txt`, `ru-karing-happ.txt` URLs are byte-identical compatibility aliases, not different subscriptions. No provider interval, routing import command or separate routing profile is attached. Disable/remove a previously imported Russia profile in the app, or import the common URL as a new subscription.

## Routing

Embedded rules block `geosite:category-ads-all`; route `geosite:category-ru`, `geoip:ru` and private/local networks directly; route other TCP/UDP via the automatic pool. The core uses the clients' standard `geosite.dat` and `geoip.dat`; keep those databases current. CI downloads its validation databases into ignored `.runtime/` files. No geodata downloads or routing-profile imports are attached to the subscription.

The subscription supplies **no DNS configuration**, no DNS outbound and no FakeDNS. Port 53 traffic keeps its original destination and goes directly. DNS settings belong to the client. `IPOnDemand` lets domain destinations be checked against GeoIP before the final proxy rule, using the resolver available to Xray; it does not supply a resolver address. Sniffing recovers HTTP/TLS/QUIC hostnames for routing without changing the destination.

## Pool and automatic selection

All duplicate-free working foreign exits are considered. Every IPsum-listed exit is excluded, even if there is free space. Unlisted IPv4 and addresses outside the feed's coverage remain eligible; unknown coverage is reported, not called clean. Absence from IPsum is not a positive whitelist or a guarantee of Google/Gemini access.

The artificial 24-node cap is removed. The pool grows to the conservative Android size budget (220,000 UTF-16 bytes for the base configuration, leaving room for client patching), with a 512-node resource ceiling. When not all candidates fit, greedy selection spreads actual exit IPs, entry network prefixes (/24 IPv4 or /48 IPv6), hostnames and protocol/transport/security combinations. Previous membership stabilizes equal choices. Prefix diversity approximates infrastructure diversity; it does not prove different providers/ASNs.

Client `leastPing` selects an available server with the lowest measured delay. `burstObservatory` measures HTTPS health every three minutes, one sample per node with a five-second timeout. Before initial results exist, it can use the first checked pool member; it never falls back to direct access for foreign traffic. After diversity and size determine membership, the chosen pool is ordered by ascending median HTTPS latency measured through each exact Xray outbound on the GitHub Actions runner. Two HEAD requests to `https://www.gstatic.com/generate_204` (five seconds each, HTTP 204 required) supply the median; usable evidence is cached for up to one hour. Partial measurements use their successful samples, and nodes with no successful measurement go last without being removed. Equal values preserve diversity order. `report.json.latency_selection` lists per-node samples and failures in the published order. Runner latency differs from device latency; client leastPing continues to choose using measurements on the device.

## Admission and updates

TLS nodes still require configured SNI/name, chain and expiry verification with system CAs, plus successful HTTPS egress through the exact Xray outbound. REALITY is admitted only after an actual authenticated HTTPS request through Xray. Shadowsocks still needs successful HTTPS egress. Insecure transport flags remain rejected. Actual exits must be public and outside RU; Russian entry addresses and labels are allowed.

IPsum refreshes daily and expires after 72 hours; a usable cache may cover a feed outage. Without usable reputation evidence the build fails rather than assigning clean scores. Certificate evidence expires within one hour or at certificate expiry. Failed checks exclude candidates; failed builds keep the last published subscription. Evidence stays in the Actions cache, while `report.json` describes the selected publication.

GitHub Actions runs at minutes 7, 22, 37 and 52 each hour. CI checks JSON/Xray validity, routing policy, local DNS exchange and TCP traffic; it cannot confirm device connectivity on a particular mobile operator.

## Repository files

- `subscription.json`: common client subscription; `ru-karing-incy.txt` and `ru-karing-happ.txt` are identical aliases retained for existing URLs.
- `generate.py`, `rjsxrd_parser.py`, `pool_selection.py`, `certificate_checks.py`, `ip_reputation.py`, `latency_checks.py`: collect, verify, select and rank servers.
- `karing.py`, `russia_config.py`, `routing.py`, `settings.json`, `russia-routing.json`: common JSON generation and embedded routing policy.
- `ru.json`: last checked base pool, used for stable selection and routing-only rebuilds; `report.json`: selected-node verification and latency evidence.
- `setup_xray.py`, `check_subscription.py`, `publication_changed.py`, active `test_*.py` and `.github/workflows/update.yml`: reproducible validation and scheduled publication.
- `LICENSE.rjsxrd`: upstream parser licence and attribution.

Obsolete normal pools, diagnostic snapshots, separate routing/FakeDNS generators, Happ Worker, sing-box setup, experimental subscriptions and committed validation databases are removed. No history rewriting is required.
