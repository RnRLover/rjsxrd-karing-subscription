# Common automatic subscription for INCY and Happ

Use the same URL in both clients:

https://raw.githubusercontent.com/RnRLover/rjsxrd-karing-subscription/refs/heads/main/subscription.json

One pure JSON array, one **Основной** configuration. The old `ru-karing-incy.txt`, `ru-karing-happ.txt` and routing-test URLs are byte-identical compatibility aliases, not different subscriptions. No provider interval, routing import command or separate routing profile is attached. Disable/remove a previously imported Russia profile in the app, or import the common URL as a new subscription.

## Routing

Embedded rules block `geosite:category-ads-all`; route `geosite:category-ru`, `geoip:ru` and private/local networks directly; route other TCP/UDP via the automatic pool. The core uses the clients' standard `geosite.dat` and `geoip.dat`; keep those databases current. Published `karing-*.dat` files are the exact databases used by CI validation and remain available as reference assets. They are not imported as a routing profile.

The subscription supplies **no DNS configuration**, no DNS outbound and no FakeDNS. Port 53 traffic keeps its original destination and goes directly. DNS settings belong to the client. `IPOnDemand` lets domain destinations be checked against GeoIP before the final proxy rule, using the resolver available to Xray; it does not supply a resolver address. Sniffing recovers HTTP/TLS/QUIC hostnames for routing without changing the destination.

## Pool and automatic selection

All duplicate-free working foreign exits are considered. Every IPsum-listed exit is excluded, even if there is free space. Unlisted IPv4 and addresses outside the feed's coverage remain eligible; unknown coverage is reported, not called clean. Absence from IPsum is not a positive whitelist or a guarantee of Google/Gemini access.

The artificial 24-node cap is removed. The pool grows to the conservative Android size budget (220,000 UTF-16 bytes for the base configuration, leaving room for client patching), with a 512-node resource ceiling. When not all candidates fit, greedy selection spreads actual exit IPs, entry network prefixes (/24 IPv4 or /48 IPv6), hostnames and protocol/transport/security combinations. Previous membership stabilizes equal choices. Prefix diversity approximates infrastructure diversity; it does not prove different providers/ASNs.

Client `leastPing` selects an available server with the lowest measured delay. `burstObservatory` measures HTTPS health every three minutes, one sample per node with a five-second timeout. Before initial results exist, it can use the first checked pool member; it never falls back to direct access for foreign traffic. GitHub-runner latency no longer ranks or excludes servers.

## Admission and updates

TLS nodes still require configured SNI/name, chain and expiry verification with system CAs, plus successful HTTPS egress through the exact Xray outbound. REALITY is admitted only after an actual authenticated HTTPS request through Xray. Shadowsocks still needs successful HTTPS egress. Insecure transport flags remain rejected. Actual exits must be public and outside RU; Russian entry addresses and labels are allowed.

IPsum refreshes daily and expires after 72 hours; a usable cache may cover a feed outage. Without usable reputation evidence the build fails rather than assigning clean scores. Certificate evidence expires within one hour or at certificate expiry. Failed checks exclude candidates; failed builds keep the last published subscription. Evidence stays in the Actions cache, while `report.json` describes the selected publication.

GitHub Actions runs at minutes 7, 22, 37 and 52 each hour. CI checks JSON/Xray validity, routing policy, local DNS exchange and TCP traffic; it cannot confirm device connectivity on a particular mobile operator.
