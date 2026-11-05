# MIT: whoahaow/rjsxrd, source/utils helpers, revision d3a2a7f2b78418863035d498f977e6b1c136dcb7.
# Only parser dependencies are vendored; runtime/application helpers are omitted.
import re
from typing import Any
from urllib.parse import parse_qs, unquote

TLS_FINGERPRINT = "chrome"

_SS_2022_KEY_LENGTHS = {
    "2022-blake3-aes-128-gcm": 16,
    "2022-blake3-aes-256-gcm": 32,
    "2022-blake3-chacha20-poly1305": 32,
}

SS_PLAINTEXT_CIPHERS = {"none", "plain"}

SS_XRAY_CIPHERS = {
    "aes-128-gcm",
    "aead_aes_128_gcm",
    "aes-256-gcm",
    "aead_aes_256_gcm",
    "chacha20-poly1305",
    "chacha20-ietf-poly1305",
    "aead_chacha20_poly1305",
    "xchacha20-poly1305",
    "xchacha20-ietf-poly1305",
    "aead_xchacha20_poly1305",
    *_SS_2022_KEY_LENGTHS,
    *SS_PLAINTEXT_CIPHERS,
}

def is_xray_cipher(method: str) -> bool:
    """Whether xray's Shadowsocks loader would accept this cipher method."""
    return method.strip().lower() in SS_XRAY_CIPHERS

def base64_payload(url: str) -> str:
    """The encoded payload of a URL, without its remark or parameters.

    Everything after `://` up to whichever separator comes first. Only the base64
    forms may be read this way: on a `vless://` or `trojan://` link the `?` introduces
    the parameters that *are* the configuration, and a caller that sliced those off
    would be handing xray a node with no transport, no SNI and no fingerprint.
    """
    body = url[url.index("://") + 3 :] if "://" in url else url
    cut = len(body)
    for separator in "#?":
        index = body.find(separator)
        if index != -1 and index < cut:
            cut = index
    return body[:cut]

def query_parameters(query: str) -> dict[str, list[str]]:
    """A query string parsed with its parameter names folded to lowercase.

    Three readers look at these names and disagreed about case: the compatibility
    filter matched them with `re.IGNORECASE` from the start, on the documented reason
    that YAML converters emit both `pbk` and `PBK`, while both outbound builders
    indexed `parse_qs` output with literal lowercase keys. A URL spelled
    `?Security=tls&Type=ws&SNI=…` therefore certified as encrypted by one reader and
    built as `security: none, network: tcp` by the other two -- a node dialed over the
    wrong wire, which comes back as a dead server rather than as a parse error.

    Values are left exactly as they arrived. A publicKey and a shortId are base64 and
    hex, where case is data; the fields whose case xray itself folds are folded by
    `xray_stream_settings`, which cites the line that folds them.
    """
    folded: dict[str, list[str]] = {}
    for name, values in parse_qs(query).items():
        folded.setdefault(name.lower(), []).extend(values)
    return folded

_REJECTED_FINGERPRINTS = frozenset({"unsafe", "hellogolang"})

_RE_FINGERPRINT = re.compile(r"^[a-z0-9]{2,32}$")

def xray_fingerprint(fp: str | None) -> str:
    """The ClientHello id to test with, in a spelling xray resolves."""

    value = (fp or "").strip().lower()
    if not _RE_FINGERPRINT.match(value) or value in _REJECTED_FINGERPRINTS:
        return TLS_FINGERPRINT
    return value

_WS_NAMES = frozenset({"ws", "websocket"})

_XHTTP_NAMES = frozenset({"xhttp", "splithttp"})

def _make_grpc_settings(service_name: str) -> dict:
    """Build grpcSettings dict."""
    return {"serviceName": unquote(service_name)}

def _make_httpupgrade_settings(path: str, host: str) -> dict:
    """Build httpupgradeSettings dict — `host`, not a `headers` map."""
    return {"path": unquote(path), "host": unquote(host)}

def _make_ws_settings(path: str, host: str) -> dict:
    """Build wsSettings dict.

    `host` is the field xray's WebSocketConfig reads; a `host` inside `headers` is
    still honored but only as a fallback and it prints a deprecation warning, so
    the deprecated shape is not emitted.
    """
    return {"path": unquote(path), "host": unquote(host)}

_XHTTP_MODES = frozenset({"auto", "stream-up", "stream-one", "packet-up"})

def _make_xhttp_settings(path: str, host: str, mode: str) -> dict:
    """Build xhttpSettings dict. `network: splithttp` and `xhttp` share it.

    Only the modes `SplitHTTPConfig.Build()` accepts are emitted; an unknown one is
    `unsupported mode` there, and omitting the field makes xray default to `auto`.
    """
    settings: dict[str, Any] = {"path": unquote(path), "host": unquote(host)}
    if mode in _XHTTP_MODES:
        settings["mode"] = mode
    return settings

_TLS_OFF = frozenset({"", "none", "off", "0", "false", "no"})

_TLS_ON = frozenset({"tls", "1", "true", "yes", "on"})

def vmess_security(raw: object) -> str:
    """The `security` spelling xray reads, from a vmess object's `tls` field."""
    value = str(raw if raw is not None else "").strip().lower()
    if value in _TLS_OFF:
        return "none"
    if value in _TLS_ON:
        return "tls"
    return value
