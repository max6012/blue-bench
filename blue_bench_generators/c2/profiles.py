"""C2 profile definitions + preset library.

Two profile families implement a shared ``C2Profile`` ABC:

* ``CommodityProfile`` -- loud cybercrime-foil C2 (RQ3 attribution side).
  Beacon cadence in seconds, jitter is modest, payload sizes are large,
  alerts WILL fire from a representative Suricata rule pack, and the
  ground-truth ``confidence`` is ``high``.

* ``StealthProfile`` -- low-and-slow LotL APT C2 (RQ2 detection side).
  Beacon cadence in hours, jitter is wide, payloads are small, alerts do
  NOT fire (the whole point), and the ground-truth ``confidence`` is
  ``medium``.

Preset names and the family fingerprints they represent are drawn from
public threat-intel write-ups. NO live indicators are baked in here -- the
catalogue is a SHAPE library, not an IOC feed. Domains use
``.example.invalid``; callback IPs default to TEST-NET-3 documentation
range when callers don't supply their own.

Schema-rule-4 reminder: a profile that emits a bundle MUST surface a
non-empty ``ttps_required`` set. Validators enforce this; presets that
return an empty TTP list are rejected at import time.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, Protocol, runtime_checkable


# Transport enum for the wire shape a profile uses. Stealth-DNS profiles
# emit ``dns`` + ``conn`` only; stealth-HTTPS / commodity emit the fuller
# stack.
Transport = Literal["http", "https", "dns"]


@runtime_checkable
class C2Profile(Protocol):
    """Structural protocol every profile family implements.

    Two concrete dataclasses (``CommodityProfile`` and ``StealthProfile``)
    satisfy this protocol. A Protocol rather than an ABC keeps the
    dataclass-driven attribute layout simple -- inherited class
    attributes would collide with dataclass field defaults.
    """

    # --- shared shape ---
    name: str
    family: str
    transport: Transport
    beacon_interval_seconds: float
    beacon_jitter_fraction: float
    payload_size_mean_bytes: int
    payload_size_jitter_fraction: float
    url_path_pattern: str
    tls_sni_pattern: str
    dns_query_pattern: str
    tls_fingerprint_hint: str
    suricata_rule_families: tuple[str, ...]
    ttps: tuple[str, ...]
    ttps_optional: tuple[str, ...]
    confidence: Literal["high", "medium", "low"]
    source_class: Literal["apt", "cybercrime"]

    def kind(self) -> Literal["commodity", "stealth"]:
        ...


# --- shared computed properties (free functions; profiles call these) ---
#
# Log-coverage matrix per task spec (t-c2-gen, "Components to build" >
# "Zeek emitter"):
#
#     commodity  (any transport)  -> all five: conn, dns, http, ssl, files
#         "loud traffic with full visibility" -- the spec rule covers the
#         realism hand-wave that commodity captures are typically taken
#         with TLS-key-export or MITM visibility, so http + files are
#         observable even on TLS-encrypted commodity C2.
#
#     stealth-HTTPS  -> conn + ssl ONLY
#         "TLS-encrypted, no HTTP content visible". Note the explicit
#         exclusion of dns: stealth profiles are presumed to resolve
#         endpoints via mechanisms that don't surface a dns.log
#         (cached resolution, hosts-file pinning, DoH bypass) or via
#         resolvers outside the captured perimeter.
#
#     stealth-DNS  -> conn + dns ONLY
#         "small queries, no HTTP at all". DNS is the C2 transport
#         itself.
#
# These rules drive both the Zeek emitter and the Suricata emitter so
# the on-the-wire visibility is consistent across both observers.


def emits_http_log(profile: C2Profile) -> bool:
    """Emit ``http``-shaped records only on cleartext HTTP transports.

    Tap-realistic: an unaided network tap can only reconstruct HTTP
    request/response bodies when the wire is cleartext. HTTPS C2
    (commodity or stealth) is opaque to the tap and gets no http
    record. If you ever need to model an analyst with TLS visibility
    (host-side capture, MITM with key export, decrypting proxy),
    introduce that as an explicit profile attribute or a separate
    authoring path -- the default here keeps the bench valid for
    unaided-tap reasoning so a model that flags "http body visible on
    TLS-port traffic" as anomalous isn't wrongly penalised.
    """
    return profile.transport == "http"


def emits_ssl_log(profile: C2Profile) -> bool:
    """Emit ``ssl`` / ``tls`` records on every HTTPS transport.

    Both commodity-HTTPS and stealth-HTTPS produce a TLS handshake on
    the wire; a passive tap sees the SSL record (server_name, cipher,
    JA3-shape hint) regardless of profile kind.
    """
    return profile.transport == "https"


def emits_dns_log(profile: C2Profile) -> bool:
    """Emit ``dns`` records on every profile.

    Real implants do DNS lookups before connecting (whether commodity
    or stealth), and for DNS-tunneled stealth profiles DNS IS the
    transport. A tap-realistic view shows the DNS query/response for
    every profile shape.
    """
    return True


def emits_files_log(profile: C2Profile) -> bool:
    """Emit ``files`` records only on cleartext HTTP transports.

    A tap can carve files out of HTTP because the bytes are visible on
    the wire. HTTPS is opaque; no files record. Same rationale as
    ``emits_http_log``: keep the bench valid for unaided-tap reasoning.
    """
    return profile.transport == "http"


@dataclass(frozen=True)
class CommodityProfile:
    """Loud cybercrime-flavoured C2.

    Confidence defaults to ``high``; source_class is ``cybercrime``.
    ``suricata_rule_families`` MUST be non-empty -- the commodity
    profile's discriminating property is that signature-based detection
    DOES fire.
    """

    name: str
    family: str
    transport: Transport
    beacon_interval_seconds: float
    beacon_jitter_fraction: float
    payload_size_mean_bytes: int
    payload_size_jitter_fraction: float
    url_path_pattern: str
    tls_sni_pattern: str
    dns_query_pattern: str
    tls_fingerprint_hint: str
    suricata_rule_families: tuple[str, ...]
    ttps: tuple[str, ...]
    ttps_optional: tuple[str, ...] = field(default_factory=tuple)
    confidence: Literal["high", "medium", "low"] = "high"
    source_class: Literal["apt", "cybercrime"] = "cybercrime"

    def kind(self) -> Literal["commodity", "stealth"]:
        return "commodity"


@dataclass(frozen=True)
class StealthProfile:
    """Low-and-slow LotL APT C2.

    Confidence defaults to ``medium`` -- per the schema doc, stealth
    annotations are intentionally low signal and the judge weighting
    downscales them. source_class is ``apt``.

    ``suricata_rule_families`` MUST be empty -- the stealth profile's
    discriminating property is that signature-based detection does NOT
    fire. Flow / DNS / TLS events still appear on the wire, but no
    alerts.
    """

    name: str
    family: str
    transport: Transport
    beacon_interval_seconds: float
    beacon_jitter_fraction: float
    payload_size_mean_bytes: int
    payload_size_jitter_fraction: float
    url_path_pattern: str
    tls_sni_pattern: str
    dns_query_pattern: str
    tls_fingerprint_hint: str
    suricata_rule_families: tuple[str, ...] = field(default_factory=tuple)
    ttps: tuple[str, ...] = field(default_factory=tuple)
    ttps_optional: tuple[str, ...] = field(default_factory=tuple)
    confidence: Literal["high", "medium", "low"] = "medium"
    source_class: Literal["apt", "cybercrime"] = "apt"

    def kind(self) -> Literal["commodity", "stealth"]:
        return "stealth"


# --- preset library ----------------------------------------------------------
#
# All SNI / domain strings below use ``.example.invalid`` per RFC 6761 and
# never reference a real CDN / cloud-provider domain. Preset NAMES may
# reference a real family (Cobalt Strike, IcedID, ...) because the
# preset name is a shape-of-traffic label, not a redistribution.


COMMODITY_PRESETS: tuple[CommodityProfile, ...] = (
    # 1. Cobalt Strike default Malleable C2 profile.
    #    60s beacon, 20% jitter, default URI path is the textbook tell.
    CommodityProfile(
        name="cobalt-strike-default",
        family="Cobalt Strike (default Malleable profile)",
        transport="https",
        beacon_interval_seconds=60.0,
        beacon_jitter_fraction=0.2,
        payload_size_mean_bytes=4096,
        payload_size_jitter_fraction=0.5,
        url_path_pattern="/cm/jquery-3.3.1.min.js?__cf_chl_jschl_tk__=%(seq)08x",
        tls_sni_pattern="cdn-static-%(seq)03d.example.invalid",
        dns_query_pattern="cdn-static-%(seq)03d.example.invalid",
        tls_fingerprint_hint="cs-default-ja3",
        suricata_rule_families=(
            "ET MALWARE Cobalt Strike Beacon (HTTP)",
            "ET POLICY Cobalt Strike Malleable C2 Profile URI",
        ),
        ttps=(
            "T1071.001",  # Web protocols
            "T1573.002",  # Encrypted Channel: Asymmetric Cryptography
            "T1090",      # Proxy / redirector
            "T1041",      # Exfil over C2
        ),
        ttps_optional=(
            "T1568.002",  # Domain Generation Algorithms (some profiles)
        ),
    ),
    # 2. IcedID HTTP C2 -- early loader stage with HTTP-form data POSTs.
    CommodityProfile(
        name="icedid-http",
        family="IcedID (Bokbot) HTTP loader stage",
        transport="http",
        beacon_interval_seconds=300.0,
        beacon_jitter_fraction=0.15,
        payload_size_mean_bytes=2048,
        payload_size_jitter_fraction=0.4,
        url_path_pattern="/news/?_=%(seq)d",
        tls_sni_pattern="",
        dns_query_pattern="news-update-cdn-%(seq)03d.example.invalid",
        tls_fingerprint_hint="",
        suricata_rule_families=(
            "ET MALWARE Win32/IcedID HTTP CnC Beacon",
            "ET MALWARE IcedID HTTP CnC Activity",
        ),
        ttps=(
            "T1071.001",
            "T1568.002",  # IcedID is known DGA-adjacent
            "T1041",
        ),
        ttps_optional=(
            "T1027",
        ),
    ),
    # 3. BumbleBee TLS C2 -- distinctive JA3, large POST bodies.
    CommodityProfile(
        name="bumblebee-tls",
        family="BumbleBee loader (TLS C2)",
        transport="https",
        beacon_interval_seconds=120.0,
        beacon_jitter_fraction=0.25,
        payload_size_mean_bytes=8192,
        payload_size_jitter_fraction=0.5,
        url_path_pattern="/gate.php?id=%(seq)08x",
        tls_sni_pattern="api-status-%(seq)03d.example.invalid",
        dns_query_pattern="api-status-%(seq)03d.example.invalid",
        tls_fingerprint_hint="bumblebee-ja3",
        suricata_rule_families=(
            "ET MALWARE BumbleBee Loader CnC Beacon",
            "ET MALWARE BumbleBee Loader Activity",
        ),
        ttps=(
            "T1071.001",
            "T1573.002",
            "T1041",
        ),
        ttps_optional=(
            "T1055",
            "T1027",
        ),
    ),
    # 4. Lumma Stealer HTTPS C2 -- credential exfil pattern.
    CommodityProfile(
        name="lumma-https",
        family="Lumma Stealer HTTPS C2",
        transport="https",
        beacon_interval_seconds=180.0,
        beacon_jitter_fraction=0.3,
        payload_size_mean_bytes=16384,  # large -- credential exfil
        payload_size_jitter_fraction=0.6,
        url_path_pattern="/api/%(seq)d/submit",
        tls_sni_pattern="data-collect-%(seq)03d.example.invalid",
        dns_query_pattern="data-collect-%(seq)03d.example.invalid",
        tls_fingerprint_hint="lumma-ja3-2026q1",
        suricata_rule_families=(
            "ET MALWARE Lumma Stealer Exfiltration",
            "ET MALWARE Lumma Stealer CnC Beacon",
        ),
        ttps=(
            "T1071.001",
            "T1573.002",
            "T1041",
            "T1555.003",  # Credentials from web browsers
        ),
        ttps_optional=(
            "T1056.001",
        ),
    ),
    # 5. Hancitor stage HTTP -- pre-CS staging traffic with the textbook
    #    URI shape Brad Duncan documents on MTA.
    CommodityProfile(
        name="hancitor-stage",
        family="Hancitor staging (pre-Cobalt-Strike)",
        transport="http",
        beacon_interval_seconds=240.0,
        beacon_jitter_fraction=0.1,
        payload_size_mean_bytes=1024,
        payload_size_jitter_fraction=0.3,
        url_path_pattern="/8/forum.php",
        tls_sni_pattern="",
        dns_query_pattern="forum-host-%(seq)03d.example.invalid",
        tls_fingerprint_hint="",
        suricata_rule_families=(
            "ET MALWARE Hancitor/Chanitor CnC Beacon",
            "ET MALWARE Hancitor Checkin",
        ),
        ttps=(
            "T1071.001",
            "T1041",
        ),
        ttps_optional=(
            "T1027",
        ),
    ),
)


STEALTH_PRESETS: tuple[StealthProfile, ...] = (
    # 1. LotL HTTPS to a CDN-shaped SNI.
    #    4h beacon, 50% jitter, small payloads.
    StealthProfile(
        name="lotl-https-cloudfront",
        family="LotL HTTPS via legitimate-CDN-shaped SNI",
        transport="https",
        beacon_interval_seconds=14400.0,  # 4h
        beacon_jitter_fraction=0.5,
        payload_size_mean_bytes=256,
        payload_size_jitter_fraction=0.4,
        url_path_pattern="/static/css/main.%(seq)08x.css",
        tls_sni_pattern="cdn-assets.example.invalid",
        dns_query_pattern="cdn-assets.example.invalid",
        tls_fingerprint_hint="modern-tls-fingerprint",
        suricata_rule_families=(),
        ttps=(
            "T1071.001",
            "T1573.002",
            "T1090",
        ),
        ttps_optional=(
            "T1568.002",
        ),
    ),
    # 2. LotL HTTPS to a cloud-provider-shaped SNI (Azure-like).
    StealthProfile(
        name="lotl-https-azure",
        family="LotL HTTPS via legitimate-cloud-shaped SNI",
        transport="https",
        beacon_interval_seconds=21600.0,  # 6h
        beacon_jitter_fraction=0.6,
        payload_size_mean_bytes=128,
        payload_size_jitter_fraction=0.5,
        url_path_pattern="/api/health?ts=%(seq)d",
        tls_sni_pattern="api-prod.example.invalid",
        dns_query_pattern="api-prod.example.invalid",
        tls_fingerprint_hint="modern-tls-fingerprint",
        suricata_rule_families=(),
        ttps=(
            "T1071.001",
            "T1573.002",
            "T1090.003",  # Multi-hop proxy
        ),
        ttps_optional=(
            "T1568.002",
        ),
    ),
    # 3. LotL DNS-tunneled exfil. dns + conn only.
    StealthProfile(
        name="lotl-dns-tunneled",
        family="LotL DNS-tunneled C2",
        transport="dns",
        beacon_interval_seconds=10800.0,  # 3h
        beacon_jitter_fraction=0.5,
        payload_size_mean_bytes=64,  # encoded in subdomain length
        payload_size_jitter_fraction=0.3,
        url_path_pattern="",
        tls_sni_pattern="",
        dns_query_pattern="%(payload)s.tunnel-host.example.invalid",
        tls_fingerprint_hint="",
        suricata_rule_families=(),
        ttps=(
            "T1071.004",  # DNS application layer protocol
            "T1572",      # Protocol Tunneling
            "T1041",
        ),
        ttps_optional=(
            "T1568.002",
        ),
    ),
    # 4. LotL domain-fronted HTTPS (SNI != Host).
    StealthProfile(
        name="lotl-domain-fronted",
        family="LotL domain-fronted HTTPS C2",
        transport="https",
        beacon_interval_seconds=18000.0,  # 5h
        beacon_jitter_fraction=0.7,
        payload_size_mean_bytes=512,
        payload_size_jitter_fraction=0.5,
        url_path_pattern="/v1/telemetry",
        tls_sni_pattern="legitimate-front.example.invalid",
        dns_query_pattern="legitimate-front.example.invalid",
        tls_fingerprint_hint="modern-tls-fingerprint",
        suricata_rule_families=(),
        ttps=(
            "T1071.001",
            "T1573.002",
            "T1090.004",  # Domain Fronting
        ),
        ttps_optional=(
            "T1568.002",
        ),
    ),
)


# Index for fast lookup.
_PRESETS_BY_NAME: dict[str, C2Profile] = {p.name: p for p in COMMODITY_PRESETS}
_PRESETS_BY_NAME.update({p.name: p for p in STEALTH_PRESETS})


def get_preset(name: str) -> C2Profile:
    """Look up a named preset; raise ``KeyError`` if unknown."""
    if name not in _PRESETS_BY_NAME:
        raise KeyError(
            f"unknown C2 preset {name!r}; known: {sorted(_PRESETS_BY_NAME)}"
        )
    return _PRESETS_BY_NAME[name]


def preset_names() -> list[str]:
    """Return preset names in catalogue order (commodity first, then stealth)."""
    return [p.name for p in COMMODITY_PRESETS] + [p.name for p in STEALTH_PRESETS]


# --- import-time sanity ---

assert len(COMMODITY_PRESETS) >= 5, (
    f"commodity preset library must have at least 5 entries (have {len(COMMODITY_PRESETS)})"
)
assert len(STEALTH_PRESETS) >= 4, (
    f"stealth preset library must have at least 4 entries (have {len(STEALTH_PRESETS)})"
)
for _p in COMMODITY_PRESETS:
    assert _p.ttps, f"commodity preset {_p.name} has empty ttps (schema rule 4)"
    assert _p.suricata_rule_families, (
        f"commodity preset {_p.name} must declare at least one Suricata rule "
        f"family; commodity profiles MUST be alertable"
    )
    assert _p.source_class == "cybercrime"
for _p in STEALTH_PRESETS:
    assert _p.ttps, f"stealth preset {_p.name} has empty ttps (schema rule 4)"
    assert _p.suricata_rule_families == (), (
        f"stealth preset {_p.name} must NOT declare Suricata rule families; "
        f"stealth profiles MUST be alert-silent"
    )
    assert _p.source_class == "apt"
_seen_names: set[str] = set()
for _p in (*COMMODITY_PRESETS, *STEALTH_PRESETS):
    assert _p.name not in _seen_names, f"duplicate preset name {_p.name!r}"
    _seen_names.add(_p.name)
