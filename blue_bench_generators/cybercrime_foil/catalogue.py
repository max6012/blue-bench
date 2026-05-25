"""PCAP catalogue: v1 shortlist of 16 cybercrime PCAPs from MTA.

Each entry references a public malware-traffic-analysis.net writeup. The URLs
are factual references to public exercises — they are NOT a redistribution of
MTA content. Raw PCAP bytes are NEVER committed to this repo; the downloader
fetches them into ``data/raw/mta/<incident_id>/`` which is gitignored.

Attribution-fidelity grades (H/M/L) follow the eval-mta.md rubric:
    H — cleartext payload + distinctive protocol/family fingerprint;
        sub-technique resolution feasible.
    M — TLS-encrypted but well-documented family with stable JA3/JA4 + SNI;
        technique-level resolution.
    L — TLS-only modern, family freshness or opacity limits attribution to
        gross bucket only.

Per the schema (rule 11), ``attribution_required`` MUST be a subset of
``ttps_required + ttps_optional``. Pre-authored from Brad Duncan's writeup
narratives + public community reverse-engineering for each family. H-grade
entries resolve to sub-technique IDs; L-grade entries stay coarse.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class CatalogueEntry:
    """One MTA writeup reference + pre-authored TTP attribution.

    Attributes:
        incident_id: kebab-case stable id; convention ``mta-<YYYY-MM-DD>-<slug>``.
        url: link to the MTA writeup HTML page (NOT to a PCAP zip directly).
        family: free-text family chain from the writeup title.
        date: ISO-8601 date of the original capture (UTC).
        attribution_fidelity: ``H`` | ``M`` | ``L`` per eval-mta.md.
        ttps_required: MITRE ATT&CK technique IDs the analyst MUST surface.
        ttps_optional: techniques plausibly demonstrated; bonus credit only.
        attribution_required: subset of ``ttps_required`` that earns full
            attribution credit (rule-11 subset of total ttps).
        accepted_alternates: per-required-TTP map of accepted parent/sibling
            techniques (e.g. surfacing T1059 when required was T1059.001).
        narrative_facts: plain-language analyst-note claims.
        archive_sha256: SHA256 of the downloaded zip archive when known;
            empty string means "unknown — warn the operator, do not gate".
    """

    incident_id: str
    url: str
    family: str
    date: str
    attribution_fidelity: str
    ttps_required: tuple[str, ...]
    ttps_optional: tuple[str, ...]
    attribution_required: tuple[str, ...]
    accepted_alternates: dict[str, tuple[str, ...]] = field(default_factory=dict)
    narrative_facts: tuple[str, ...] = field(default_factory=tuple)
    archive_sha256: str = ""

    @property
    def all_ttps(self) -> tuple[str, ...]:
        """Union of required + optional. Used as the schema's ``ttps`` field."""
        seen: list[str] = []
        for t in self.ttps_required + self.ttps_optional:
            if t not in seen:
                seen.append(t)
        return tuple(seen)


# Standard MTA zip password. Documented as an image on the MTA about page;
# the IR community uses ``infected`` by convention. Downloader fails loud if
# the password ever rejects a fetched zip — do not silently re-guess.
MTA_ZIP_PASSWORD = "infected"


# Canonical "parent-technique-accepted" map applied where a required entry is
# a sub-technique (e.g. T1059.001 accepts T1059). Pre-merged into each
# entry's ``accepted_alternates`` at construction.
def _parent_alt(tid: str) -> dict[str, tuple[str, ...]]:
    if "." in tid:
        return {tid: (tid.split(".")[0],)}
    return {}


def _alternates(*tids: str) -> dict[str, tuple[str, ...]]:
    out: dict[str, tuple[str, ...]] = {}
    for t in tids:
        out.update(_parent_alt(t))
    return out


CATALOGUE: tuple[CatalogueEntry, ...] = (
    # 1 — 2025-08-20 SmartApeSG → ClickFix → NetSupport RAT → StealCv2  (H)
    CatalogueEntry(
        incident_id="mta-2025-08-20-smartapesg-netsupport-stealc",
        url="https://www.malware-traffic-analysis.net/2025/08/20/index.html",
        family="SmartApeSG CAPTCHA -> ClickFix -> NetSupport RAT -> StealCv2",
        date="2025-08-20",
        attribution_fidelity="H",
        ttps_required=(
            "T1189",      # Drive-by Compromise (compromised-site CAPTCHA gate)
            "T1204.004",  # User Execution: Malicious Copy and Paste (ClickFix)
            "T1059.003",  # Command and Scripting Interpreter: Windows Command Shell
            "T1219",      # Remote Access Software (NetSupport RAT)
            "T1555",      # Credentials from Password Stores (StealC family)
        ),
        ttps_optional=(
            "T1071.001",  # Web protocols (NetSupport C2 over HTTP)
            "T1041",      # Exfiltration Over C2 Channel
        ),
        attribution_required=("T1204.004", "T1219", "T1555"),
        accepted_alternates=_alternates("T1204.004", "T1059.003", "T1071.001"),
        narrative_facts=(
            "Initial vector was a compromised-site CAPTCHA gate that delivered a ClickFix social-engineering payload.",
            "User-executed clipboard command launched a Windows command shell loader.",
            "NetSupport RAT C2 traffic is non-TLS on a non-standard port and is a strong family-attribution anchor.",
        ),
    ),
    # 2 — 2025-09-03 KongTuke ClickFix -> Lumma Stealer  (M)
    CatalogueEntry(
        incident_id="mta-2025-09-03-kongtuke-lumma",
        url="https://www.malware-traffic-analysis.net/2025/09/03/index.html",
        family="KongTuke CAPTCHA -> ClickFix -> Lumma Stealer",
        date="2025-09-03",
        attribution_fidelity="M",
        ttps_required=(
            "T1189",
            "T1204.004",
            "T1059.001",  # PowerShell loader stage
            "T1555.003",  # Credentials from Web Browsers (Lumma)
        ),
        ttps_optional=(
            "T1071.001",
            "T1573.002",  # Encrypted Channel: Asymmetric Cryptography (TLS C2)
        ),
        attribution_required=("T1204.004", "T1555.003"),
        accepted_alternates=_alternates("T1204.004", "T1059.001", "T1071.001", "T1573.002", "T1555.003"),
        narrative_facts=(
            "KongTuke compromised-site injector routed the victim to a CAPTCHA-style gate.",
            "ClickFix copy-paste payload launched PowerShell stage.",
            "Lumma C2 is TLS but the JA3 + SNI patterns match published Lumma campaigns.",
        ),
    ),
    # 3 — 2026-02-02 KongTuke ClickFix -> MintsLoader -> GhostWeaver  (L)
    CatalogueEntry(
        incident_id="mta-2026-02-02-kongtuke-mintsloader-ghostweaver",
        url="https://www.malware-traffic-analysis.net/2026/02/02/index.html",
        family="KongTuke ClickFix -> MintsLoader -> GhostWeaver RAT",
        date="2026-02-02",
        attribution_fidelity="L",
        # L-grade: gross-bucket only. Stay at technique level, no sub-techniques.
        ttps_required=(
            "T1189",
            "T1204",      # User Execution (technique level, not sub)
            "T1059",      # Command and Scripting Interpreter (technique level)
            "T1071",      # Application Layer Protocol (technique level)
        ),
        ttps_optional=(
            "T1219",
            "T1573",
        ),
        attribution_required=("T1204", "T1059"),
        accepted_alternates={},
        narrative_facts=(
            "Fresh-family loader (MintsLoader) with limited published reverse-engineering — attribution stays gross-bucket.",
            "GhostWeaver RAT C2 is TLS-only; on-wire signal limited to flow shape + SNI patterns.",
        ),
    ),
    # 4 — 2026-04-16 Lumma + Sectop RAT / ArechClient2  (M)
    CatalogueEntry(
        incident_id="mta-2026-04-16-lumma-sectop",
        url="https://www.malware-traffic-analysis.net/2026/04/16/index.html",
        family="Lumma Stealer + Sectop RAT (ArechClient2)",
        date="2026-04-16",
        attribution_fidelity="M",
        ttps_required=(
            "T1566.002",  # Phishing: Spearphishing Link
            "T1204.001",  # User Execution: Malicious Link
            "T1555.003",
            "T1219",
        ),
        ttps_optional=(
            "T1071.001",
            "T1573.002",
        ),
        attribution_required=("T1555.003", "T1219"),
        accepted_alternates=_alternates("T1566.002", "T1204.001", "T1555.003", "T1071.001", "T1573.002"),
        narrative_facts=(
            "Lumma C2 fingerprint matches the published 2026-Q1 JA3 cluster.",
            "Sectop RAT (ArechClient2) carries some cleartext C2 elements historically.",
        ),
    ),
    # 5 — 2022-12-20 IcedID + Cobalt Strike  (H)  -- canonical example incident
    CatalogueEntry(
        incident_id="mta-2022-12-20-icedid-cs",
        url="https://www.malware-traffic-analysis.net/2022/12/20/index.html",
        family="IcedID (Bokbot) + Cobalt Strike",
        date="2022-12-20",
        attribution_fidelity="H",
        ttps_required=(
            "T1566.001",  # Spearphishing Attachment
            "T1204.002",  # User Execution: Malicious File
            "T1059.001",  # PowerShell
            "T1055",      # Process Injection
            "T1071.001",  # Web Protocols
            "T1573.002",  # Encrypted Channel: Asymmetric Cryptography
        ),
        ttps_optional=(
            "T1090",      # Proxy (CS redirector)
            "T1041",      # Exfil over C2
            "T1027",      # Obfuscated Files
            "T1218",      # System Binary Proxy Execution
        ),
        attribution_required=("T1566.001", "T1059.001", "T1071.001", "T1573.002"),
        accepted_alternates=_alternates("T1566.001", "T1204.002", "T1059.001", "T1071.001", "T1573.002"),
        narrative_facts=(
            "Initial vector was an email attachment delivered to a user mailbox.",
            "PowerShell loader was launched from a user-mode process, indicating user execution rather than admin-driven activity.",
            "Subsequent C2 traffic uses TLS with a beaconing cadence consistent with Cobalt Strike default profiles.",
            "This is commodity cybercrime (IcedID -> Cobalt Strike chain), not a targeted APT — Cobalt Strike here is shared infrastructure with APT operators, so attribution must rest on the IcedID delivery chain, not on the CS beacon alone.",
        ),
    ),
    # 6 — 2022-11-28 Qakbot + Cobalt Strike + VNC  (H)
    CatalogueEntry(
        incident_id="mta-2022-11-28-qakbot-cs-vnc",
        url="https://www.malware-traffic-analysis.net/2022/11/28/index.html",
        family="Qakbot (Qbot) + Cobalt Strike + VNC",
        date="2022-11-28",
        attribution_fidelity="H",
        ttps_required=(
            "T1566.001",
            "T1204.002",
            "T1059.003",  # cmd.exe
            "T1071.001",
            "T1573.002",
            "T1219",      # Remote Access Software (BackConnect VNC)
        ),
        ttps_optional=(
            "T1055",
            "T1090",
            "T1041",
        ),
        attribution_required=("T1566.001", "T1219", "T1071.001"),
        accepted_alternates=_alternates("T1566.001", "T1204.002", "T1059.003", "T1071.001", "T1573.002"),
        narrative_facts=(
            "Qakbot delivery chain followed by Cobalt Strike beacon and BackConnect VNC.",
            "VNC traffic is non-TLS and gives clear payload visibility for family attribution.",
        ),
    ),
    # 7 — 2022-11-07 Emotet (epoch4) + IcedID + BumbleBee  (H)
    CatalogueEntry(
        incident_id="mta-2022-11-07-emotet-icedid-bumblebee",
        url="https://www.malware-traffic-analysis.net/2022/11/07/index.html",
        family="Emotet (epoch4) + IcedID + BumbleBee",
        date="2022-11-07",
        attribution_fidelity="H",
        ttps_required=(
            "T1566.001",
            "T1204.002",
            "T1059.001",
            "T1071.001",
            "T1573.002",
            "T1055",
        ),
        ttps_optional=(
            "T1027",
            "T1218",
            "T1041",
        ),
        attribution_required=("T1566.001", "T1059.001", "T1071.001"),
        accepted_alternates=_alternates("T1566.001", "T1204.002", "T1059.001", "T1071.001", "T1573.002"),
        narrative_facts=(
            "Triple-loader chain — Emotet drops IcedID drops BumbleBee — gives three distinguishable family fingerprints in one incident.",
            "Strong multi-TTP attribution case across the kill chain.",
        ),
    ),
    # 8 — 2022-12-07 BumbleBee + Cobalt Strike  (M)
    CatalogueEntry(
        incident_id="mta-2022-12-07-bumblebee-cs",
        url="https://www.malware-traffic-analysis.net/2022/12/07/index.html",
        family="BumbleBee + Cobalt Strike",
        date="2022-12-07",
        attribution_fidelity="M",
        ttps_required=(
            "T1566.001",
            "T1204.002",
            "T1071.001",
            "T1573.002",
        ),
        ttps_optional=(
            "T1059.001",
            "T1055",
            "T1090",
        ),
        attribution_required=("T1071.001", "T1573.002"),
        accepted_alternates=_alternates("T1566.001", "T1204.002", "T1071.001", "T1573.002"),
        narrative_facts=(
            "BumbleBee has a distinctive JA3 fingerprint but C2 is mostly TLS-bound.",
            "Cobalt Strike beacon timing is characteristic and is the primary attribution anchor here.",
        ),
    ),
    # 9 — 2021-01-13 Emotet epoch2 + TrickBot  (H)
    CatalogueEntry(
        incident_id="mta-2021-01-13-emotet-trickbot",
        url="https://www.malware-traffic-analysis.net/2021/01/13/index.html",
        family="Emotet epoch2 + TrickBot",
        date="2021-01-13",
        attribution_fidelity="H",
        ttps_required=(
            "T1566.001",
            "T1204.002",
            "T1059.001",
            "T1071.001",
            "T1055",
        ),
        ttps_optional=(
            "T1027",
            "T1041",
        ),
        attribution_required=("T1566.001", "T1059.001", "T1071.001"),
        accepted_alternates=_alternates("T1566.001", "T1204.002", "T1059.001", "T1071.001"),
        narrative_facts=(
            "Pre-takedown Emotet era — more cleartext C2 visibility than the post-2021 reincarnation.",
            "Both Emotet and TrickBot are heavily reverse-engineered families with documented signatures.",
        ),
    ),
    # 10 — 2021-09-24 SquirrelWaffle + Qakbot + Cobalt Strike  (M)
    CatalogueEntry(
        incident_id="mta-2021-09-24-squirrelwaffle-qakbot-cs",
        url="https://www.malware-traffic-analysis.net/2021/09/24/index.html",
        family="SquirrelWaffle + Qakbot + Cobalt Strike",
        date="2021-09-24",
        attribution_fidelity="M",
        ttps_required=(
            "T1566.001",
            "T1204.002",
            "T1059.001",
            "T1071.001",
            "T1573.002",
        ),
        ttps_optional=(
            "T1055",
            "T1090",
        ),
        attribution_required=("T1566.001", "T1071.001"),
        accepted_alternates=_alternates("T1566.001", "T1204.002", "T1059.001", "T1071.001", "T1573.002"),
        narrative_facts=(
            "SquirrelWaffle was a short-lived loader — useful family-diversity anchor for the classifier.",
            "Attribution depth is limited by the family's short documented lifespan.",
        ),
    ),
    # 11 — 2021-12-16 Hancitor + Cobalt Strike  (H)
    CatalogueEntry(
        incident_id="mta-2021-12-16-hancitor-cs",
        url="https://www.malware-traffic-analysis.net/2021/12/16/index.html",
        family="Hancitor + Cobalt Strike",
        date="2021-12-16",
        attribution_fidelity="H",
        ttps_required=(
            "T1566.001",
            "T1204.002",
            "T1059.001",
            "T1071.001",
            "T1573.002",
        ),
        ttps_optional=(
            "T1055",
            "T1090",
            "T1041",
        ),
        attribution_required=("T1566.001", "T1071.001", "T1573.002"),
        accepted_alternates=_alternates("T1566.001", "T1204.002", "T1059.001", "T1071.001", "T1573.002"),
        narrative_facts=(
            "Hancitor has a distinctive URL and C2 URI pattern that is a textbook attribution case.",
            "Chained to a Cobalt Strike beacon, this is a high-fidelity RQ3 discrimination case.",
        ),
    ),
    # 12 — 2019-08-01 Lord Exploit Kit  (H)
    CatalogueEntry(
        incident_id="mta-2019-08-01-lord-ek",
        url="https://www.malware-traffic-analysis.net/2019/08/01/index.html",
        family="Lord Exploit Kit",
        date="2019-08-01",
        attribution_fidelity="H",
        ttps_required=(
            "T1189",      # Drive-by Compromise
            "T1203",      # Exploitation for Client Execution
            "T1071.001",
        ),
        ttps_optional=(
            "T1055",
            "T1027",
        ),
        attribution_required=("T1189", "T1203"),
        accepted_alternates=_alternates("T1071.001"),
        narrative_facts=(
            "Pre-2020 exploit-kit era with mostly-cleartext HTTP delivery.",
            "EK URL patterns are heavily documented and the primary attribution anchor.",
        ),
    ),
    # 13 — 2019-03-16 Spelevo EK  (H)
    CatalogueEntry(
        incident_id="mta-2019-03-16-spelevo-ek",
        url="https://www.malware-traffic-analysis.net/2019/03/16/index.html",
        family="Spelevo EK",
        date="2019-03-16",
        attribution_fidelity="H",
        ttps_required=(
            "T1189",
            "T1203",
            "T1071.001",
        ),
        ttps_optional=(
            "T1055",
            "T1027",
        ),
        attribution_required=("T1189", "T1203"),
        accepted_alternates=_alternates("T1071.001"),
        narrative_facts=(
            "EK era with cleartext HTTP delivery chain.",
            "Spelevo had a distinctive landing-page URI pattern.",
        ),
    ),
    # 14 — 2017-12-27 Emotet + Zeus Panda Banker  (H)
    CatalogueEntry(
        incident_id="mta-2017-12-27-emotet-zeuspanda",
        url="https://www.malware-traffic-analysis.net/2017/12/27/index.html",
        family="Emotet + Zeus Panda Banker",
        date="2017-12-27",
        attribution_fidelity="H",
        ttps_required=(
            "T1566.001",
            "T1204.002",
            "T1059.001",
            "T1071.001",
            "T1185",      # Browser Session Hijacking (banking trojan webinject)
        ),
        ttps_optional=(
            "T1055",
            "T1027",
        ),
        attribution_required=("T1566.001", "T1185"),
        accepted_alternates=_alternates("T1566.001", "T1204.002", "T1059.001", "T1071.001"),
        narrative_facts=(
            "Banking-trojan era with cleartext C2 visibility.",
            "Zeus Panda webinjects produce a distinctive HTTP pattern that is the primary attribution anchor.",
        ),
    ),
    # 15 — 2017-08-02 Magnitude EK + Cerber ransomware  (H)
    CatalogueEntry(
        incident_id="mta-2017-08-02-magnitude-cerber",
        url="https://www.malware-traffic-analysis.net/2017/08/02/index.html",
        family="Magnitude EK + Cerber ransomware",
        date="2017-08-02",
        attribution_fidelity="H",
        ttps_required=(
            "T1189",
            "T1203",
            "T1486",      # Data Encrypted for Impact
            "T1071.001",
        ),
        ttps_optional=(
            "T1027",
            "T1041",
        ),
        attribution_required=("T1189", "T1486"),
        accepted_alternates=_alternates("T1071.001"),
        narrative_facts=(
            "Ransomware-delivery-via-EK chain with cleartext HTTP visibility.",
            "Cerber encryption activity is the impact-stage anchor; Magnitude is the delivery anchor.",
        ),
    ),
    # 16 — 2026-01-29 njRAT + MassLogger  (H)
    CatalogueEntry(
        incident_id="mta-2026-01-29-njrat-masslogger",
        url="https://www.malware-traffic-analysis.net/2026/01/29/index.html",
        family="njRAT + MassLogger",
        date="2026-01-29",
        attribution_fidelity="H",
        ttps_required=(
            "T1566.001",
            "T1204.002",
            "T1219",      # Remote Access Software (njRAT)
            "T1071.001",
            "T1048.003",  # Exfiltration Over Unencrypted Non-C2 Protocol (MassLogger SMTP)
        ),
        ttps_optional=(
            "T1555",
            "T1056.001",  # Input Capture: Keylogging (MassLogger)
        ),
        attribution_required=("T1219", "T1048.003"),
        accepted_alternates=_alternates("T1566.001", "T1204.002", "T1071.001", "T1048.003", "T1056.001"),
        narrative_facts=(
            "njRAT uses non-TLS C2 and is straightforward to fingerprint on the wire.",
            "MassLogger exfiltrates over SMTP in cleartext — strong attribution anchor.",
        ),
    ),
)


# Sanity-check the catalogue at import time. This is a development-time
# guard, not a runtime gate.
assert len(CATALOGUE) == 16, f"catalogue must have exactly 16 entries (have {len(CATALOGUE)})"
_fidelity_counts: dict[str, int] = {"H": 0, "M": 0, "L": 0}
for _e in CATALOGUE:
    _fidelity_counts[_e.attribution_fidelity] += 1
assert _fidelity_counts == {"H": 11, "M": 4, "L": 1}, (
    f"attribution-fidelity distribution must be 11H/4M/1L (have {_fidelity_counts})"
)
_ids = [e.incident_id for e in CATALOGUE]
assert len(set(_ids)) == len(_ids), "duplicate incident_id in catalogue"


def get(incident_id: str) -> CatalogueEntry:
    """Look up a catalogue entry by id. Raises KeyError if absent."""
    for entry in CATALOGUE:
        if entry.incident_id == incident_id:
            return entry
    raise KeyError(f"unknown incident_id: {incident_id!r}")


def ids() -> list[str]:
    """Return all catalogue incident ids, in catalogue order."""
    return [e.incident_id for e in CATALOGUE]
