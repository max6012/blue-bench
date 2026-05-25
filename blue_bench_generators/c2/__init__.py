"""Synthetic C2 traffic generator.

Emits synthetic Zeek + Suricata events representing two distinct profiles of
command-and-control traffic, paired with ground-truth annotations conforming
to ``docs/internal/heavy-telemetry/ground-truth-schema.md`` v1.0:

    commodity  --  loud, recognizable, high beacon rate, known-bad indicator
                   patterns, large POST payloads, recognizable C2-framework
                   fingerprints (Cobalt Strike defaults, IcedID HTTP, BumbleBee,
                   Lumma TLS, Hancitor stage). RQ3 cybercrime-foil side.
    stealth    --  low-and-slow, jitter in hours, small payloads, DNS or HTTPS
                   tunneling to legitimate-looking infrastructure, domain
                   fronting, typo-squat shapes. RQ2 APT-LotL side.

Distinct from ``cybercrime_foil``: that module replays real MTA PCAPs;
``c2`` synthesises events directly for cases where real PCAPs aren't available
or aren't licensable, and for the APT signal where Atomic Red Team / Caldera
don't naturally produce on-the-wire C2.

Pipeline shape::

    profiles  --->  beacon  --->  zeek_emit       -\\
                                                    |--->  bundle
                                  suricata_emit   -/

Components:
    profiles        -- profile dataclasses + preset library (5 commodity + 4 stealth)
    beacon          -- deterministic beacon-event stream generator
    zeek_emit       -- profile-appropriate Zeek TSV record emission
    suricata_emit   -- profile-appropriate Suricata eve.json record emission
    bundle          -- NDJSON + ground-truth YAML emitter (schema-validated)

License / safety:
    * No real malicious payload bytes are emitted; payloads are random-data
      with the right SIZE distribution. Marked as such in code.
    * Default callback hosts use TEST-NET-3 (203.0.113.0/24) and
      ``.example.invalid`` domains. Users may override.
"""

from blue_bench_generators.c2.profiles import (
    COMMODITY_PRESETS,
    STEALTH_PRESETS,
    C2Profile,
    CommodityProfile,
    StealthProfile,
    get_preset,
    preset_names,
)

__all__ = [
    "C2Profile",
    "CommodityProfile",
    "StealthProfile",
    "COMMODITY_PRESETS",
    "STEALTH_PRESETS",
    "get_preset",
    "preset_names",
]
