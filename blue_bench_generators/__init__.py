"""Blue-Bench generator suite.

Generators produce capability-discriminating telemetry corpora and ground-truth
bundles for the heavy-telemetry benchmark substrate. Each sub-module owns one
source-stack ingestion or one synthesis path.

Sub-modules:
    cybercrime_foil  — MTA PCAP → Zeek/Suricata → time/IP-rewritten bundle
                       conforming to docs/internal/heavy-telemetry/
                       ground-truth-schema.md v1.0.

License posture: this package contains tracked code only. Raw upstream data
(PCAPs, AIT logs, indicators-repo content) is fetched into ``data/raw/`` which
is gitignored repo-wide. Refer to ``docs/internal/heavy-telemetry/
decision-source-stack.md`` for per-source license handling.
"""

__all__ = ["cybercrime_foil"]
