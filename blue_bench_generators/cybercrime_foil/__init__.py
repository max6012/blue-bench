"""Cybercrime-foil splice pipeline.

Takes per-incident PCAPs from the malware-traffic-analysis.net (MTA) catalogue,
runs them through Zeek/Suricata, rewrites timestamps + IPs to land inside a
target corpus epoch, and emits per-incident annotated bundles conforming to
``docs/internal/heavy-telemetry/ground-truth-schema.md`` v1.0.

Pipeline shape::

    catalogue ──► download ──► zeek_replay   ─┐
                          \\─► suricata_replay ├─► rewrite ──► bundle
                                              ─┘

Components:
    catalogue       — 16-entry v1 PCAP shortlist (pure data, dataclasses)
    download        — targeted fetch + password-protected unzip
    zeek_replay     — ``zeek -r`` subprocess + TSV parsers (parsing is pure)
    suricata_replay — ``suricata -r`` subprocess + eve.json reader (pure)
    rewrite         — deterministic time + IP rewrite on parsed events
    bundle          — emit NDJSON + ground-truth YAML; validate against schema

The replay wrappers separate subprocess invocation from parsing so unit tests
can feed fixture log content directly without requiring Zeek/Suricata installed.

License posture: catalogue holds references (URLs) to public MTA writeups; this
package does NOT redistribute PCAP content. Raw PCAPs land under
``data/raw/mta/<incident_id>/`` which is gitignored.
"""

from blue_bench_generators.cybercrime_foil.catalogue import CATALOGUE, CatalogueEntry

__all__ = ["CATALOGUE", "CatalogueEntry"]
