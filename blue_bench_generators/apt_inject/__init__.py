"""APT injection harness — sandbox kill-chain captures → injectable bundle.

The parallel of ``cybercrime_foil`` for sandbox-captured EVTX + Zeek
telemetry (instead of MTA PCAPs). Ingests the per-stage ATT&CK kill-chain
captures produced by ``sandbox/vm/capture-killchain.sh``, stitches them
into a single low-and-slow campaign timeline, rewrites host identity + IPs
to a target corpus host, and emits an annotated bundle conforming to
``docs/internal/heavy-telemetry/ground-truth-schema.md`` v1.0.

Flow::

    data/raw/sandbox/<run>/   ── ingest ──► event dicts (EVTX + Zeek)
    (per kill-chain stage)                       │
                                                 ▼
    killchain-index.tsv ──── schedule ──► LotL campaign timeline
    (stage → run dir)        (dwell in days; sparse C2; lateral across days)
                                                 │
                                                 ▼
                            rewrite ──► host/IP remap + time-shift
                                                 │
                                                 ▼
                            bundle ──► <campaign>.events.ndjson
                                       <campaign>.ground-truth.yaml  (source_class=apt)

Determinism: a given (campaign seed, target host, dwell window, corpus
binding) produces a byte-identical bundle. The campaign seed drives the
stage scheduling jitter and the IP map; re-running rebuilds the same
corpus.

Distinct from ``cybercrime_foil``:
  * input is EVTX (binary, parse via python-evtx) + Zeek TSV, not PCAP;
  * the campaign is STITCHED from 10 separate stage-captures into one
    timeline with realistic dwell, where the foil is a single continuous
    incident;
  * host-rewrite remaps a hostname (Sysmon ``Computer``) in addition to
    IPs (the foil only sees IPs in PCAP).

Reuses ``cybercrime_foil.bundle.validate_bundle`` + ``CorpusBinding`` —
the ground-truth schema and its 11 validation rules are shared.
"""
