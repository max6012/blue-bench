"""Credential-abuse injection generators.

Unlike ``apt_inject`` (which stitches real sandbox kill-chain captures) these
six adversaries are **synthetic** auth/host telemetry — brute force, password
spraying, dormant service-account misuse, pass-the-hash, impossible travel, and
a noisy commodity infection. They exercise the credential-abuse and alert-triage
tradecraft that the host-side Sysmon/Zeek adversaries don't.

``python -m blue_bench_generators.cred_inject build`` writes each bundle to
``data/bundles/<subdir>/<incident_id>.{events.ndjson,ground-truth.yaml}`` — the
same on-disk contract the merge/inject pipeline consumes (and the same one the
hand-authored bundles used). Generation is deterministic: the emitted telemetry
is a fixed function of the builders, so a rebuild reproduces byte-stable bundles.

Every event is authored with the shared capture identity
(``WS-FIN-014`` / ``ws-fin-014.corp.example`` / ``10.10.4.37``); the injector
remaps it onto the real target host and ``leak_check`` aborts if it survives.
External attacker IPs are synthetic (RFC 5737 documentation ranges:
``198.51.100.42`` brute-force source, ``203.0.113.200`` C2 / download cradle)
and are preserved through remap as signal. Until 2026-09-10 two of them were
REAL allocated addresses -- ``185.220.101.42`` (RIPE: TOR-EXIT, DE) and
``45.61.136.200`` (ARIN: BL Networks) -- so this invariant was asserted and
violated, in a public repo, and ``p3-10``'s answer key rewarded naming the Tor
exit as attacker infrastructure.

Two attacker sources are deliberately RFC 1918 rather than RFC 5737, because
they model an already-compromised INTERNAL host rather than an external
attacker: ``10.10.0.199`` (password spray against dc-01) and ``10.10.0.88``
(initial access). Both sit outside the range the scenarios allocate to real
hosts (``10.10.0.11``-``10.10.0.31``), so they cannot be confused with a
legitimate endpoint.
"""
from __future__ import annotations

from blue_bench_generators.cred_inject.events import BUILDERS

__all__ = ["BUILDERS"]
