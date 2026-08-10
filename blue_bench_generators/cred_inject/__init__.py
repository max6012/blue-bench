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
Attacker/external IPs are synthetic (RFC 5737 / documentation ranges) and are
preserved through remap as signal.
"""
from __future__ import annotations

from blue_bench_generators.cred_inject.events import BUILDERS

__all__ = ["BUILDERS"]
