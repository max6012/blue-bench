"""Canonical Zeek-style UID derivation for the OT protocol generators.

All four per-protocol generators (Modbus, DNP3, IEC-104, S7Comm) share
this helper so UID shape and derivation are a single source of truth.
Previously each protocol used a slightly different ``blake2b`` /
``sha256`` truncation path, all converging to 13-character UIDs but via
inconsistent code -- a refactor hazard.

Shape: ``"C" + 12 hex chars from blake2b(digest_size=6)``, matching the
``C``-prefix convention used by the IT-baseline ``network_zeek``
generator and the existing OT modules.
"""

from __future__ import annotations

import hashlib


def link_uid(seed: int, *parts: object) -> str:
    """Stable 13-character Zeek-style UID for a (seed, *parts) tuple.

    ``parts`` is the per-call key set -- typically (kind, master,
    slave, hour_epoch) for cyclic links, with extra index components
    appended for sub-bucket sequences. All parts are ``str()``-coerced
    and joined by ``|`` for stable serialisation.
    """
    payload = "|".join([str(seed), *(str(p) for p in parts)]).encode()
    return "C" + hashlib.blake2b(payload, digest_size=6).hexdigest()
