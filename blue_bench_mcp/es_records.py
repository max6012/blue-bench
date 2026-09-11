"""Turning an ES hit into the record a tool returns.

Shared by every tool that reads Elasticsearch directly (ElasticTool, AuthTool,
the Wazuh ES fallback) so one hit shape cannot drift from another.
"""
from __future__ import annotations


def with_identity(hit: dict) -> dict:
    """``_source`` with the ES ``_id`` and ``_index`` as its first two keys.

    Ground truth is keyed on the ES ``_id`` (``where.doc_id`` in the
    ground-truth YAML), so a worker can only cite evidence the scorer can join
    if the record carries it. First, not last: pretty-printed JSON is cut from
    the tail and the model reads the front of each record.

    ES reserves both names inside ``_source`` (a document carrying them fails
    to index), so a collision means a broken ingest; the metadata wins and the
    ``_source`` copy is dropped rather than shadowing the real identity.
    """
    rec = {"_id": hit.get("_id"), "_index": hit.get("_index")}
    for k, v in (hit.get("_source") or {}).items():
        if k not in rec:
            rec[k] = v
    return rec
