"""Query clauses shared by every tool that filters Elasticsearch on a host name.

One definition, because the same filter used to be written five times and two
of the copies were wrong in opposite directions:

* a bare ``match`` on the text-mapped ``Computer`` analyzes the FQDN into
  ``wkst 13 corp.example.invalid`` OR'd together, and every host in the domain
  shares the last token -- a host-scoped search came back as the entire index
  (issue #46: 2,637,278 hits where the host has 109,094);
* a bare ``term`` on ``Computer.keyword`` is exact on the stored FQDN, so a
  short name (``wkst-13``, which is what the slice resolver returns for a host
  it learned from ``ecar-edr``) matches NOTHING, and a worker reads nothing as
  "this host is clean".

The host-name fields in this corpus (``Computer`` on the Windows indices,
``host`` / ``hostname`` on linux-syslog, ``host_name`` on zeek-dhcp,
``hostname`` on ecar-edr) are all dynamically mapped: ``text`` with a
``.keyword`` subfield. Every clause here names the ``.keyword`` subfield and
nothing analyzed, so what a filter matches is decided by string equality on the
stored value and never by the standard analyzer. That rules out the last
over-match ``match_phrase`` still had: a bare shared token such as ``wkst``
is a whole phrase and matched 800,384 Sysmon documents (every workstation);
``prefix "wkst."`` matches none, because no stored value starts with it.
"""
from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from typing import Any


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def host_name_clauses(host: str, field: str) -> list[dict[str, Any]]:
    """The ``should`` clauses that match ``host`` against one text-with-keyword field.

    The stored value may be the FQDN (Sysmon's ``Computer``, most of
    windows-security) or the bare label (linux-syslog's ``host`` for the Linux
    servers: 48,429 records as ``srv-app-01`` against 41 as
    ``srv-app-01.corp.example.invalid``), and the caller may hold either
    spelling. Both directions are covered without inventing a domain:

    * the value as given, exact;
    * given an FQDN, its first label, exact -- the record that stores only the
      short name. This is a lookup of the label the caller wrote, not a guess
      at a domain, and it is safe because short labels are unique across the
      corpus's domains (the invariant ``host_resolve.short_name`` rests on);
    * given a short label, ``prefix`` on ``<label>.`` -- the record that
      stores it qualified. The trailing dot is what makes it exact on the
      label: ``wkst-1.`` is not a prefix of ``wkst-13.corp.example.invalid``.

    Case-insensitive on every clause: the analyzed ``match`` these replace
    folded case, and a model that writes ``WKST-13`` should not get an empty
    result for it.
    """
    h = host.strip().rstrip(".")
    kw = f"{field}.keyword"
    out: list[dict[str, Any]] = [{"term": {kw: {"value": h, "case_insensitive": True}}}]
    if _is_ip(h):
        # count_by_time takes an address here for the Zeek indices; its first
        # "label" would be an octet, and a should clause can only widen.
        return out
    label = h.split(".")[0]
    if label != h:
        out.append({"term": {kw: {"value": label, "case_insensitive": True}}})
    else:
        out.append({"prefix": {kw: {"value": f"{h}.", "case_insensitive": True}}})
    return out


def host_name_clause(
    host: str, *fields: str, extra: Iterable[dict[str, Any]] = ()
) -> dict[str, Any]:
    """One ``bool`` filter matching ``host`` on any of ``fields``.

    ``extra`` is for clauses on fields that are not host names but name the
    same host another way -- ``count_by_time`` adds the Zeek address fields so
    one call surveys a host across a comma-list of indices.
    """
    should = [c for f in fields for c in host_name_clauses(host, f)]
    should.extend(extra)
    return {"bool": {"should": should, "minimum_should_match": 1}}


def host_ip_clauses(ip: str) -> list[dict[str, Any]]:
    """The ``should`` clauses that match an address at either end of a record.

    Zeek and OT conn logs map ``id.orig_h`` / ``id.resp_h`` as ``ip``; Zeek,
    OT and Suricata also carry ``src_ip`` / ``dest_ip`` as text with a keyword
    subfield. A non-address never reaches the ``ip``-typed fields: a term
    query there with a hostname is a 400, not an empty result.
    """
    a = ip.strip()
    out: list[dict[str, Any]] = [{"term": {f"{f}.keyword": a}} for f in ("src_ip", "dest_ip")]
    if _is_ip(a):
        out = [{"term": {"id.orig_h": a}}, {"term": {"id.resp_h": a}}, *out]
    return out
