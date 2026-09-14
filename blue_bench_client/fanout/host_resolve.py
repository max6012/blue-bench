"""Hostname <-> IP resolution for slice scoping, answered from the live corpus.

A slice carries ``hosts`` (FQDNs) and ``host_ips`` separately, and the two
halves bind to different tools: the host-telemetry tools filter on the computer
name, the network tools filter on the address. A slice that names only a
hostname therefore leaves every network tool unbound, and one that names only
an address leaves every host tool unbound -- silently. Rather than make the
lead spend turns discovering the mapping, the HARNESS completes the missing
half here, from the corpus itself, and records which values it added so the
judge scores the lead on the plan it wrote and not on the harness's filling-in.

Sources, in authority order -- the first that answers wins:

* ``ot-assets`` -- the OT asset inventory. Authoritative for the plant segment
  and consulted first: it is a declared name<->address mapping rather than an
  inference from traffic, and it covers the embedded devices (controllers,
  RTUs) that emit no host telemetry at all. It holds only OT records, so an IT
  host simply does not match and the traffic-derived sources below still
  answer. It carries no ``@timestamp`` (an inventory is a standing fact, not an
  observation), so its queries -- alone among these -- do not take the slice
  window; applying one would match nothing and silently fall through to the
  guesswork sources.
* ``zeek-dhcp`` -- the lease record. Authoritative for anything that takes a
  lease, which in this corpus means the workstations (``host_name`` short,
  ``domain`` alongside it, so an FQDN is derivable).
* ``windows-sysmon`` EventID 3 (network connection) -- ``Computer`` is already
  an FQDN and ``SourceIp`` is the connecting host's own address. Covers the
  statically-addressed Windows servers that never appear in DHCP.
* ``ecar-edr`` OUTBOUND FLOW records -- ``hostname`` (short) with
  ``properties.src_ip``. The only source that covers the Linux servers
  (``srv-app-*``, ``srv-db-*``); they are in neither DHCP nor Sysmon. It
  carries no domain.

A short name from a source that carries no domain is qualified by a second,
name-keyed lookup: if the same label is stored as an FQDN in ``zeek-dhcp``
(``host_name`` + ``domain``) or in Sysmon's ``Computer``, that FQDN is
returned. That is a lookup of a recorded fact, not a guess -- the resolver
never assembles a domain by majority vote. Only when no source knows the
FQDN does the short name come back, and it is then listed under
``short_only`` in the resolution and in the slice's provenance record, so
scoring can see that the host tools were bound to a label rather than to the
FQDN they store. (The host tools' own filter accepts either spelling, so the
label still binds; the record is there so nobody has to trust that.)

``ot-hosts`` is deliberately NOT a source. Its ``source_ip`` is the peer that
connected, not the subject host's address: ``ews-01.plant.example.invalid``'s
top ``source_ip`` is ``10.30.0.10``, which Sysmon independently identifies as
``jump-ot-01``. Binding a slice from it would scope the network tools to a
dozen addresses that are not the host. That used to mean the OT hosts
(``*.plant.example.invalid``) did not resolve at all; ``ot-assets`` is what
closes it, and on a corpus built before the inventory existed the old gap is
still the behaviour -- the index is simply absent and every OT name falls
through unresolved.

Every query is a terms aggregation, not a document fetch: the answer is the set
of distinct values, and an aggregation gets it in one round trip regardless of
how many million records back it. ``host_name`` / ``Computer`` / ``hostname``
are text-mapped with a ``.keyword`` subfield, so every filter and every
aggregation here names the ``.keyword`` field -- a bare ``match`` on the text
field OR-matches the shared FQDN tokens and pulls in every host in the domain
(issue #46).
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any

import httpx

ASSETS_INDEX = "ot-assets"
DHCP_INDEX = "zeek-dhcp"
SYSMON_INDEX = "windows-sysmon"
EDR_INDEX = "ecar-edr"

# Addresses a lease record can carry that are not a host address.
_NOT_AN_ADDRESS = {"", "-", "0.0.0.0", "::"}

# Aggregation width. A host with more distinct addresses than this over one
# slice window is not a host, it is a NAT egress; the cap keeps a bad name from
# binding a slice to a hundred values.
_MAX_VALUES = 20


@dataclass
class Resolution:
    """One answer plus where it came from.

    ``source`` is the index that answered, or ``""`` when nothing did -- the
    record on the slice needs to say which, because "the DHCP lease says so"
    and "no source in the corpus knows" are different facts for the judge.

    ``short_only`` lists the host names in ``values`` that no source could
    qualify: the answering source carries no domain and neither DHCP nor
    Sysmon stores the label as an FQDN. Empty for the IP direction.
    """
    values: list[str] = field(default_factory=list)
    source: str = ""
    short_only: list[str] = field(default_factory=list)

    def __bool__(self) -> bool:
        return bool(self.values)


def short_name(host: str) -> str:
    """The label before the first dot, lowercased.

    Used both to query (the DHCP and EDR records carry the short name, Sysmon
    the FQDN, so every query asks for both spellings) and to key the cache, so
    ``wkst-03`` and ``wkst-03.corp.example.invalid`` resolve once rather than
    twice. That key assumes short names are unique across the corpus's domains,
    which holds here: the corp hosts and the plant hosts share no labels.
    """
    return host.strip().rstrip(".").split(".")[0].lower()


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    return True


def _name_spellings(host: str) -> list[str]:
    """Both spellings of ``host`` for a terms filter: the short label and, when
    the caller gave one, the FQDN as written."""
    h = host.strip().rstrip(".")
    out = [short_name(h)]
    if "." in h and h.lower() not in out:
        out.append(h.lower())
        out.append(h)  # the corpus stores FQDNs as written; do not assume case
    return list(dict.fromkeys(out))


def _buckets(agg: dict[str, Any], name: str) -> list[dict[str, Any]]:
    return agg.get("aggregations", {}).get(name, {}).get("buckets", []) or []


class HostResolver:
    """Answers hostname -> IP and IP -> hostname off the live corpus, once.

    The cache is keyed on (question, window): the same host asked for twice in
    one run costs one round trip, and two slices with different time bands do
    not share an answer -- an address can change over the corpus's 18 days, and
    a slice must be scoped to what was true inside its own band.
    """

    def __init__(
        self,
        es_url: str,
        *,
        verify_ssl: bool = False,
        user: str = "",
        password: str = "",
        timeout: int = 30,
        dhcp_index: str = DHCP_INDEX,
        sysmon_index: str = SYSMON_INDEX,
        edr_index: str = EDR_INDEX,
        assets_index: str = ASSETS_INDEX,
    ) -> None:
        self.url = es_url.rstrip("/")
        self.verify_ssl = verify_ssl
        self.user = user
        self.password = password
        self.timeout = timeout
        self.dhcp_index = dhcp_index
        self.sysmon_index = sysmon_index
        self.edr_index = edr_index
        self.assets_index = assets_index
        self._cache: dict[tuple[str, str, str, str], Resolution] = {}

    @classmethod
    def from_config(cls, cfg: Any) -> "HostResolver":
        """Build from a :class:`blue_bench_mcp.config.ServerConfig`.

        Takes the object rather than importing the config module, so this
        module stays importable (and testable) without the server package. The
        fields read are the ones the tool classes read: ``cfg.elastic.url``,
        its credentials, and the query timeout.
        """
        return cls(
            cfg.elastic.url,
            verify_ssl=cfg.elastic.verify_ssl,
            user=cfg.elastic.user,
            password=cfg.elastic.password,
            timeout=cfg.limits.query_timeout,
            sysmon_index=cfg.sysmon.index,
            assets_index=getattr(cfg.elastic, "asset_index", ASSETS_INDEX),
        )

    # --- ES ------------------------------------------------------------------

    def _auth(self) -> tuple[str, str] | None:
        return (self.user, self.password) if self.user and self.password else None

    async def _agg(self, index: str, body: dict) -> dict:
        """One aggregation round trip.

        ``ignore_unavailable`` / ``allow_no_indices`` for the same reason the
        tool classes set them: a deployment without ``ecar-edr`` should fall
        through to the next source, not 404 the whole resolution. Tests stub
        this method, which is why the HTTP is in one place.
        """
        url = f"{self.url}/{index}/_search?ignore_unavailable=true&allow_no_indices=true"
        async with httpx.AsyncClient(
            verify=self.verify_ssl, auth=self._auth(), timeout=float(self.timeout)
        ) as client:
            resp = await client.post(url, json=body)
            resp.raise_for_status()
            return resp.json()

    def _window(self, since: str, until: str) -> list[dict]:
        """The slice's own band as a ``@timestamp`` filter, or nothing.

        An unbounded resolution would answer with an address the host held
        outside the slice, which is exactly the mis-scoping the band exists to
        prevent.
        """
        bounds: dict[str, str] = {}
        if since:
            bounds["gte"] = since
        if until:
            bounds["lte"] = until
        return [{"range": {"@timestamp": bounds}}] if bounds else []

    async def _terms(
        self, index: str, must: list[dict], field_name: str, *, size: int = _MAX_VALUES
    ) -> list[str]:
        body = {
            "size": 0,
            "query": {"bool": {"must": must}},
            "aggs": {"values": {"terms": {"field": field_name, "size": size}}},
        }
        try:
            data = await self._agg(index, body)
        except httpx.HTTPError:
            # A source that cannot be reached is a source that does not answer;
            # the next one still might. Inventing nothing is the contract.
            return []
        return [str(b["key"]) for b in _buckets(data, "values")]

    # --- host -> ip ----------------------------------------------------------

    async def resolve_ips(
        self, fqdn_or_short: str, *, since: str = "", until: str = ""
    ) -> Resolution:
        """:meth:`ips_for_host` with the answering index attached."""
        key = ("ips", short_name(fqdn_or_short), since, until)
        if key in self._cache:
            return self._cache[key]
        res = await self._lookup_ips(fqdn_or_short, since, until)
        self._cache[key] = res
        return res

    async def ips_for_host(
        self, fqdn_or_short: str, *, since: str = "", until: str = ""
    ) -> list[str]:
        """Every address the host held inside the window, most-seen first.

        Empty when no source knows the host -- the harness does not invent an
        address, and an unknown host is not an error: a lead may legitimately
        name a host that has no network telemetry at all.
        """
        return (await self.resolve_ips(fqdn_or_short, since=since, until=until)).values

    async def _lookup_ips(self, host: str, since: str, until: str) -> Resolution:
        names = _name_spellings(host)
        window = self._window(since, until)

        # The OT asset inventory: a declared mapping, so it outranks everything
        # below, which infers the mapping from traffic. No window clause -- the
        # records carry no @timestamp (see the module docstring).
        must = [{"bool": {"should": [
            {"terms": {"name.keyword": names}},
            {"terms": {"fqdn.keyword": names}},
        ], "minimum_should_match": 1}}]
        vals = [v for v in await self._terms(self.assets_index, must, "ip.keyword")
                if v not in _NOT_AN_ADDRESS]
        if vals:
            return Resolution(vals, self.assets_index)

        # DHCP: the lease record. assigned_addr is what the server handed out;
        # client_addr is what the client asked to keep. Both are the host's.
        for field_name in ("assigned_addr.keyword", "client_addr.keyword"):
            must = [{"terms": {"host_name.keyword": names}}, *window]
            vals = [v for v in await self._terms(self.dhcp_index, must, field_name)
                    if v not in _NOT_AN_ADDRESS]
            if vals:
                return Resolution(vals, self.dhcp_index)

        # Sysmon EventID 3: SourceIp on a network-connection record is the
        # reporting host's own address.
        must = [
            {"term": {"EventID": 3}},
            {"terms": {"Computer.keyword": names}},
            *window,
        ]
        vals = [v for v in await self._terms(self.sysmon_index, must, "SourceIp.keyword")
                if v not in _NOT_AN_ADDRESS]
        if vals:
            return Resolution(vals, self.sysmon_index)

        # EDR: OUTBOUND flow, so src_ip is the agent's host. The direction
        # filter is load-bearing -- an INBOUND record's src_ip is the peer.
        must = [
            {"term": {"object.keyword": "FLOW"}},
            {"term": {"properties.direction.keyword": "OUTBOUND"}},
            {"terms": {"hostname.keyword": names}},
            *window,
        ]
        vals = [v for v in await self._terms(self.edr_index, must, "properties.src_ip.keyword")
                if v not in _NOT_AN_ADDRESS]
        if vals:
            return Resolution(vals, self.edr_index)

        return Resolution([], "")

    # --- ip -> host ----------------------------------------------------------

    async def resolve_hosts(
        self, ip: str, *, since: str = "", until: str = ""
    ) -> Resolution:
        """:meth:`hosts_for_ip` with the answering index attached."""
        key = ("hosts", ip.strip(), since, until)
        if key in self._cache:
            return self._cache[key]
        res = await self._lookup_hosts(ip.strip(), since, until)
        self._cache[key] = res
        return res

    async def hosts_for_ip(
        self, ip: str, *, since: str = "", until: str = ""
    ) -> list[str]:
        """Every host that held the address inside the window.

        FQDNs where any source knows the domain (DHCP carries ``domain``,
        Sysmon's ``Computer`` is already qualified, and a label the EDR
        records name is looked up in both); the short name only where none
        does -- guessing a domain by majority vote across the corpus would be
        a fabricated fact in a scoping filter. :meth:`resolve_hosts` says
        which names stayed short.
        """
        return (await self.resolve_hosts(ip, since=since, until=until)).values

    async def _fqdn_for_label(self, label: str) -> str:
        """The FQDN some source stores for a short label, or ``""``.

        Asked without the slice window, deliberately: the window scopes
        ADDRESSES, which a host can change inside the corpus, but the domain a
        host belongs to is a standing fact like the asset inventory. A
        windowed lookup would drop to the short name whenever the host's
        DHCP or Sysmon records happen to fall outside the band, and the answer
        would then depend on the band rather than on the corpus.

        DHCP first (the lease names the domain outright), then Sysmon, where
        the label is matched as ``prefix`` on ``Computer.keyword`` with the
        trailing dot -- exact on the label, never on a token the analyzer
        made, so ``wkst-1.`` cannot pick up ``wkst-13``.
        """
        body = {
            "size": 0,
            "query": {"bool": {"must": [{"term": {"host_name.keyword": label}}]}},
            "aggs": {"values": {
                "terms": {"field": "host_name.keyword", "size": 1},
                "aggs": {"domain": {"terms": {"field": "domain.keyword", "size": 1}}},
            }},
        }
        try:
            data = await self._agg(self.dhcp_index, body)
        except httpx.HTTPError:
            data = {}
        for b in _buckets(data, "values"):
            doms = b.get("domain", {}).get("buckets", []) or []
            if doms:
                return f"{b['key']}.{doms[0]['key']}"

        must = [{"prefix": {"Computer.keyword": {"value": f"{label}.", "case_insensitive": True}}}]
        vals = await self._terms(self.sysmon_index, must, "Computer.keyword", size=1)
        return vals[0] if vals else ""

    async def _qualified(self, names: list[str], source: str) -> Resolution:
        """A :class:`Resolution` whose short names are qualified where a
        source knows the FQDN, and listed as ``short_only`` where none does."""
        out: list[str] = []
        short_only: list[str] = []
        for name in names:
            if "." in name:
                out.append(name)
                continue
            fqdn = await self._fqdn_for_label(name)
            if fqdn:
                out.append(fqdn)
            else:
                out.append(name)
                short_only.append(name)
        return Resolution(list(dict.fromkeys(out)), source, short_only)

    async def _lookup_hosts(self, ip: str, since: str, until: str) -> Resolution:
        window = self._window(since, until)

        # Asset inventory first, same reasoning and same no-window rule as the
        # host -> ip direction. Answers with the FQDN, which is what the host
        # tools filter on.
        vals = await self._terms(
            self.assets_index, [{"term": {"ip.keyword": ip}}], "fqdn.keyword")
        if vals:
            return Resolution(vals, self.assets_index)

        # DHCP, with the domain pulled alongside each name so the answer can be
        # qualified in the same round trip.
        body = {
            "size": 0,
            "query": {"bool": {"must": [
                {"bool": {"should": [
                    {"term": {"assigned_addr.keyword": ip}},
                    {"term": {"client_addr.keyword": ip}},
                ], "minimum_should_match": 1}},
                *window,
            ]}},
            "aggs": {"values": {
                "terms": {"field": "host_name.keyword", "size": _MAX_VALUES},
                "aggs": {"domain": {"terms": {"field": "domain.keyword", "size": 1}}},
            }},
        }
        try:
            data = await self._agg(self.dhcp_index, body)
        except httpx.HTTPError:
            data = {}
        names = []
        for b in _buckets(data, "values"):
            name = str(b["key"])
            doms = b.get("domain", {}).get("buckets", []) or []
            names.append(f"{name}.{doms[0]['key']}" if doms and "." not in name else name)
        if names:
            return await self._qualified(names, self.dhcp_index)

        must = [{"term": {"EventID": 3}}, {"term": {"SourceIp.keyword": ip}}, *window]
        vals = await self._terms(self.sysmon_index, must, "Computer.keyword")
        if vals:
            return Resolution(vals, self.sysmon_index)

        must = [
            {"term": {"object.keyword": "FLOW"}},
            {"term": {"properties.direction.keyword": "OUTBOUND"}},
            {"term": {"properties.src_ip.keyword": ip}},
            *window,
        ]
        vals = await self._terms(self.edr_index, must, "hostname.keyword")
        if vals:
            # EDR carries no domain: qualify each label from the sources that
            # do, and say which ones stayed short.
            return await self._qualified(vals, self.edr_index)

        return Resolution([], "")


def _iso(dt: Any) -> str:
    return dt.isoformat().replace("+00:00", "Z") if dt is not None else ""


async def complete_slice_scope(slice: Any, resolver: HostResolver | None) -> tuple[Any, dict]:
    """Fill a slice's missing scope half and say what was filled.

    Returns a COPY of the slice (the caller's object is not mutated -- the
    lead's plan is what the judge reads, and it must stay as written) plus the
    provenance record, which is also stored on the copy as ``slice.resolved``.

    Both directions are computed off the ORIGINAL lists and merged once. Doing
    them in sequence would resolve hostnames back out of the addresses the
    first pass had just added, which grows the scope with values the lead never
    named and no source directly supports.

    The record lives on ``Slice`` rather than inside ``SliceFilters`` because
    ``fanout_bind`` binds from ``filters``: every field there is a scoping
    dimension, and ``SliceFilters.is_empty()`` and the multi-value binding
    rules both walk that model. A provenance dict there would be a non-filter
    in a filter bag. On ``Slice`` it is inert to the binder and still rides to
    the server in the serialized slice, so the dispatcher gets it for free; it
    is also returned so a caller can log it without re-reading the slice.
    """
    f = slice.filters
    since, until = _iso(f.time_start), _iso(f.time_end)
    supplied_hosts = list(f.hosts)
    supplied_ips = list(f.host_ips)
    sources: dict[str, str] = {}
    unresolved: list[str] = []
    short_only: list[str] = []

    new_ips: list[str] = []
    new_hosts: list[str] = []
    if resolver is not None:
        for host in supplied_hosts:
            res = await resolver.resolve_ips(host, since=since, until=until)
            if res:
                sources[host] = res.source
                new_ips += [v for v in res.values if v not in supplied_ips]
            else:
                unresolved.append(host)
        for ip in supplied_ips:
            res = await resolver.resolve_hosts(ip, since=since, until=until)
            if res:
                sources[ip] = res.source
                # Match on the short label: the lead may have written the FQDN
                # where the source knows only the short name (or the reverse),
                # and adding the other spelling of a host it already named
                # would bind the host tools to a name that is not in the index.
                have = {short_name(h) for h in supplied_hosts}
                new_hosts += [v for v in res.values if short_name(v) not in have]
                short_only += [v for v in res.short_only if short_name(v) not in have]
            else:
                unresolved.append(ip)

    hosts = supplied_hosts + list(dict.fromkeys(new_hosts))
    ips = supplied_ips + list(dict.fromkeys(new_ips))
    record = {
        "hosts": {"supplied": supplied_hosts, "resolved": [h for h in hosts if h not in supplied_hosts]},
        "host_ips": {"supplied": supplied_ips, "resolved": [i for i in ips if i not in supplied_ips]},
        "sources": sources,
        "unresolved": unresolved,
        # Hosts added to the slice under a short name because no source knows
        # the FQDN. The host tools accept the label, but a scorer comparing
        # the bound scope against the FQDN-keyed ground truth needs to know.
        "short_only": list(dict.fromkeys(short_only)),
        "window": {"since": since, "until": until},
    }
    completed = slice.model_copy(
        update={
            "filters": f.model_copy(update={"hosts": hosts, "host_ips": ips}, deep=True),
            "resolved": record,
        },
        deep=True,
    )
    return completed, record
