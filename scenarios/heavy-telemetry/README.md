# Heavy-telemetry baseline scenarios

The benign IT baseline for Blue-Bench's S/M/L corpus tiers, written for
[EvidenceForge](https://github.com/Cisco-Talos/EvidenceForge). Each file
describes an enterprise environment — workstations, a domain controller, a
Windows file server, Linux app and database servers — and the ordinary workday
traffic that runs across it. No attack content lives here.

These scenarios are the **source**. The telemetry they produce is a build
product: `eforge generate` turns a scenario into the same bytes every run, so
the corpus is rebuilt on demand rather than stored in git. A full corpus adds
OT telemetry and an injected adversary on top of this baseline; the benign
substrate is the haystack a model works through while hunting the injected
signal.

## Tiers

| File | Hosts × users × window | Generated size | Use |
|---|---|---|---|
| `bb-benign-s.yaml` | 10 × 8 × 1 day | ~165 MB | CI smoke, 4B-class runs |
| `bb-benign-m.yaml` | 15 × 12 × 3 days | ~660 MB | 70B-class benchmark |
| `bb-benign-l.yaml` | 30 × 24 × 18 days | ~7–8 GB | stress floor (≥5 GB) |

Output scales at roughly 15 MB per host-day, near-linear across the range.
Generation runs about 8 seconds per host-day (S ≈ 90 s, L ≈ 70 min).

## Generating a tier

```bash
eforge validate scenarios/heavy-telemetry/bb-benign-s.yaml
eforge generate scenarios/heavy-telemetry/bb-benign-s.yaml -o ./out/s
# then ingest into Elasticsearch for the MCP tools:
python scripts/ingest_ef.py --ef-dir ./out/s --anchor-end-to-now
```

Output is byte-identical across runs for the same scenario, so two people
generating the same tier get the same corpus, and `build_hash` confirms it.

## Conventions

Hostnames are short (`wkst-01`, `dc-01`, `srv-files-01`) with the AD domain in
`environment.domain` (`corp.example.invalid`); the full FQDN appears in the
generated logs (e.g. `wkst-01.corp.example.invalid`). Usernames are bare
(`wkst-01-user`, `corp-admin`). Workstations sit in `10.10.0.0/16`, servers in
`10.20.0.0/16`.
