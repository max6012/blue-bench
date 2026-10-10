# Blue-Bench corpus generators

Builds the tiered telemetry corpus: benign IT baseline, OT traffic, IT/OT
bridge, and injected adversary activity with ground-truth answer keys.

## Layout

| Directory | Contents |
| --- | --- |
| `merge/` | Build orchestrator (`build`), injector, RQ3 gates, coherence checks |
| `it_baseline/` | Topology and Suricata-noise code used by `merge`; standalone `build` CLI not used by `merge build` |
| `ot_hosts/`, `ot_protocols/` | OT hosts; Modbus, S7comm, DNP3, IEC-104 traffic |
| `it_ot_bridge/` | IT↔OT crossing traffic |
| `apt_inject/` | APT bundle from sandbox kill-chain captures |
| `cybercrime_foil/` | Cybercrime bundles from public PCAPs via Zeek and Suricata |
| `cred_inject/` | Credential-abuse and commodity bundles |
| `c2/` | Synthetic C2 beacon generator |

Scenario YAMLs: `scenarios/heavy-telemetry/`. Adversary bundles: `data/bundles/`.

## Install

Requires Python >= 3.11 (EvidenceForge), git, and ~24 GB free disk for L.
Elasticsearch 8.x is needed for ingest (`docker/compose.tools.yml`).

```bash
python3.11 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

git clone https://github.com/Cisco-Talos/EvidenceForge ~/EvidenceForge
python3.11 -m venv ~/ef-venv
~/ef-venv/bin/pip install -e ~/EvidenceForge
~/ef-venv/bin/eforge --help
```

## Configure

- `export TZ=UTC` before building.
- EvidenceForge path: `--eforge` (default `~/ef-venv/bin/eforge`).
- Elasticsearch: `--es-url` on `ingest_ef.py` (default `http://localhost:9200`).

## Build

```bash
# Full corpus
python -m blue_bench_generators.merge build --tier L --out ./out/l

# Smoke test
python -m blue_bench_generators.merge build --tier S --out ./out/s
```

| Flag | Meaning |
| --- | --- |
| `--tier S\|M\|L` | Required |
| `--out DIR` | Required |
| `--seed N` | Default 0 |
| `--scenario FILE` | Default `scenarios/heavy-telemetry/bb-benign-<tier>.yaml` |
| `--ef-dir DIR` | Use an existing EvidenceForge output instead of running `eforge` |
| `--eforge PATH` | Path to `eforge` |
| `--inject INCIDENT:SUBDIR:HOST` | Replace default adversaries; repeatable |
| `--no-enforce-gates` | Report RQ3 gate results without failing |

| Tier | Use | Baseline | Size | EvidenceForge time | Default adversaries |
| --- | --- | --- | --- | --- | --- |
| L | Full corpus | 30 hosts × 18 days | ~24 GB | ~70 min | APT on wkst-03, foil on wkst-07, 5 credential/commodity attacks |
| M | Mid-size | 15 hosts × 3 days | — | — | cybercrime foil on wkst-03 |
| S | Smoke test | 10 hosts × 1 day | ~290 MB | ~90 s | cybercrime foil on wkst-03 |

### Output

- Per-host EvidenceForge data plus OT and bridge telemetry under `<out>/`
- `corpus-manifest.yaml`: tier, seed, `build_hash`, injected incidents, RQ3 gate verdicts
- `<out>/ground-truth/`: one answer key per injected incident

### RQ3 gates

Run when both the APT and cybercrime incidents are present. A failure aborts
the build. Verdicts are in `corpus-manifest.yaml` under `rq3_gates`.
Code: `merge/gates.py`.

## Load into Elasticsearch

```bash
docker compose -f docker/compose.tools.yml up -d elasticsearch
python scripts/ingest_ef.py --ef-dir ./out/l --anchor-end-to-now
```

Flags: `--es-url`, `--anchor-end-to-now`, `--ot-sample-rate`, `-v`.

## Adversary bundles

`merge build` reads `<incident>.events.ndjson` and `<incident>.ground-truth.yaml`
pairs from `data/bundles/<subdir>/`.

| Subdir | Incident | Tiers | Regenerate |
| --- | --- | --- | --- |
| `cybercrime_foil` | `cybercrime-bb-001` | S, M, L | — |
| `apt_inject` | `apt-bb-001` | L | `python -m blue_bench_generators.apt_inject build` (needs `data/raw/sandbox/` captures) |
| `cred_bruteforce`, `cred_spray`, `cred_dormant`, `cred_pth`, `cred_travel`, `commodity` | credential / commodity | L | `python -m blue_bench_generators.cred_inject build` |

## Tests

```bash
pytest tests/test_build_corpus.py tests/test_merger.py tests/test_inject.py tests/test_cred_inject.py
```

## Troubleshooting

| Message | Fix |
| --- | --- |
| `ABORT: ... clock` | `export TZ=UTC` |
| `ABORT: eforge not found` | Install EvidenceForge or pass `--eforge` |
| `ABORT: target host ... not in scenario` | Use a host from that tier's scenario in `--inject` |
| `RQ3 gates failed` | See `rq3_gates` in the manifest |
