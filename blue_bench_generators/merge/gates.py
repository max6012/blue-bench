"""RQ3 anti-giveaway gates (EF-P5 / t-ll52).

APT-vs-cybercrime discrimination is only a real test if the two classes are
non-separable on SURFACE and separable on BEHAVIOUR. These four gates, run on
the labeled APT-injection vs cybercrime-foil event sets, decide corpus validity:

  1. Surface non-separability  — a classifier on per-event SURFACE features
     (dest port, proto/service, process image, byte buckets, event kind; NO
     time, NO host identity) scores AUC <= 0.65 (near chance). If a cheap
     surface classifier separates the classes, the foil is a giveaway.
  2. Behavioural separability  — a classifier on per-event TEMPORAL features
     (inter-event gap on the same host, dwell position) scores AUC >= 0.85.
     Proves the discriminating signal genuinely lives in the behavioural channel.
  3. Volume parity             — per tier, |apt| vs |foil| event counts within 2x.
  4. Matched surface tells     — the classes overlap on dest-port set (Jaccard)
     and both exhibit periodic external (C2-style) egress, so "it's on port X"
     or "it beacons" cannot by itself classify.

SPEC DEVIATION (flag to Max): the t-9pwe spec lists "per-host event-type
histograms" as a gate-1 surface feature. With one host per class (APT->wkst-03,
foil->wkst-04) any per-host aggregate IS the class label (AUC 1.0, tautological),
so it is excluded here; gate-1 uses per-event intrinsic features only. Per-host
histograms remain a valid malicious-vs-benign feature, just not for this
pairwise apt-vs-cybercrime test.

The classifier is a pure-Python logistic regression with a single seeded
train/test split and a rank-based (Mann-Whitney) AUC — deterministic, no numpy.
A per-feature univariate-AUC diagnostic NAMES the most class-correlated surface
feature so a failing gate 1 points at the leak instead of inviting a threshold bump.
"""

from __future__ import annotations

import json
import math
import random
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

# --- thresholds (starting points; tune the BEHAVIOURAL side, not gate 1) ---
SURFACE_AUC_MAX = 0.65
BEHAVIORAL_AUC_MIN = 0.85
VOLUME_RATIO_MAX = 2.0
PORT_JACCARD_MIN = 0.5
SPLIT_SEED = 1729

_UTCTIME_FMT = "%Y-%m-%d %H:%M:%S.%f"


# --- event time (same derivation rebase_campaign uses) ---

def _event_time(ev: dict) -> float | None:
    if ev.get("UtcTime"):
        try:
            return datetime.strptime(str(ev["UtcTime"]), _UTCTIME_FMT).replace(
                tzinfo=timezone.utc).timestamp()
        except ValueError:
            return None
    ts = ev.get("ts")
    if ts not in (None, ""):
        try:
            return float(ts)
        except (TypeError, ValueError):
            return None
    return None


def _host(ev: dict) -> str:
    return str(ev.get("Computer") or ev.get("id.orig_h") or ev.get("src_ip") or "")


def _is_external(ip: str) -> bool:
    return bool(ip) and not ip.startswith(("10.", "192.168.", "172.16.", "127."))


# --- per-event SURFACE features (intrinsic; no host identity, no time) ---

def _byte_bucket(v) -> int:
    try:
        n = int(v)
    except (TypeError, ValueError):
        return 0
    return int(math.log10(n + 1))


def surface_features(ev: dict) -> dict[str, float]:
    stream = ev.get("_stream")
    feats: dict[str, float] = {"is_network": 1.0 if stream == "zeek" else 0.0}
    # network 5-tuple-ish (port/proto/service) — dest IP intentionally omitted
    # except an "external dest" flag (class-shared C2 infra, kept honestly).
    dport = ev.get("id.resp_p") or ev.get("DestinationPort")
    try:
        feats["dest_port"] = float(dport) if dport not in (None, "") else 0.0
    except (TypeError, ValueError):
        feats["dest_port"] = 0.0
    for proto in ("tcp", "udp", "icmp"):
        feats[f"proto_{proto}"] = 1.0 if str(ev.get("proto", "")).lower() == proto else 0.0
    for svc in ("http", "ssl", "dns"):
        feats[f"svc_{svc}"] = 1.0 if str(ev.get("service", "")).lower() == svc else 0.0
    feats["dest_external"] = 1.0 if _is_external(str(ev.get("id.resp_h", ""))) else 0.0
    feats["orig_bytes_b"] = float(_byte_bucket(ev.get("orig_bytes")))
    feats["resp_bytes_b"] = float(_byte_bucket(ev.get("resp_bytes")))
    # host telemetry: event kind + process image (basename), no host/user/guid
    try:
        feats["sysmon_eid"] = float(ev.get("event_id") or 0)
    except (TypeError, ValueError):
        feats["sysmon_eid"] = 0.0
    image = str(ev.get("Image", "")).replace("\\", "/").rsplit("/", 1)[-1].lower()
    for proc in ("powershell.exe", "cmd.exe", "mshta.exe", "rundll32.exe",
                 "makecab.exe", "net.exe", "reg.exe", "systeminfo.exe", "whoami.exe"):
        feats[f"img_{proc}"] = 1.0 if image == proc else 0.0
    return feats


# --- per-event BEHAVIOURAL features (temporal context) ---

def behavioral_features(events: list[dict]) -> list[dict[str, float]]:
    """Per-event temporal features. Inter-event gap is computed within each
    host (host is the grouping key, not a feature) — the gap VALUE is the
    cadence signal that distinguishes low-and-slow from smash-and-grab."""
    times = [(_event_time(e), e) for e in events]
    valid = [(t, e) for t, e in times if t is not None]
    if not valid:
        return [{"gap_log": 0.0, "dwell_frac": 0.0} for _ in events]
    t0 = min(t for t, _ in valid)
    t1 = max(t for t, _ in valid)
    span = (t1 - t0) or 1.0
    # previous-event time per host
    by_host: dict[str, list[float]] = {}
    for t, e in valid:
        by_host.setdefault(_host(e), []).append(t)
    for h in by_host:
        by_host[h].sort()
    out: list[dict[str, float]] = []
    win = 300.0  # +/- 5 min local-density window
    for e in events:
        t = _event_time(e)
        if t is None:
            out.append({"gap_log": 0.0, "dwell_frac": 0.0, "local_density": 0.0, "iso_score": 0.0})
            continue
        seq = by_host.get(_host(e), [])
        prev = [x for x in seq if x < t]
        nxt = [x for x in seq if x > t]
        gap = (t - prev[-1]) if prev else span  # first event on host -> full span
        # local_density: same-host events within +/-win (burst vs sparse context).
        # Non-degenerate: varies per event within a campaign (a between-stage
        # isolated event scores low even in a dense foil; a within-burst APT
        # event scores high), so it is not a campaign-constant class one-hot.
        dens = sum(1 for x in seq if abs(x - t) <= win)
        # isolation: min gap to nearest neighbour either side (log). Low-and-slow
        # events sit alone; smash-and-grab events have a close neighbour.
        nbr = min([gap] + ([nxt[0] - t] if nxt else []))
        out.append({
            "gap_log": math.log10(max(gap, 1.0)),       # cadence to previous event
            "dwell_frac": (t - t0) / span,               # position within the window
            "local_density": math.log10(dens + 1),       # burst vs sparse neighbourhood
            "iso_score": math.log10(max(nbr, 1.0)),      # isolation from nearest neighbour
        })
    return out


# --- pure-Python logistic regression + Mann-Whitney AUC ---

def _standardize(rows: list[list[float]]) -> list[list[float]]:
    if not rows:
        return rows
    n, d = len(rows), len(rows[0])
    means = [sum(r[j] for r in rows) / n for j in range(d)]
    sds = []
    for j in range(d):
        var = sum((r[j] - means[j]) ** 2 for r in rows) / n
        sds.append(math.sqrt(var) or 1.0)
    return [[(r[j] - means[j]) / sds[j] for j in range(d)] for r in rows]


def _train_logreg(X: list[list[float]], y: list[int], iters: int = 400, lr: float = 0.1) -> list[float]:
    n, d = len(X), len(X[0])
    w = [0.0] * (d + 1)  # +1 bias
    for _ in range(iters):
        grad = [0.0] * (d + 1)
        for i in range(n):
            z = w[0] + sum(w[j + 1] * X[i][j] for j in range(d))
            p = 1.0 / (1.0 + math.exp(-max(-60.0, min(60.0, z))))
            err = p - y[i]
            grad[0] += err
            for j in range(d):
                grad[j + 1] += err * X[i][j]
        w[0] -= lr * grad[0] / n
        for j in range(d):
            w[j + 1] -= lr * grad[j + 1] / n
    return w


def _score(w: list[float], x: list[float]) -> float:
    return w[0] + sum(w[j + 1] * x[j] for j in range(len(x)))


def auc(scores: list[float], labels: list[int]) -> float:
    """Rank-based AUC (Mann-Whitney U), tie-safe via average ranks."""
    pos = sum(labels)
    neg = len(labels) - pos
    if pos == 0 or neg == 0:
        return 0.5
    order = sorted(range(len(scores)), key=lambda i: scores[i])
    ranks = [0.0] * len(scores)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and scores[order[j + 1]] == scores[order[i]]:
            j += 1
        avg = (i + j) / 2.0 + 1.0  # 1-based average rank
        for k in range(i, j + 1):
            ranks[order[k]] = avg
        i = j + 1
    sum_pos = sum(ranks[i] for i in range(len(labels)) if labels[i] == 1)
    return (sum_pos - pos * (pos + 1) / 2.0) / (pos * neg)


def _classifier_auc(feat_rows: list[dict[str, float]], labels: list[int], seed: int) -> float:
    keys = sorted({k for r in feat_rows for k in r})
    X = [[r.get(k, 0.0) for k in keys] for r in feat_rows]
    X = _standardize(X)
    idx = list(range(len(X)))
    random.Random(seed).shuffle(idx)
    cut = int(len(idx) * 0.7)
    tr, te = idx[:cut], idx[cut:]
    if not te or len(set(labels[i] for i in tr)) < 2:
        return 0.5
    w = _train_logreg([X[i] for i in tr], [labels[i] for i in tr])
    return auc([_score(w, X[i]) for i in te], [labels[i] for i in te])


def feature_diagnostic(feat_rows: list[dict[str, float]], labels: list[int]) -> list[tuple[str, float]]:
    """Univariate AUC per surface feature, ranked by |AUC-0.5| — names the leak."""
    keys = sorted({k for r in feat_rows for k in r})
    out = []
    for k in keys:
        col = [r.get(k, 0.0) for r in feat_rows]
        out.append((k, auc(col, labels)))
    return sorted(out, key=lambda kv: abs(kv[1] - 0.5), reverse=True)


# --- gates ---

@dataclass
class GateResult:
    name: str
    passed: bool
    value: float
    threshold: float
    detail: str = ""


@dataclass
class GateReport:
    results: list[GateResult] = field(default_factory=list)
    diagnostic: list[tuple[str, float]] = field(default_factory=list)

    @property
    def all_passed(self) -> bool:
        return all(r.passed for r in self.results)


def _dest_ports(events: list[dict]) -> set[int]:
    out = set()
    for e in events:
        p = e.get("id.resp_p") or e.get("DestinationPort")
        try:
            if p not in (None, ""):
                out.add(int(p))
        except (TypeError, ValueError):
            pass
    return out


def _has_periodic_egress(events: list[dict], min_hits: int = 3) -> bool:
    """True if some external dest:port is contacted >= min_hits times (beacon-like)."""
    counts: dict[tuple[str, str], int] = {}
    for e in events:
        if e.get("_stream") != "zeek":
            continue
        dst = str(e.get("id.resp_h", ""))
        if _is_external(dst):
            key = (dst, str(e.get("id.resp_p", "")))
            counts[key] = counts.get(key, 0) + 1
    return any(c >= min_hits for c in counts.values())


def run_gates(apt_events: list[dict], foil_events: list[dict], *, seed: int = SPLIT_SEED) -> GateReport:
    events = apt_events + foil_events
    labels = [1] * len(apt_events) + [0] * len(foil_events)  # apt = positive class

    surf = [surface_features(e) for e in events]
    behav = behavioral_features(apt_events) + behavioral_features(foil_events)

    surf_auc = _classifier_auc(surf, labels, seed)
    behav_auc = _classifier_auc(behav, labels, seed)
    ratio = (max(len(apt_events), len(foil_events)) /
             max(1, min(len(apt_events), len(foil_events))))
    pj_a, pj_f = _dest_ports(apt_events), _dest_ports(foil_events)
    jacc = (len(pj_a & pj_f) / len(pj_a | pj_f)) if (pj_a | pj_f) else 1.0
    periodic = _has_periodic_egress(apt_events) and _has_periodic_egress(foil_events)

    report = GateReport(diagnostic=feature_diagnostic(surf, labels))
    report.results = [
        GateResult("surface_non_separability", surf_auc <= SURFACE_AUC_MAX, surf_auc, SURFACE_AUC_MAX,
                   "surface-only classifier AUC (near-chance is good)"),
        GateResult("behavioral_separability", behav_auc >= BEHAVIORAL_AUC_MIN, behav_auc, BEHAVIORAL_AUC_MIN,
                   "temporal classifier AUC (high is good)"),
        GateResult("volume_parity", ratio <= VOLUME_RATIO_MAX, ratio, VOLUME_RATIO_MAX,
                   f"|apt|={len(apt_events)} |foil|={len(foil_events)} ratio (<=2x)"),
        GateResult("matched_surface_tells", jacc >= PORT_JACCARD_MIN and periodic, jacc, PORT_JACCARD_MIN,
                   f"dest-port Jaccard={jacc:.2f}; periodic egress both classes={periodic}"),
    ]
    return report


def _load(path: Path) -> list[dict]:
    return [json.loads(l) for l in Path(path).read_text().splitlines() if l.strip()]


def main(argv: list[str] | None = None) -> int:
    import argparse
    p = argparse.ArgumentParser(prog="blue_bench_generators.merge.gates",
                                description="Run the 4 RQ3 anti-giveaway gates on labeled event sets.")
    p.add_argument("--apt", required=True, help="APT bundle events.ndjson")
    p.add_argument("--foil", required=True, help="cybercrime foil bundle events.ndjson")
    p.add_argument("--seed", type=int, default=SPLIT_SEED)
    args = p.parse_args(argv)

    rep = run_gates(_load(Path(args.apt)), _load(Path(args.foil)), seed=args.seed)
    print("RQ3 anti-giveaway gates")
    for r in rep.results:
        mark = "PASS" if r.passed else "FAIL"
        print(f"  [{mark}] {r.name:26s} value={r.value:.3f} threshold={r.threshold} — {r.detail}")
    print("\ntop surface-feature class correlations (univariate AUC, |AUC-0.5| desc):")
    for k, a in rep.diagnostic[:6]:
        print(f"    {k:20s} AUC={a:.3f}")
    print(f"\nVERDICT: {'ALL GATES PASS' if rep.all_passed else 'GATES FAILED — investigate (do not bump thresholds for gate 1)'}")
    return 0 if rep.all_passed else 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
