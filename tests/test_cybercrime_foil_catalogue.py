"""Catalogue invariants for the cybercrime-foil v1 shortlist.

Pinned by the task description: 16 entries with H/M/L attribution distribution
11/4/1, every entry must carry non-empty TTPs (rule 4 in the schema validator
considers an empty TTP list a malformed bundle).
"""

from __future__ import annotations

import re

import pytest

from blue_bench_generators.cybercrime_foil import catalogue


TTP_REGEX = re.compile(r"^T\d{4}(\.\d{3})?$")


def test_catalogue_size():
    assert len(catalogue.CATALOGUE) == 16


def test_attribution_fidelity_distribution():
    counts = {"H": 0, "M": 0, "L": 0}
    for entry in catalogue.CATALOGUE:
        counts[entry.attribution_fidelity] += 1
    assert counts == {"H": 11, "M": 4, "L": 1}


def test_every_entry_has_non_empty_ttps():
    for entry in catalogue.CATALOGUE:
        assert entry.ttps_required, f"{entry.incident_id} has no required TTPs"
        # all_ttps is the union used by the schema's `ttps` field
        assert entry.all_ttps, f"{entry.incident_id} has empty union of TTPs"


def test_every_ttp_matches_schema_regex():
    for entry in catalogue.CATALOGUE:
        for tid in entry.all_ttps:
            assert TTP_REGEX.match(tid), f"{entry.incident_id}: bad TTP {tid!r}"


def test_attribution_required_subset_of_all_ttps():
    # Schema rule 11: ttp_attribution.required ⊆ ttps. The catalogue is the
    # authoritative pre-author of attribution_required; assert the subset
    # invariant at the catalogue layer so bundle emission inherits it.
    for entry in catalogue.CATALOGUE:
        for tid in entry.attribution_required:
            assert tid in entry.all_ttps, (
                f"{entry.incident_id}: attribution_required {tid!r} not in all_ttps"
            )


def test_incident_ids_unique_and_kebab():
    ids = [e.incident_id for e in catalogue.CATALOGUE]
    assert len(set(ids)) == len(ids), "duplicate incident_id detected"
    for iid in ids:
        assert iid == iid.lower(), f"{iid} not lowercase"
        assert "_" not in iid, f"{iid} uses underscores; convention is kebab-case"


def test_canonical_example_entry_present_and_aligned():
    # The example file (ground-truth-example.yaml) is for entry #5.
    entry = catalogue.get("mta-2022-12-20-icedid-cs")
    assert entry.attribution_fidelity == "H"
    # Sanity-check it carries the TTPs the example file lists in `ttps`.
    expected_subset = {"T1566.001", "T1059.001", "T1071.001", "T1573.002"}
    assert expected_subset.issubset(set(entry.all_ttps))


def test_get_unknown_raises():
    with pytest.raises(KeyError):
        catalogue.get("nope-not-a-thing")


def test_ids_helper_matches_catalogue_order():
    assert catalogue.ids() == [e.incident_id for e in catalogue.CATALOGUE]
