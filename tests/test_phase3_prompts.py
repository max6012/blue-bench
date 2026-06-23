"""Phase-3 (heavy-telemetry RQ) eval prompts load + target the corpus adversary."""
from pathlib import Path
import yaml
from blue_bench_eval.prompts._schema import load_all

PROMPTS = Path(__file__).resolve().parents[1] / "blue_bench_eval" / "prompts"
RUBRIC = Path(__file__).resolve().parents[1] / "blue_bench_eval" / "rubrics" / "phase3.yaml"


def test_phase3_prompts_load_and_validate():
    specs = load_all(PROMPTS, prefix="p3-")
    assert len(specs) >= 4
    cats = {s.category for s in specs}
    # the three RQs are represented
    assert {"apt_detection", "discrimination", "ot_segment"} <= cats
    for s in specs:
        assert s.expected_findings and s.expected_tools


def test_phase3_prompts_target_the_injected_adversary():
    specs = {s.id: s for s in load_all(PROMPTS, prefix="p3-")}
    # RQ2 detection names the APT victim host + uses the Sysmon host tools
    blob = " ".join(syn for f in specs["p3-01"].expected_findings for syn in f.synonyms)
    assert "wkst-03" in blob and "get_process_events" in specs["p3-01"].expected_tools
    # RQ3 discrimination scores behavior over surface
    d = " ".join(syn for f in specs["p3-02"].expected_findings for syn in f.synonyms).lower()
    assert "low-and-slow" in d or "low and slow" in d
    assert "smash-and-grab" in d or "smash and grab" in d


def test_phase3_rubric_has_discrimination_dimension():
    r = yaml.safe_load(RUBRIC.read_text())
    assert r["prompt_prefix"] == "p3-"
    assert "discrimination" in r["dimensions"] and "attribution" in r["dimensions"]
