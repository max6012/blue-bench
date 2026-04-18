from pathlib import Path

from blue_bench_eval.prompts._schema import PromptSpec, load_all, load_prompt

REPO = Path(__file__).parent.parent
PROMPTS_DIR = REPO / "blue_bench_eval" / "prompts"


def test_all_ten_prompts_load():
    specs = load_all(PROMPTS_DIR)
    assert len(specs) == 10
    ids = [s.id for s in specs]
    assert ids == [f"p2-{n:02d}" for n in range(1, 11)]


def test_each_prompt_required_fields():
    for spec in load_all(PROMPTS_DIR):
        assert spec.id.startswith("p2-")
        assert spec.question
        assert spec.expected_tools, f"{spec.id} has no expected_tools"
        assert spec.expected_findings, f"{spec.id} has no expected_findings"
        assert spec.pass_criteria, f"{spec.id} has no pass_criteria"
        for fs in spec.expected_findings:
            assert fs.synonyms, f"{spec.id} has a finding set with empty synonyms"


def test_coverage_of_categories():
    specs = load_all(PROMPTS_DIR)
    categories = {s.category for s in specs}
    # Expected coverage: triage, malware, exfil, lateral, account, detection, recon, correlation, forensic (x2)
    expected = {"triage", "malware", "exfil", "lateral", "account", "detection", "recon", "correlation", "forensic"}
    assert expected.issubset(categories), f"missing categories: {expected - categories}"


def test_g4_known_weakness_prompt_tagged():
    # p2-06 is the DR/Sigma rule prompt that targets G4's Phase 1 regression.
    # It must be tagged so tuning cycles can filter on it.
    specs = {s.id: s for s in load_all(PROMPTS_DIR)}
    p206 = specs["p2-06"]
    assert "g4-known-weakness" in p206.tags
    assert "validate_sigma_rule" in p206.expected_tools


def test_tool_set_size_in_bounds():
    # Scope doc promises 12 tools — sanity-check the port agrees.
    specs = load_all(PROMPTS_DIR)
    all_tools = set()
    for s in specs:
        all_tools.update(s.expected_tools)
    assert 10 <= len(all_tools) <= 14, f"tool set size out of expected bounds: {sorted(all_tools)}"
