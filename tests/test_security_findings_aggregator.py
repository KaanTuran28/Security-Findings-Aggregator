import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from security_findings_aggregator import (
    aggregate,
    build_json_report,
    build_report,
    load_report,
    main,
)

FIXTURES = Path(__file__).resolve().parent.parent / "sample_reports"


def write_json(tmp_path, name, data):
    path = tmp_path / name
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_load_report_handles_list_at_top_level(tmp_path):
    path = write_json(tmp_path, "list.json", [{"severity": "high"}, {"severity": "LOW"}])
    report = load_report(path)
    assert report["source"] == "list.json"
    assert [f["severity"] for f in report["findings"]] == ["HIGH", "LOW"]


def test_load_report_handles_dict_with_findings_key(tmp_path):
    path = write_json(tmp_path, "dict.json", {"findings": [{"severity": "medium"}]})
    report = load_report(path)
    assert report["findings"][0]["severity"] == "MEDIUM"


def test_load_report_uses_source_label_when_present(tmp_path):
    path = write_json(tmp_path, "labeled.json", {"source": "my-scanner-run", "findings": []})
    report = load_report(path)
    assert report["source"] == "my-scanner-run"


def test_load_report_falls_back_to_domain_then_file_then_filename(tmp_path):
    domain_path = write_json(tmp_path, "d.json", {"domain": "example.com", "findings": []})
    assert load_report(domain_path)["source"] == "example.com"

    file_path = write_json(tmp_path, "f.json", {"file": "some/path.txt", "findings": []})
    assert load_report(file_path)["source"] == "some/path.txt"

    plain_path = write_json(tmp_path, "plain.json", {"findings": []})
    assert load_report(plain_path)["source"] == "plain.json"


def test_load_report_normalizes_unknown_or_missing_severity(tmp_path):
    path = write_json(tmp_path, "weird.json", {"findings": [{"severity": "CRITICAL"}, {"note": "no severity key"}]})
    report = load_report(path)
    assert all(f["severity"] == "UNKNOWN" for f in report["findings"])


def test_load_report_skips_non_dict_finding_entries(tmp_path):
    path = write_json(tmp_path, "malformed.json", {"findings": ["not-a-dict", {"severity": "high"}]})
    report = load_report(path)
    assert len(report["findings"]) == 1
    assert report["findings"][0]["severity"] == "HIGH"


def test_aggregate_counts_and_risk_score():
    reports = [
        {"source": "a", "path": "a.json", "findings": [{"severity": "HIGH"}, {"severity": "LOW"}]},
        {"source": "b", "path": "b.json", "findings": [{"severity": "MEDIUM"}]},
    ]
    aggregated = aggregate(reports)
    assert aggregated["total_counts"] == {"HIGH": 1, "MEDIUM": 1, "LOW": 1, "UNKNOWN": 0}
    # weights: HIGH=10, MEDIUM=5, LOW=1 -> 10 + 5 + 1 = 16
    assert aggregated["total_risk_score"] == 16
    assert len(aggregated["findings"]) == 3


def test_aggregate_sorts_sources_by_risk_score_descending():
    reports = [
        {"source": "low-risk", "path": "l.json", "findings": [{"severity": "LOW"}]},
        {"source": "high-risk", "path": "h.json", "findings": [{"severity": "HIGH"}]},
    ]
    aggregated = aggregate(reports)
    assert [s["source"] for s in aggregated["sources"]] == ["high-risk", "low-risk"]


def test_aggregate_tags_each_finding_with_its_report_source():
    reports = [{"source": "tool-x", "path": "x.json", "findings": [{"severity": "HIGH"}]}]
    aggregated = aggregate(reports)
    assert aggregated["findings"][0]["report_source"] == "tool-x"


def test_aggregate_empty_reports_list_produces_zero_counts():
    aggregated = aggregate([])
    assert aggregated["total_counts"] == {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    assert aggregated["total_risk_score"] == 0
    assert aggregated["findings"] == []


def test_build_report_includes_summary_and_findings_table():
    reports = [{"source": "tool-x", "path": "x.json", "findings": [{"severity": "HIGH", "reason": "bad stuff"}]}]
    report = build_report(aggregate(reports))
    assert "tool-x" in report
    assert "bad stuff" in report
    assert "HIGH" in report


def test_build_report_empty_says_no_findings():
    report = build_report(aggregate([]))
    assert "No findings in any source." in report


def test_json_report_is_valid_and_matches_aggregate():
    reports = [{"source": "tool-x", "path": "x.json", "findings": [{"severity": "HIGH"}]}]
    aggregated = aggregate(reports)
    payload = json.loads(build_json_report(aggregated))
    assert payload["total_counts"]["HIGH"] == 1
    assert payload["total_risk_score"] == aggregated["total_risk_score"]


# ---------------------------------------------------------------------------
# Real fixture files — actual JSON output from sibling tools in this portfolio
# ---------------------------------------------------------------------------

def test_real_fixture_reports_load_and_aggregate_correctly():
    paths = sorted(FIXTURES.glob("*.json"))
    assert len(paths) == 4
    reports = [load_report(p) for p in paths]
    aggregated = aggregate(reports)
    # dockerfile(5H,2M) + cloud_iam(1H) + dns(1H,1L) + jwt(1H) = 8 HIGH, 2 MEDIUM, 1 LOW
    assert aggregated["total_counts"] == {"HIGH": 8, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}


def run_main(monkeypatch, tmp_path, extra_args):
    out = str(tmp_path / "out.md")
    argv = ["security_findings_aggregator.py", "--input-dir", str(FIXTURES), "--output", out] + extra_args
    monkeypatch.setattr(sys, "argv", argv)
    return main()


def test_fail_on_high_exits_nonzero_for_real_fixtures(monkeypatch, tmp_path):
    assert run_main(monkeypatch, tmp_path, ["--fail-on", "high"]) == 1


def test_fail_on_none_always_exits_zero(monkeypatch, tmp_path):
    assert run_main(monkeypatch, tmp_path, []) == 0


def test_main_errors_without_inputs_or_input_dir(monkeypatch, tmp_path):
    out = str(tmp_path / "out.md")
    monkeypatch.setattr(sys, "argv", ["security_findings_aggregator.py", "--output", out])
    try:
        main()
        assert False, "expected SystemExit"
    except SystemExit as exc:
        assert exc.code == 2


def test_main_errors_when_input_dir_has_no_json_files(monkeypatch, tmp_path):
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()
    out = str(tmp_path / "out.md")
    monkeypatch.setattr(sys, "argv", ["security_findings_aggregator.py", "--input-dir", str(empty_dir), "--output", out])
    assert main() == 2
