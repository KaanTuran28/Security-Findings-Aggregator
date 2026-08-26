#!/usr/bin/env python3
"""Aggregates JSON findings from multiple security-scanner reports into one dashboard.

Ingests the `--format json` output of any tool that follows a simple,
tool-agnostic contract: a JSON list of finding objects, or a JSON object with
a "findings" list — where each finding has at least a "severity" key
(HIGH/MEDIUM/LOW, case-insensitive). This happens to be the exact shape every
other scanner in this portfolio already emits, so their reports can be fed in
directly with no adapter code — but nothing here imports or depends on any
other project; it's a generic, standalone consumer of that shape.
"""

import argparse
import json
import sys
from pathlib import Path

VALID_SEVERITIES = ("HIGH", "MEDIUM", "LOW")
SEVERITY_WEIGHTS = {"HIGH": 10, "MEDIUM": 5, "LOW": 1, "UNKNOWN": 2}
SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "UNKNOWN": 3}


def load_report(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, list):
        raw_findings = data
        label = None
    elif isinstance(data, dict):
        raw_findings = data.get("findings", [])
        label = data.get("source") or data.get("domain") or data.get("file") or data.get("url")
    else:
        raw_findings, label = [], None

    findings = []
    for item in raw_findings:
        if not isinstance(item, dict):
            continue
        severity = str(item.get("severity", "UNKNOWN")).upper()
        if severity not in VALID_SEVERITIES:
            severity = "UNKNOWN"
        findings.append({**item, "severity": severity})

    return {"source": label or path.name, "path": str(path), "findings": findings}


def aggregate(reports: list) -> dict:
    per_source = []
    all_findings = []

    for report in reports:
        counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        for finding in report["findings"]:
            counts[finding["severity"]] += 1
            all_findings.append({**finding, "report_source": report["source"]})

        risk_score = sum(SEVERITY_WEIGHTS[sev] * count for sev, count in counts.items())
        per_source.append({
            "source": report["source"],
            "path": report["path"],
            "counts": counts,
            "finding_count": sum(counts.values()),
            "risk_score": risk_score,
        })

    per_source.sort(key=lambda s: s["risk_score"], reverse=True)

    total_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for finding in all_findings:
        total_counts[finding["severity"]] += 1
    total_risk_score = sum(SEVERITY_WEIGHTS[sev] * count for sev, count in total_counts.items())

    return {
        "sources": per_source,
        "total_counts": total_counts,
        "total_risk_score": total_risk_score,
        "findings": all_findings,
    }


def build_report(aggregated: dict) -> str:
    counts = aggregated["total_counts"]
    lines = [
        "# Security Findings Dashboard",
        "",
        f"- **Sources aggregated:** {len(aggregated['sources'])}",
        "- **Total findings:** {} ({} HIGH, {} MEDIUM, {} LOW, {} UNKNOWN)".format(
            sum(counts.values()), counts["HIGH"], counts["MEDIUM"], counts["LOW"], counts["UNKNOWN"]
        ),
        f"- **Total risk score:** {aggregated['total_risk_score']}",
        "",
        "## By Source (highest risk first)",
        "",
        "| Source | Findings | HIGH | MEDIUM | LOW | Risk Score |",
        "|---|---|---|---|---|---|",
    ]
    for s in aggregated["sources"]:
        c = s["counts"]
        lines.append(
            f"| {s['source']} | {s['finding_count']} | {c['HIGH']} | {c['MEDIUM']} | {c['LOW']} | {s['risk_score']} |"
        )

    lines += ["", "## All Findings", ""]
    if aggregated["findings"]:
        lines += ["| Severity | Source | Summary |", "|---|---|---|"]
        ordered = sorted(aggregated["findings"], key=lambda f: SEVERITY_ORDER[f["severity"]])
        for f in ordered:
            summary = str(
                f.get("reason") or f.get("summary") or f.get("detail") or f.get("check") or "(no description)"
            ).replace("|", "\\|")
            lines.append(f"| {f['severity']} | {f['report_source']} | {summary} |")
    else:
        lines.append("No findings in any source.")
    lines.append("")
    return "\n".join(lines)


def build_json_report(aggregated: dict) -> str:
    return json.dumps(aggregated, indent=2, ensure_ascii=False) + "\n"


def main():
    parser = argparse.ArgumentParser(
        description="Aggregate JSON findings from multiple security-scanner reports into one dashboard."
    )
    parser.add_argument("--inputs", nargs="+", help="Paths to one or more tool JSON report files.")
    parser.add_argument(
        "--input-dir", help="Directory to glob for *.json report files (used instead of --inputs)."
    )
    parser.add_argument("--output", default="sample_report.md", help="Path to write the dashboard.")
    parser.add_argument(
        "--format", choices=["markdown", "json"], default="markdown", help="Output report format."
    )
    parser.add_argument(
        "--fail-on",
        choices=["none", "medium", "high"],
        default="none",
        help="Exit with code 1 if the combined findings include one at/above this severity (for CI gating).",
    )
    args = parser.parse_args()

    if args.input_dir:
        paths = sorted(Path(args.input_dir).glob("*.json"))
    elif args.inputs:
        paths = [Path(p) for p in args.inputs]
    else:
        parser.error("provide --inputs <file...> or --input-dir <dir>")

    if not paths:
        print("No input JSON reports found.", file=sys.stderr)
        return 2

    reports = [load_report(p) for p in paths]
    aggregated = aggregate(reports)
    report = build_json_report(aggregated) if args.format == "json" else build_report(aggregated)

    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write(report)

    counts = aggregated["total_counts"]
    print(
        f"Aggregated {len(paths)} report(s): {counts['HIGH']} HIGH, {counts['MEDIUM']} MEDIUM, "
        f"{counts['LOW']} LOW (risk score {aggregated['total_risk_score']})."
    )
    print(f"Report written to {args.output}")

    if args.fail_on == "high" and counts["HIGH"] > 0:
        return 1
    if args.fail_on == "medium" and (counts["HIGH"] > 0 or counts["MEDIUM"] > 0):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
