"""Phase 4+5: Reporting with SBERT mappings and HITL workflow."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd

from grc_ai_pipeline import (
    DEFAULT_NIST_JSON_URL,
    fetch_nist_controls,
    generate_markdown_report,
    map_logs_to_controls,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Phase 4+5 - Reporting + HITL")
    parser.add_argument("--anomaly-csv", type=Path, required=True)
    parser.add_argument("--report-md", type=Path, default=Path("outputs_phase4/compliance_drift_report.md"))
    parser.add_argument("--mapping-json", type=Path, default=Path("outputs_phase4/sbert_mapping_results.json"))
    parser.add_argument("--nist-source-url", default=DEFAULT_NIST_JSON_URL)
    parser.add_argument("--similarity-threshold", type=float, default=0.7)
    parser.add_argument("--interactive-hitl", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    anomaly_df = pd.read_csv(args.anomaly_csv)
    flagged_df = anomaly_df[anomaly_df["DriftFlag"] == "Potential Compliance Drift"].reset_index(drop=True)

    controls_df = fetch_nist_controls(args.nist_source_url)
    mappings = map_logs_to_controls(
        logs_df=flagged_df,
        controls_df=controls_df,
        similarity_threshold=args.similarity_threshold,
        interactive_hitl=args.interactive_hitl,
    )

    args.mapping_json.parent.mkdir(parents=True, exist_ok=True)
    args.mapping_json.write_text(json.dumps(mappings, indent=2), encoding="utf-8")

    report_text = generate_markdown_report(flagged_df, mappings, args.report_md)

    print("Phase 4+5 complete:")
    print(f"- Mapping JSON: {args.mapping_json}")
    print(f"- Markdown report: {args.report_md}")
    print(f"- Report length: {len(report_text.splitlines())} lines")


if __name__ == "__main__":
    main()
