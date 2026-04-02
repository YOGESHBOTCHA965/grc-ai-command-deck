"""Phase 3: Isolation Forest anomaly scoring for compliance drift."""

from __future__ import annotations

import argparse
from pathlib import Path

from grc_ai_pipeline import train_isolation_forest_and_score


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Phase 3 - Isolation Forest")
    parser.add_argument("--input-csv", type=Path, required=True)
    parser.add_argument("--output-csv", type=Path, default=Path("outputs_phase3/anomaly_scored_logs.csv"))
    parser.add_argument("--threshold", type=float, default=-0.5)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    scored_df = train_isolation_forest_and_score(
        input_csv=args.input_csv,
        output_csv=args.output_csv,
        drift_threshold=args.threshold,
    )

    flagged = scored_df[scored_df["DriftFlag"] == "Potential Compliance Drift"]
    print("Phase 3 complete:")
    print(f"- Output CSV: {args.output_csv}")
    print(f"- Total logs: {len(scored_df)}")
    print(f"- Flagged logs: {len(flagged)}")


if __name__ == "__main__":
    main()
