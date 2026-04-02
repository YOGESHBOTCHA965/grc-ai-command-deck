"""Phase 1: Fetch NIST controls and generate synthetic CloudTrail logs."""

from __future__ import annotations

import argparse
from pathlib import Path

from grc_ai_pipeline import (
    DEFAULT_NIST_JSON_URL,
    fetch_nist_controls,
    generate_synthetic_cloudtrail_logs,
    save_controls,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Phase 1 - Data Engineering")
    parser.add_argument("--nist-source-url", default=DEFAULT_NIST_JSON_URL)
    parser.add_argument("--logs-count", type=int, default=1000)
    parser.add_argument("--output-dir", type=Path, default=Path("outputs_phase1"))
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)

    controls_df = fetch_nist_controls(args.nist_source_url)
    controls_json = args.output_dir / "nist_controls_rev5.json"
    controls_csv = args.output_dir / "nist_controls_rev5.csv"
    save_controls(controls_df, controls_json, controls_csv)

    logs_df = generate_synthetic_cloudtrail_logs(n_logs=args.logs_count)
    logs_csv = args.output_dir / "synthetic_cloudtrail_logs.csv"
    logs_df.to_csv(logs_csv, index=False)

    print("Phase 1 complete:")
    print(f"- Controls JSON: {controls_json}")
    print(f"- Controls CSV:  {controls_csv}")
    print(f"- Logs CSV:      {logs_csv}")


if __name__ == "__main__":
    main()
