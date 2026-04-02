"""Phase 2: Map logs to top-3 NIST controls using SBERT."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd

from grc_ai_pipeline import DEFAULT_NIST_JSON_URL, NISTControlMapper, fetch_nist_controls


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Phase 2 - SBERT mapping")
    parser.add_argument("--log-text", required=True, help="Raw system log string")
    parser.add_argument("--nist-source-url", default=DEFAULT_NIST_JSON_URL)
    parser.add_argument("--output-json", type=Path, default=Path("outputs_phase2/top3_controls.json"))
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    controls_df = fetch_nist_controls(args.nist_source_url)
    mapper = NISTControlMapper(controls_df)
    top3 = mapper.top_k_controls(args.log_text, k=3)

    result = [
        {
            "control_id": m.control_id,
            "title": m.title,
            "description": m.description,
            "similarity": m.similarity,
        }
        for m in top3
    ]

    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(result, indent=2), encoding="utf-8")

    print("Phase 2 complete. Top-3 controls:")
    print(pd.DataFrame(result).to_string(index=False))
    print(f"\nSaved JSON: {args.output_json}")


if __name__ == "__main__":
    main()
