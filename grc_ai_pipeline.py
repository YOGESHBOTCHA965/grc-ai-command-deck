"""End-to-end GRC AI pipeline for NIST 800-53 mapping and compliance drift detection.

Phases covered:
1) Scrape NIST SP 800-53 Rev 5 controls (JSON/CSV).
2) Generate synthetic AWS CloudTrail-style logs.
3) Map logs to NIST controls with SBERT.
4) Train Isolation Forest and flag compliance drift.
5) Human-in-the-loop verification and Markdown reporting.
"""

from __future__ import annotations

import argparse
import io
import json
import random
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional

import numpy as np
import pandas as pd
import requests
from sentence_transformers import SentenceTransformer, util
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

DEFAULT_NIST_JSON_URL = (
    "https://raw.githubusercontent.com/usnistgov/oscal-content/main/"
    "nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
)


@dataclass
class ControlMatch:
    control_id: str
    title: str
    description: str
    similarity: float


class NISTControlMapper:
    """SBERT-based mapper between log text and NIST control descriptions."""

    def __init__(self, controls_df: pd.DataFrame, model_name: str = "all-MiniLM-L6-v2") -> None:
        required = {"control_id", "title", "description"}
        missing = required.difference(controls_df.columns)
        if missing:
            raise ValueError(f"controls_df missing columns: {sorted(missing)}")

        self.controls_df = controls_df.reset_index(drop=True).copy()
        self.model = SentenceTransformer(model_name)
        control_texts = (
            self.controls_df["control_id"].astype(str)
            + " "
            + self.controls_df["title"].astype(str)
            + " "
            + self.controls_df["description"].astype(str)
        ).tolist()
        self.control_embeddings = self.model.encode(control_texts, convert_to_tensor=True)

    def top_k_controls(self, raw_log: str, k: int = 3) -> List[ControlMatch]:
        """Return top-k most relevant controls for a raw log string."""
        if not raw_log or not raw_log.strip():
            return []

        query_embedding = self.model.encode(raw_log, convert_to_tensor=True)
        cosine_scores = util.cos_sim(query_embedding, self.control_embeddings)[0]
        top_k = min(k, len(self.controls_df))
        scores, indices = cosine_scores.topk(top_k)

        matches: List[ControlMatch] = []
        for score, idx in zip(scores.tolist(), indices.tolist()):
            row = self.controls_df.iloc[idx]
            matches.append(
                ControlMatch(
                    control_id=str(row["control_id"]),
                    title=str(row["title"]),
                    description=str(row["description"]),
                    similarity=float(score),
                )
            )
        return matches


def _extract_prose_from_parts(parts: Iterable[Dict]) -> str:
    prose: List[str] = []
    for part in parts or []:
        text = part.get("prose", "")
        if text:
            prose.append(str(text).strip())
        nested = part.get("parts", [])
        if nested:
            nested_text = _extract_prose_from_parts(nested)
            if nested_text:
                prose.append(nested_text)
    return " ".join([p for p in prose if p]).strip()


def _flatten_oscal_controls(controls: Iterable[Dict], family: str) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    for control in controls or []:
        control_id = str(control.get("id", "")).strip()
        title = str(control.get("title", "")).strip()
        description = _extract_prose_from_parts(control.get("parts", []))

        if control_id and (title or description):
            rows.append(
                {
                    "control_id": control_id,
                    "title": title,
                    "description": description,
                    "family": family,
                }
            )

        enhancements = control.get("controls", [])
        if enhancements:
            rows.extend(_flatten_oscal_controls(enhancements, family))
    return rows


def fetch_nist_controls(source_url: str = DEFAULT_NIST_JSON_URL, timeout: int = 90) -> pd.DataFrame:
    """Fetch NIST SP 800-53 Rev 5 controls from a JSON or CSV source URL."""
    response = requests.get(source_url, timeout=timeout)
    response.raise_for_status()

    if source_url.lower().endswith(".csv"):
        df = pd.read_csv(io.StringIO(response.text))
        column_aliases = {
            "control_id": ["control_id", "id", "Control Identifier", "Control ID", "ControlId"],
            "title": ["title", "name", "Control Name", "Control Title"],
            "description": ["description", "statement", "Control Text", "Description"],
            "family": ["family", "Family", "Control Family", "group"],
        }
        mapped: Dict[str, pd.Series] = {}
        for target_col, aliases in column_aliases.items():
            for alias in aliases:
                if alias in df.columns:
                    mapped[target_col] = df[alias].astype(str)
                    break

        out = pd.DataFrame(mapped)
        required = ["control_id", "title", "description"]
        missing = [c for c in required if c not in out.columns]
        if missing:
            raise ValueError(
                f"CSV source missing required columns after alias mapping: {missing}. "
                f"Available columns: {df.columns.tolist()}"
            )
        if "family" not in out.columns:
            out["family"] = "UNKNOWN"
        out = out.fillna("")
        out = out.drop_duplicates(subset=["control_id", "description"]).reset_index(drop=True)
        return out

    payload = response.json()
    catalog = payload.get("catalog", payload)
    groups = catalog.get("groups", [])

    rows: List[Dict[str, str]] = []
    for group in groups:
        family = str(group.get("id") or group.get("title") or "UNKNOWN").strip()
        rows.extend(_flatten_oscal_controls(group.get("controls", []), family))

    controls_df = pd.DataFrame(rows)
    if controls_df.empty:
        raise ValueError("No controls parsed from JSON source.")

    controls_df = controls_df.fillna("")
    controls_df = controls_df.drop_duplicates(subset=["control_id", "description"]).reset_index(drop=True)
    return controls_df


def save_controls(controls_df: pd.DataFrame, output_json: Path, output_csv: Path) -> None:
    output_json.parent.mkdir(parents=True, exist_ok=True)
    controls_df.to_json(output_json, orient="records", indent=2)
    controls_df.to_csv(output_csv, index=False)


def generate_synthetic_cloudtrail_logs(n_logs: int = 1000, seed: int = 42) -> pd.DataFrame:
    """Generate synthetic compliant and non-compliant CloudTrail-like logs."""
    random.seed(seed)
    np.random.seed(seed)

    regions = ["us-east-1", "us-west-2", "eu-west-1", "ap-south-1"]
    users = [f"user-{i:03d}" for i in range(1, 75)] + ["root"]
    ip_blocks = ["10.0", "172.16", "192.168", "54.240", "3.91"]

    compliant_events = [
        {
            "EventName": "ConsoleLogin",
            "EventSource": "signin.amazonaws.com",
            "MFA_Used": True,
            "Resource": "IAM User",
            "EventDetail": "User logged in with MFA",
            "ComplianceLabel": "Compliant",
        },
        {
            "EventName": "PutBucketPublicAccessBlock",
            "EventSource": "s3.amazonaws.com",
            "MFA_Used": True,
            "Resource": "S3 Bucket",
            "EventDetail": "S3 public access block enabled",
            "ComplianceLabel": "Compliant",
        },
        {
            "EventName": "AuthorizeSecurityGroupIngress",
            "EventSource": "ec2.amazonaws.com",
            "MFA_Used": True,
            "Resource": "Security Group",
            "EventDetail": "Security group updated with restricted source CIDR",
            "ComplianceLabel": "Compliant",
        },
        {
            "EventName": "DisableKey",
            "EventSource": "kms.amazonaws.com",
            "MFA_Used": True,
            "Resource": "KMS Key",
            "EventDetail": "Unused KMS key disabled per key lifecycle policy",
            "ComplianceLabel": "Compliant",
        },
    ]

    non_compliant_events = [
        {
            "EventName": "CreateBucket",
            "EventSource": "s3.amazonaws.com",
            "MFA_Used": False,
            "Resource": "S3 Bucket",
            "EventDetail": "Public S3 bucket created",
            "ComplianceLabel": "Non-Compliant",
        },
        {
            "EventName": "ConsoleLogin",
            "EventSource": "signin.amazonaws.com",
            "MFA_Used": False,
            "Resource": "Root Account",
            "EventDetail": "Root login without MFA",
            "ComplianceLabel": "Non-Compliant",
        },
        {
            "EventName": "PutBucketAcl",
            "EventSource": "s3.amazonaws.com",
            "MFA_Used": False,
            "Resource": "S3 Bucket",
            "EventDetail": "Bucket ACL set to public-read",
            "ComplianceLabel": "Non-Compliant",
        },
        {
            "EventName": "AuthorizeSecurityGroupIngress",
            "EventSource": "ec2.amazonaws.com",
            "MFA_Used": False,
            "Resource": "Security Group",
            "EventDetail": "Security group opened to 0.0.0.0/0 on port 22",
            "ComplianceLabel": "Non-Compliant",
        },
        {
            "EventName": "CreateAccessKey",
            "EventSource": "iam.amazonaws.com",
            "MFA_Used": False,
            "Resource": "IAM User",
            "EventDetail": "Long-lived IAM access key created without approval",
            "ComplianceLabel": "Non-Compliant",
        },
    ]

    start_time = datetime.now(timezone.utc) - timedelta(days=7)
    logs: List[Dict[str, object]] = []

    for _ in range(n_logs):
        is_compliant = random.random() < 0.7
        template = random.choice(compliant_events if is_compliant else non_compliant_events).copy()

        user = random.choice(users)
        if template["EventDetail"] == "Root login without MFA":
            user = "root"

        region = random.choice(regions)
        event_time = start_time + timedelta(seconds=random.randint(0, 7 * 24 * 3600))
        ip_prefix = random.choice(ip_blocks)
        source_ip = f"{ip_prefix}.{random.randint(0, 255)}.{random.randint(1, 254)}"

        logs.append(
            {
                "EventTime": event_time.isoformat(),
                "UserID": user,
                "EventName": template["EventName"],
                "EventSource": template["EventSource"],
                "AWSRegion": region,
                "Region": region,
                "SourceIPAddress": source_ip,
                "MFA_Used": bool(template["MFA_Used"]),
                "Resource": template["Resource"],
                "EventDetail": template["EventDetail"],
                "ComplianceLabel": template["ComplianceLabel"],
                "RawLog": (
                    f"{event_time.isoformat()} {template['EventSource']} {template['EventName']} "
                    f"by {user} in {region}; MFA={template['MFA_Used']}; {template['EventDetail']}"
                ),
            }
        )

    return pd.DataFrame(logs)


def _build_drift_reason(row: pd.Series, region_frequency: Dict[str, int]) -> str:
    reasons: List[str] = []

    user_id = str(row.get("UserID", ""))
    event_source = str(row.get("EventSource", ""))
    event_name = str(row.get("EventName", ""))
    region = str(row.get("Region", row.get("AWSRegion", "")))
    mfa_used = str(row.get("MFA_Used", "")).strip().lower() in {"1", "true", "yes"}

    if user_id.lower() == "root":
        reasons.append("event performed by root account")
    if not mfa_used:
        reasons.append("MFA not used for a sensitive action")
    if "s3" in event_source.lower() and (
        "public" in str(row.get("EventDetail", "")).lower() or "putbucketacl" in event_name.lower()
    ):
        reasons.append("S3 action indicates possible public exposure")
    if region and region_frequency.get(region, 0) <= 5:
        reasons.append(f"activity in rare region {region}")

    if not reasons:
        reasons.append("rare combination of categorical feature values")

    return "; ".join(reasons)


def _recommended_remediation(reason: str) -> str:
    lowered = reason.lower()
    if "mfa" in lowered:
        return "Enforce MFA via IAM policy and block sensitive APIs without MFA context."
    if "root" in lowered:
        return "Disable root access keys and restrict root account usage to break-glass scenarios."
    if "public exposure" in lowered or "s3" in lowered:
        return "Enable S3 Block Public Access and apply restrictive bucket policies."
    if "rare region" in lowered:
        return "Review geo-access policy and restrict deployment regions."
    return "Review IAM permissions, tighten least privilege, and verify change approvals."


def train_isolation_forest_and_score(
    input_csv: Path,
    output_csv: Path,
    random_state: int = 42,
    contamination: float = 0.12,
    drift_threshold: float = -0.5,
) -> pd.DataFrame:
    """Train Isolation Forest and flag logs with anomaly score below threshold."""
    df = pd.read_csv(input_csv)

    for col in ["UserID", "EventSource", "Region", "MFA_Used"]:
        if col not in df.columns:
            raise ValueError(f"Input CSV must include column: {col}")

    model_df = df.copy()
    model_df["MFA_Used"] = model_df["MFA_Used"].astype(str).str.lower().isin(["true", "1", "yes"])

    categorical_features = ["UserID", "EventSource", "Region", "MFA_Used"]
    numeric_features = [c for c in model_df.columns if c not in categorical_features and pd.api.types.is_numeric_dtype(model_df[c])]

    preprocessor = ColumnTransformer(
        transformers=[
            ("cat", OneHotEncoder(handle_unknown="ignore"), categorical_features),
            ("num", "passthrough", numeric_features),
        ],
        remainder="drop",
    )

    iso = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=random_state,
    )

    pipeline = Pipeline(steps=[("prep", preprocessor), ("model", iso)])
    pipeline.fit(model_df)

    scores = pipeline.named_steps["model"].score_samples(pipeline.named_steps["prep"].transform(model_df))
    df["Anomaly Score"] = scores
    df["DriftFlag"] = np.where(df["Anomaly Score"] < drift_threshold, "Potential Compliance Drift", "Normal")

    region_frequency = model_df["Region"].value_counts().to_dict()
    df["DriftReason"] = df.apply(lambda r: _build_drift_reason(r, region_frequency), axis=1)
    df["RemediationStep"] = df["DriftReason"].apply(_recommended_remediation)

    output_csv.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_csv, index=False)
    return df


def resolve_mapping_with_hitl(
    log_text: str,
    top_matches: List[ControlMatch],
    similarity_threshold: float = 0.7,
    reviewer_fn: Optional[Callable[[str, List[ControlMatch]], Optional[str]]] = None,
    interactive: bool = False,
) -> Dict[str, object]:
    """Human-in-the-loop control selection when model confidence is low."""
    if not top_matches:
        return {
            "selected_control_id": "UNKNOWN",
            "selected_similarity": 0.0,
            "hitl_required": True,
            "hitl_decision": "No match candidates generated",
            "top_matches": [],
        }

    best = top_matches[0]
    hitl_required = best.similarity < similarity_threshold
    selected_control_id = best.control_id
    selected_similarity = best.similarity
    hitl_decision = "Accepted model suggestion"

    if hitl_required:
        hitl_decision = "Pending human review"
        if reviewer_fn is not None:
            human_choice = reviewer_fn(log_text, top_matches)
            if human_choice:
                selected_control_id = human_choice
                hitl_decision = f"Human selected {human_choice}"
        elif interactive:
            print("\nHITL REVIEW REQUIRED")
            print(f"Log: {log_text}")
            for idx, match in enumerate(top_matches, start=1):
                print(
                    f"  {idx}. {match.control_id} ({match.similarity:.3f}) - "
                    f"{match.title[:90]}"
                )
            print("Enter control id to override, or press Enter to keep top match.")
            choice = input("Control ID: ").strip()
            if choice:
                selected_control_id = choice
                hitl_decision = f"Human selected {choice}"

    return {
        "selected_control_id": selected_control_id,
        "selected_similarity": float(selected_similarity),
        "hitl_required": hitl_required,
        "hitl_decision": hitl_decision,
        "top_matches": [
            {
                "control_id": m.control_id,
                "title": m.title,
                "similarity": round(m.similarity, 4),
            }
            for m in top_matches
        ],
    }


def map_logs_to_controls(
    logs_df: pd.DataFrame,
    controls_df: pd.DataFrame,
    similarity_threshold: float = 0.7,
    interactive_hitl: bool = False,
) -> List[Dict[str, object]]:
    mapper = NISTControlMapper(controls_df)
    mapping_results: List[Dict[str, object]] = []

    for _, row in logs_df.iterrows():
        raw_log = str(row.get("RawLog", row.get("EventDetail", "")))
        top_matches = mapper.top_k_controls(raw_log, k=3)
        resolved = resolve_mapping_with_hitl(
            raw_log,
            top_matches,
            similarity_threshold=similarity_threshold,
            interactive=interactive_hitl,
        )
        mapping_results.append(
            {
                "Resource": row.get("Resource", "Unknown Resource"),
                "RawLog": raw_log,
                "DriftReason": row.get("DriftReason", "Potential policy deviation"),
                "RemediationStep": row.get("RemediationStep", "Investigate and remediate configuration."),
                "selected_control_id": resolved["selected_control_id"],
                "selected_similarity": resolved["selected_similarity"],
                "hitl_required": resolved["hitl_required"],
                "hitl_decision": resolved["hitl_decision"],
                "top_matches": resolved["top_matches"],
            }
        )

    return mapping_results


def generate_markdown_report(
    anomaly_df: pd.DataFrame,
    mapping_results: List[Dict[str, object]],
    output_md: Path,
) -> str:
    """Generate final Markdown report for flagged anomalies."""
    flagged = anomaly_df[anomaly_df["DriftFlag"] == "Potential Compliance Drift"].reset_index(drop=True)
    result_count = min(len(flagged), len(mapping_results))

    lines: List[str] = []
    lines.append("# Compliance Drift Report")
    lines.append("")
    lines.append(f"Generated at: {datetime.now(timezone.utc).isoformat()}")
    lines.append(f"Flagged anomalies: {len(flagged)}")
    lines.append("")

    if result_count == 0:
        lines.append("No flagged anomalies were detected.")
    else:
        for idx in range(result_count):
            anomaly_row = flagged.iloc[idx]
            mapping = mapping_results[idx]

            resource = str(mapping.get("Resource", anomaly_row.get("Resource", "Unknown Resource")))
            control_id = str(mapping.get("selected_control_id", "UNKNOWN"))
            reason = str(mapping.get("DriftReason", anomaly_row.get("DriftReason", "Unknown reason")))
            recommendation = str(mapping.get("RemediationStep", anomaly_row.get("RemediationStep", "Review configuration.")))
            sim = float(mapping.get("selected_similarity", 0.0))
            hitl_note = str(mapping.get("hitl_decision", ""))

            lines.append(f"## Anomaly {idx + 1}")
            lines.append(
                f"Anomaly detected in {resource}. This violates NIST Control {control_id} "
                f"because {reason}. Recommendation: {recommendation}."
            )
            lines.append(f"- Similarity Score: {sim:.3f}")
            lines.append(f"- HITL Decision: {hitl_note}")
            lines.append("")

    report = "\n".join(lines)
    output_md.parent.mkdir(parents=True, exist_ok=True)
    output_md.write_text(report, encoding="utf-8")
    return report


def run_pipeline(
    nist_source_url: str,
    logs_count: int,
    output_dir: Path,
    processed_logs_csv: Optional[Path] = None,
    similarity_threshold: float = 0.7,
    interactive_hitl: bool = False,
) -> Dict[str, Path]:
    """Run all phases and persist outputs."""
    output_dir.mkdir(parents=True, exist_ok=True)

    controls_df = fetch_nist_controls(nist_source_url)
    controls_json = output_dir / "nist_controls_rev5.json"
    controls_csv = output_dir / "nist_controls_rev5.csv"
    save_controls(controls_df, controls_json, controls_csv)

    synthetic_logs_df = generate_synthetic_cloudtrail_logs(n_logs=logs_count)
    synthetic_logs_csv = output_dir / "synthetic_cloudtrail_logs.csv"
    synthetic_logs_df.to_csv(synthetic_logs_csv, index=False)

    model_input_csv = processed_logs_csv if processed_logs_csv else synthetic_logs_csv
    anomaly_csv = output_dir / "anomaly_scored_logs.csv"
    scored_df = train_isolation_forest_and_score(model_input_csv, anomaly_csv)

    flagged_df = scored_df[scored_df["DriftFlag"] == "Potential Compliance Drift"].copy().reset_index(drop=True)
    mapping_results = map_logs_to_controls(
        flagged_df,
        controls_df,
        similarity_threshold=similarity_threshold,
        interactive_hitl=interactive_hitl,
    )

    mapping_json = output_dir / "sbert_mapping_results.json"
    mapping_json.write_text(json.dumps(mapping_results, indent=2), encoding="utf-8")

    report_md = output_dir / "compliance_drift_report.md"
    generate_markdown_report(flagged_df, mapping_results, report_md)

    return {
        "controls_json": controls_json,
        "controls_csv": controls_csv,
        "synthetic_logs_csv": synthetic_logs_csv,
        "anomaly_csv": anomaly_csv,
        "mapping_json": mapping_json,
        "report_md": report_md,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="GRC AI compliance drift pipeline")
    parser.add_argument(
        "--nist-source-url",
        default=DEFAULT_NIST_JSON_URL,
        help="NIST controls source URL (JSON or CSV).",
    )
    parser.add_argument(
        "--logs-count",
        type=int,
        default=1000,
        help="Number of synthetic CloudTrail-style logs to generate.",
    )
    parser.add_argument(
        "--processed-logs-csv",
        type=Path,
        default=None,
        help="Optional path to processed AWS logs CSV for model training.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("outputs"),
        help="Output directory for generated artifacts.",
    )
    parser.add_argument(
        "--similarity-threshold",
        type=float,
        default=0.7,
        help="HITL trigger threshold for top SBERT similarity score.",
    )
    parser.add_argument(
        "--interactive-hitl",
        action="store_true",
        help="Prompt for human control override when confidence is low.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    outputs = run_pipeline(
        nist_source_url=args.nist_source_url,
        logs_count=args.logs_count,
        output_dir=args.output_dir,
        processed_logs_csv=args.processed_logs_csv,
        similarity_threshold=args.similarity_threshold,
        interactive_hitl=args.interactive_hitl,
    )

    print("Pipeline completed. Artifacts:")
    for name, path in outputs.items():
        print(f"- {name}: {path}")


if __name__ == "__main__":
    main()
