# CPSC 6185 Demo Transcript

Date: 2026-03-30
Workspace: C:/Users/yoges/Desktop/GRC AI

## Environment Setup

Command:

```powershell
pip install -r requirements.txt
```

Installed packages:
- pandas
- numpy
- requests
- scikit-learn
- sentence-transformers

## Phase 1: Data Engineering

Command:

```powershell
python phase1_data_engineering.py --output-dir demo_outputs/phase1 --logs-count 1000
```

Observed output summary:
- Controls JSON generated
- Controls CSV generated
- Synthetic CloudTrail CSV generated

Artifact paths:
- demo_outputs/phase1/nist_controls_rev5.json
- demo_outputs/phase1/nist_controls_rev5.csv
- demo_outputs/phase1/synthetic_cloudtrail_logs.csv

Validation metric:
- controls_count = 1196
- synthetic_logs_count = 1000

## Phase 2: SBERT Mapping

Command:

```powershell
python phase2_sbert_mapping.py --log-text "Root login without MFA from us-east-1" --output-json demo_outputs/phase2/top3_controls.json
```

Observed top-3 controls (from output JSON):
1. ia-2.4, similarity 0.3754
2. ia-2.3, similarity 0.3688
3. ia-2.1, similarity 0.3564

Artifact path:
- demo_outputs/phase2/top3_controls.json

## Phase 3: Isolation Forest Drift Detection

Command:

```powershell
python phase3_anomaly_detection.py --input-csv sample_processed_aws_logs.csv --output-csv demo_outputs/phase3/anomaly_scored_logs.csv --threshold -0.5
```

Observed output summary:
- Total logs processed: 10
- Flagged logs: 0

Artifact path:
- demo_outputs/phase3/anomaly_scored_logs.csv

Validation metric:
- phase3_flagged_count = 0

## Phase 4 + 5: Final Report + HITL

Command:

```powershell
python phase4_reporting_hitl.py --anomaly-csv demo_outputs/phase3/anomaly_scored_logs.csv --report-md demo_outputs/phase4/compliance_drift_report.md --mapping-json demo_outputs/phase4/sbert_mapping_results.json --similarity-threshold 0.7
```

Observed output summary:
- Mapping JSON generated
- Markdown report generated
- Report indicates zero flagged anomalies for this sample run

Artifact paths:
- demo_outputs/phase4/sbert_mapping_results.json
- demo_outputs/phase4/compliance_drift_report.md

HITL behavior implemented:
- If top similarity < 0.7, mapping is marked for human review.
- Optional interactive override is available via:

```powershell
python phase4_reporting_hitl.py ... --interactive-hitl
```

## End-to-End Option

Single-command pipeline command:

```powershell
python grc_ai_pipeline.py --output-dir outputs
```

Outputs:
- outputs/nist_controls_rev5.json
- outputs/nist_controls_rev5.csv
- outputs/synthetic_cloudtrail_logs.csv
- outputs/anomaly_scored_logs.csv
- outputs/sbert_mapping_results.json
- outputs/compliance_drift_report.md
