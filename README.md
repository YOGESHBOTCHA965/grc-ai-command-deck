# GRC AI Pipeline (NIST 800-53 + CloudTrail + SBERT + Isolation Forest)

This project implements all requested phases:

1. Scrapes NIST SP 800-53 Rev 5 controls from a JSON/CSV source.
2. Generates 1,000 synthetic AWS CloudTrail-style logs (compliant and non-compliant).
3. Maps log text to top-3 NIST controls using SBERT (`all-MiniLM-L6-v2`).
4. Trains an Isolation Forest model and flags `Potential Compliance Drift` where anomaly score < -0.5.
5. Adds Human-in-the-loop (HITL) review when similarity < 0.7.
6. Produces a final Markdown compliance report.

## Setup

```powershell
pip install -r requirements.txt
```

## Run

```powershell
python grc_ai_pipeline.py --output-dir outputs
```

## Web Dashboard (FastAPI + Frontend)

This project now includes a demo-ready web app so you can present results in a single interface.

Start the dashboard:

```powershell
uvicorn app:app --reload
```

Open:

- `http://127.0.0.1:8000`

What you can do from the dashboard:

- Login with role-based access (analyst, reviewer, admin).
- Run the full end-to-end pipeline as an asynchronous background job with live progress.
- Switch across output sets (`outputs`, `outputs_sample`, and `demo_outputs` phase folders).
- View telemetry (controls count, drift count, HITL-required count).
- Inspect generated artifacts.
- Browse recent SBERT mappings.
- Review run history with status and duration.
- Open per-run drilldown with artifact status and run metadata.
- Export the report as PDF and download a ZIP bundle of CSV outputs.
- Read the generated compliance drift report.

Demo credentials:

- `analyst / analyst123` (can run pipeline)
- `reviewer / reviewer123` (read/export only)
- `admin / admin123` (full access)

Security note:

- User credentials are persisted in `data/users.json` with salted PBKDF2-SHA256 password hashes.
- In production mode (`APP_ENV=production`), the app requires `GRC_ADMIN_USER` and `GRC_ADMIN_PASSWORD` for first startup if `data/users.json` does not exist.

API endpoints (for future integrations):

- `POST /api/login`
- `GET /api/me`
- `GET /api/output-sets`
- `GET /api/summary?output_set=outputs`
- `GET /api/artifacts?output_set=outputs`
- `GET /api/mappings?output_set=outputs&limit=20`
- `GET /api/report?output_set=outputs`
- `GET /api/run-history?limit=25`
- `GET /api/run-history/{run_id}`
- `GET /api/jobs/{job_id}`
- `GET /api/export/report.pdf?output_set=outputs`
- `GET /api/export/csv-bundle?output_set=outputs`
- `POST /api/run-pipeline`

Sample run payload:

```json
{
	"logs_count": 1000,
	"similarity_threshold": 0.7,
	"output_set": "outputs"
}
```

Sample queued response from `POST /api/run-pipeline`:

```json
{
	"message": "Pipeline job queued successfully.",
	"job_id": "<uuid>",
	"run_id": "<uuid>"
}
```

## Scaling Path (Production)

1. Split pipeline workloads into background jobs (Celery or RQ) so API requests return immediately.
2. Add a small database (PostgreSQL) to persist run history, metrics, and reviewer decisions.
3. Store output artifacts in object storage (S3/Azure Blob) with signed URLs.
4. Add authentication and role-based access for analyst, reviewer, and admin personas.
5. Containerize with Docker and deploy API/frontend behind a reverse proxy (Nginx) with HTTPS.
6. Add observability: structured logs, metrics, tracing, and alerting.

## Deploy (Docker)

Build and run:

```powershell
docker compose up --build
```

App URL:

- `http://127.0.0.1:8000`

For production container startup, set env vars:

- `APP_ENV=production`
- `GRC_ADMIN_USER=<your_admin_user>`
- `GRC_ADMIN_PASSWORD=<strong_password>`

Files:

- `Dockerfile`
- `docker-compose.yml`
- `.dockerignore`
- `.env.example`

## Deploy (Render)

1. Push this repo to GitHub.
2. In Render, create a new Blueprint/Web Service and point to this repo.
3. Render will detect `render.yaml`.
4. Set secret env vars in Render:
	- `GRC_ADMIN_USER`
	- `GRC_ADMIN_PASSWORD`
5. Deploy and open your generated Render URL.

## Deploy (Railway)

1. Push this repo to GitHub.
2. Create a new Railway project from the repo.
3. Railway will use `railway.json` and start with uvicorn.
4. Configure env vars:
	- `APP_ENV=production`
	- `GRC_ADMIN_USER`
	- `GRC_ADMIN_PASSWORD`
5. Deploy and use the generated public URL.

## CI (GitHub Actions)

This repo includes an automated CI workflow at `.github/workflows/ci.yml`.

On every push and pull request, CI runs:

1. Python dependency install from `requirements.txt`.
2. Python syntax/compile checks for top-level project scripts.
3. App import smoke test (`import app`).
4. FastAPI home route smoke test (`GET /` returns 200).
5. Docker image build validation (`docker build`).

This ensures code quality and deployment readiness before merging changes.

## Phase-Wise Demo (CPSC 6185)

Phase 1: Data engineering

```powershell
python phase1_data_engineering.py --output-dir outputs_phase1 --logs-count 1000
```

Phase 2: SBERT top-3 mapping

```powershell
python phase2_sbert_mapping.py --log-text "Root login without MFA from us-east-1" --output-json outputs_phase2/top3_controls.json
```

Phase 3: Anomaly detection

```powershell
python phase3_anomaly_detection.py --input-csv sample_processed_aws_logs.csv --output-csv outputs_phase3/anomaly_scored_logs.csv --threshold -0.5
```

Phase 4 + 5: Reporting + HITL

```powershell
python phase4_reporting_hitl.py --anomaly-csv outputs_phase3/anomaly_scored_logs.csv --report-md outputs_phase4/compliance_drift_report.md --mapping-json outputs_phase4/sbert_mapping_results.json --similarity-threshold 0.7 --interactive-hitl
```

Optional arguments:

- `--processed-logs-csv path/to/logs.csv` to train on your own processed AWS logs.
- `--similarity-threshold 0.7` to change HITL trigger level.
- `--interactive-hitl` to manually confirm low-confidence mappings.
- `--logs-count 1000` to change synthetic log count.

## Key Outputs

- `outputs/nist_controls_rev5.json`
- `outputs/nist_controls_rev5.csv`
- `outputs/synthetic_cloudtrail_logs.csv`
- `outputs/anomaly_scored_logs.csv`
- `outputs/sbert_mapping_results.json`
- `outputs/compliance_drift_report.md`
