from __future__ import annotations

import base64
import hashlib
import hmac
import io
import json
import os
import secrets
import threading
import time
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import pandas as pd
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

DEFAULT_NIST_JSON_URL = (
    "https://raw.githubusercontent.com/usnistgov/oscal-content/main/"
    "nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
)

app = FastAPI(title="GRC AI Dashboard", version="1.0.0")
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

HISTORY_PATH = Path("data") / "run_history.json"
USERS_PATH = Path("data") / "users.json"
TOKENS: Dict[str, Dict[str, str]] = {}
JOBS: Dict[str, Dict[str, Any]] = {}
APP_ENV = os.getenv("APP_ENV", "development").strip().lower()
TOKEN_SECRET = os.getenv("GRC_TOKEN_SECRET", "grc-ai-demo-token-secret-change-in-prod")
TOKEN_TTL_SECONDS = int(os.getenv("GRC_TOKEN_TTL_SECONDS", "43200"))
FORCE_DEMO_USERS = os.getenv("GRC_FORCE_DEMO_USERS", "false").strip().lower() in {"1", "true", "yes"}
DEFAULT_DEMO_ADMIN_USER = os.getenv("GRC_DEMO_ADMIN_USER", "demo_admin").strip() or "demo_admin"
DEFAULT_DEMO_ADMIN_PASSWORD = os.getenv("GRC_DEMO_ADMIN_PASSWORD", "GrcAI_Demo@2026").strip() or "GrcAI_Demo@2026"
DEFAULT_DEMO_REVIEWER_USER = os.getenv("GRC_DEMO_REVIEWER_USER", "demo_reviewer").strip() or "demo_reviewer"
DEFAULT_DEMO_REVIEWER_PASSWORD = os.getenv("GRC_DEMO_REVIEWER_PASSWORD", "GrcAI_Review@2026").strip() or "GrcAI_Review@2026"


OUTPUT_SETS = {
    "outputs": Path("outputs"),
    "outputs_sample": Path("outputs_sample"),
    "demo_phase1": Path("demo_outputs") / "phase1",
    "demo_phase2": Path("demo_outputs") / "phase2",
    "demo_phase3": Path("demo_outputs") / "phase3",
    "demo_phase4": Path("demo_outputs") / "phase4",
}


class PipelineRunRequest(BaseModel):
    logs_count: int = Field(default=1000, ge=100, le=100000)
    similarity_threshold: float = Field(default=0.7, ge=0.0, le=1.0)
    output_set: str = Field(default="outputs")
    nist_source_url: str = Field(default=DEFAULT_NIST_JSON_URL)


class PipelineRunResponse(BaseModel):
    message: str
    artifacts: Dict[str, str]


class PipelineRunQueuedResponse(BaseModel):
    message: str
    job_id: str
    run_id: str


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    role: str


def _hash_password(password: str, salt: bytes | None = None) -> Dict[str, str]:
    salt_bytes = salt if salt is not None else os.urandom(16)
    digest = __import__("hashlib").pbkdf2_hmac("sha256", password.encode("utf-8"), salt_bytes, 120000)
    return {
        "salt": base64.b64encode(salt_bytes).decode("ascii"),
        "hash": base64.b64encode(digest).decode("ascii"),
    }


def _verify_password(password: str, salt_b64: str, hash_b64: str) -> bool:
    salt = base64.b64decode(salt_b64.encode("ascii"))
    expected = base64.b64decode(hash_b64.encode("ascii"))
    candidate = __import__("hashlib").pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120000)
    return secrets.compare_digest(candidate, expected)


def _save_users(users: Dict[str, Dict[str, str]]) -> None:
    USERS_PATH.parent.mkdir(parents=True, exist_ok=True)
    USERS_PATH.write_text(json.dumps(users, indent=2), encoding="utf-8")


def _load_users() -> Dict[str, Dict[str, str]]:
    if not USERS_PATH.exists():
        return {}
    payload = _read_json(USERS_PATH, default={})
    if not isinstance(payload, dict):
        return {}
    return payload


def _ensure_default_users() -> None:
    users = _load_users()
    if users and not FORCE_DEMO_USERS:
        return

    env_admin_user = os.getenv("GRC_ADMIN_USER", "").strip()
    env_admin_pass = os.getenv("GRC_ADMIN_PASSWORD", "").strip()
    env_admin_role = os.getenv("GRC_ADMIN_ROLE", "admin").strip() or "admin"

    if env_admin_user and env_admin_pass:
        seeded = {
            env_admin_user: {
                **_hash_password(env_admin_pass),
                "role": env_admin_role,
            }
        }
        _save_users(seeded)
        return

    seeded = users.copy() if users else {}
    seeded[DEFAULT_DEMO_ADMIN_USER] = {
        **_hash_password(DEFAULT_DEMO_ADMIN_PASSWORD),
        "role": "admin",
    }
    seeded[DEFAULT_DEMO_REVIEWER_USER] = {
        **_hash_password(DEFAULT_DEMO_REVIEWER_PASSWORD),
        "role": "reviewer",
    }
    seeded["demo_analyst"] = {
        **_hash_password("GrcAI_Analyst@2026"),
        "role": "analyst",
    }
    _save_users(seeded)


def _safe_output_dir(output_set: str) -> Path:
    if output_set not in OUTPUT_SETS:
        raise HTTPException(status_code=400, detail=f"Unknown output_set: {output_set}")
    return OUTPUT_SETS[output_set]


def _read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _read_markdown(path: Path) -> str:
    if not path.exists():
        return "Report not generated yet. Run the pipeline from the dashboard."
    return path.read_text(encoding="utf-8")


def _collect_artifacts(base_dir: Path) -> Dict[str, Path]:
    return {
        "controls_json": base_dir / "nist_controls_rev5.json",
        "controls_csv": base_dir / "nist_controls_rev5.csv",
        "synthetic_logs_csv": base_dir / "synthetic_cloudtrail_logs.csv",
        "anomaly_csv": base_dir / "anomaly_scored_logs.csv",
        "mapping_json": base_dir / "sbert_mapping_results.json",
        "report_md": base_dir / "compliance_drift_report.md",
    }


def _summary_for_output_set(output_set: str) -> Dict[str, Any]:
    base_dir = _safe_output_dir(output_set)
    artifacts = _collect_artifacts(base_dir)

    summary: Dict[str, Any] = {
        "output_set": output_set,
        "base_dir": str(base_dir),
        "exists": base_dir.exists(),
        "controls_count": 0,
        "logs_count": 0,
        "drift_count": 0,
        "drift_rate": 0.0,
        "mapped_count": 0,
        "hitl_required_count": 0,
    }

    controls_path = artifacts["controls_csv"]
    if controls_path.exists():
        controls_df = pd.read_csv(controls_path)
        summary["controls_count"] = len(controls_df)

    anomaly_path = artifacts["anomaly_csv"]
    if anomaly_path.exists():
        anomaly_df = pd.read_csv(anomaly_path)
        summary["logs_count"] = len(anomaly_df)
        drift_mask = anomaly_df.get("DriftFlag", pd.Series([], dtype=object)) == "Potential Compliance Drift"
        drift_count = int(drift_mask.sum()) if len(anomaly_df) else 0
        summary["drift_count"] = drift_count
        summary["drift_rate"] = (drift_count / len(anomaly_df)) if len(anomaly_df) else 0.0

    mapping_path = artifacts["mapping_json"]
    mappings = _read_json(mapping_path, default=[])
    if isinstance(mappings, list):
        summary["mapped_count"] = len(mappings)
        summary["hitl_required_count"] = sum(1 for m in mappings if bool(m.get("hitl_required")))

    return summary


def _load_history() -> List[Dict[str, Any]]:
    if not HISTORY_PATH.exists():
        return []
    with HISTORY_PATH.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, list):
        return []
    return payload


def _save_history(items: List[Dict[str, Any]]) -> None:
    HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
    HISTORY_PATH.write_text(json.dumps(items, indent=2), encoding="utf-8")


def _append_history(item: Dict[str, Any]) -> None:
    history = _load_history()
    history.append(item)
    _save_history(history)


def _get_history_item(run_id: str) -> Dict[str, Any] | None:
    for item in _load_history():
        if item.get("run_id") == run_id:
            return item
    return None


def _extract_token(authorization: str | None) -> str:
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    if not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Authorization must be Bearer token")
    return authorization.split(" ", 1)[1].strip()


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode((data + padding).encode("ascii"))


def _issue_token(username: str, role: str) -> str:
    payload = {
        "u": username,
        "r": role,
        "exp": int(time.time()) + TOKEN_TTL_SECONDS,
    }
    payload_str = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    sig = hmac.new(TOKEN_SECRET.encode("utf-8"), payload_str.encode("ascii"), hashlib.sha256).digest()
    sig_str = _b64url_encode(sig)
    return f"{payload_str}.{sig_str}"


def _verify_token(token: str) -> Dict[str, str] | None:
    try:
        payload_part, sig_part = token.split(".", 1)
    except ValueError:
        return None

    expected_sig = hmac.new(TOKEN_SECRET.encode("utf-8"), payload_part.encode("ascii"), hashlib.sha256).digest()
    provided_sig = _b64url_decode(sig_part)
    if not hmac.compare_digest(expected_sig, provided_sig):
        return None

    payload_raw = _b64url_decode(payload_part)
    payload = json.loads(payload_raw.decode("utf-8"))
    if int(payload.get("exp", 0)) < int(time.time()):
        return None

    username = str(payload.get("u", "")).strip()
    role = str(payload.get("r", "")).strip()
    if not username or not role:
        return None
    return {"username": username, "role": role}


def get_current_user(authorization: str | None = Header(default=None)) -> Dict[str, str]:
    token = _extract_token(authorization)
    user = _verify_token(token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return user


def require_roles(*allowed_roles: str):
    def _role_dependency(user: Dict[str, str] = Depends(get_current_user)) -> Dict[str, str]:
        if user.get("role") not in allowed_roles:
            raise HTTPException(status_code=403, detail="Insufficient role permissions")
        return user

    return _role_dependency


def _render_report_pdf(report_markdown: str) -> bytes:
    buffer = io.BytesIO()
    doc = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    x = 40
    y = height - 40

    doc.setFont("Helvetica-Bold", 13)
    doc.drawString(x, y, "GRC AI Compliance Drift Report")
    y -= 24
    doc.setFont("Helvetica", 9)

    for raw_line in report_markdown.splitlines():
        line = raw_line if raw_line.strip() else " "
        for chunk_start in range(0, len(line), 110):
            chunk = line[chunk_start : chunk_start + 110]
            if y < 40:
                doc.showPage()
                doc.setFont("Helvetica", 9)
                y = height - 40
            doc.drawString(x, y, chunk)
            y -= 12

    doc.save()
    return buffer.getvalue()


def _run_pipeline_job(job_id: str, run_id: str, payload: PipelineRunRequest, user: Dict[str, str]) -> None:
    output_dir = _safe_output_dir(payload.output_set)
    output_dir.mkdir(parents=True, exist_ok=True)
    started_at = datetime.now(timezone.utc)

    JOBS[job_id].update(
        {
            "status": "running",
            "progress": 10,
            "stage": "Preparing output directory",
            "started_at": started_at.isoformat(),
        }
    )

    try:
        JOBS[job_id].update({"progress": 25, "stage": "Running GRC pipeline"})
        # Import lazily to avoid loading heavy ML dependencies during web app cold start.
        from grc_ai_pipeline import run_pipeline

        outputs = run_pipeline(
            nist_source_url=payload.nist_source_url,
            logs_count=payload.logs_count,
            output_dir=output_dir,
            similarity_threshold=payload.similarity_threshold,
            interactive_hitl=False,
        )
        JOBS[job_id].update({"progress": 85, "stage": "Computing summary and saving run history"})

        summary = _summary_for_output_set(payload.output_set)
        status = "completed"
        error_detail = ""
    except Exception as exc:
        outputs = {}
        summary = {"output_set": payload.output_set}
        status = "failed"
        error_detail = str(exc)

    finished_at = datetime.now(timezone.utc)
    history_item = {
        "run_id": run_id,
        "job_id": job_id,
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "duration_seconds": round((finished_at - started_at).total_seconds(), 3),
        "status": status,
        "triggered_by": user["username"],
        "role": user["role"],
        "params": payload.model_dump(),
        "summary": summary,
        "artifacts": {name: str(path) for name, path in outputs.items()},
        "error": error_detail,
    }
    _append_history(history_item)

    JOBS[job_id].update(
        {
            "status": status,
            "progress": 100,
            "stage": "Completed" if status == "completed" else "Failed",
            "finished_at": finished_at.isoformat(),
            "error": error_detail,
            "summary": summary,
            "artifacts": history_item["artifacts"],
            "run_id": run_id,
        }
    )


_ensure_default_users()


@app.get("/", response_class=HTMLResponse)
def index(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request=request, name="index.html", context={})


@app.post("/api/login", response_model=LoginResponse)
def login(payload: LoginRequest) -> LoginResponse:
    users = _load_users()
    record = users.get(payload.username)
    if not record:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    salt_b64 = record.get("salt", "")
    hash_b64 = record.get("hash", "")
    if not salt_b64 or not hash_b64 or not _verify_password(payload.password, salt_b64, hash_b64):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = _issue_token(payload.username, record["role"])
    return LoginResponse(access_token=token, username=payload.username, role=record["role"])


@app.get("/api/me")
def me(user: Dict[str, str] = Depends(get_current_user)) -> Dict[str, str]:
    return user


@app.get("/api/output-sets")
def list_output_sets(user: Dict[str, str] = Depends(get_current_user)) -> Dict[str, List[str]]:
    return {"output_sets": list(OUTPUT_SETS.keys())}


@app.get("/api/summary")
def get_summary(
    output_set: str = Query(default="outputs"),
    user: Dict[str, str] = Depends(get_current_user),
) -> Dict[str, Any]:
    return _summary_for_output_set(output_set)


@app.get("/api/artifacts")
def get_artifacts(
    output_set: str = Query(default="outputs"),
    user: Dict[str, str] = Depends(get_current_user),
) -> Dict[str, Any]:
    base_dir = _safe_output_dir(output_set)
    artifacts = _collect_artifacts(base_dir)

    rows = []
    for name, path in artifacts.items():
        rows.append(
            {
                "name": name,
                "path": str(path),
                "exists": path.exists(),
                "size_bytes": path.stat().st_size if path.exists() else 0,
            }
        )

    return {"output_set": output_set, "artifacts": rows}


@app.get("/api/mappings")
def get_mappings(
    output_set: str = Query(default="outputs"),
    limit: int = Query(default=20, ge=1, le=500),
    user: Dict[str, str] = Depends(get_current_user),
) -> Dict[str, Any]:
    base_dir = _safe_output_dir(output_set)
    mapping_path = base_dir / "sbert_mapping_results.json"
    mappings = _read_json(mapping_path, default=[])

    if not isinstance(mappings, list):
        raise HTTPException(status_code=500, detail="Mapping JSON format is invalid")

    return {
        "output_set": output_set,
        "total": len(mappings),
        "items": mappings[:limit],
    }


@app.get("/api/report")
def get_report(
    output_set: str = Query(default="outputs"),
    user: Dict[str, str] = Depends(get_current_user),
) -> Dict[str, str]:
    base_dir = _safe_output_dir(output_set)
    return {"output_set": output_set, "report_markdown": _read_markdown(base_dir / "compliance_drift_report.md")}


@app.get("/api/run-history")
def get_run_history(
    limit: int = Query(default=25, ge=1, le=500),
    user: Dict[str, str] = Depends(get_current_user),
) -> Dict[str, Any]:
    history = _load_history()
    history = sorted(history, key=lambda item: item.get("started_at", ""), reverse=True)
    return {"total": len(history), "items": history[:limit]}


@app.get("/api/run-history/{run_id}")
def get_run_detail(
    run_id: str,
    user: Dict[str, str] = Depends(get_current_user),
) -> Dict[str, Any]:
    item = _get_history_item(run_id)
    if not item:
        raise HTTPException(status_code=404, detail=f"Run not found: {run_id}")

    output_set = item.get("params", {}).get("output_set", "outputs")
    base_dir = _safe_output_dir(output_set)
    artifacts = _collect_artifacts(base_dir)
    artifact_rows = []
    for name, path in artifacts.items():
        artifact_rows.append(
            {
                "name": name,
                "path": str(path),
                "exists": path.exists(),
                "size_bytes": path.stat().st_size if path.exists() else 0,
            }
        )

    summary = item.get("summary", {})
    chart = {
        "labels": ["Drift", "Normal"],
        "values": [
            int(summary.get("drift_count", 0)),
            max(int(summary.get("logs_count", 0)) - int(summary.get("drift_count", 0)), 0),
        ],
    }

    return {
        "run": item,
        "artifacts": artifact_rows,
        "chart": chart,
    }


@app.get("/api/jobs/{job_id}")
def get_job_status(
    job_id: str,
    user: Dict[str, str] = Depends(get_current_user),
) -> Dict[str, Any]:
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job not found: {job_id}")
    return job


@app.get("/api/export/report.pdf")
def export_report_pdf(
    output_set: str = Query(default="outputs"),
    user: Dict[str, str] = Depends(get_current_user),
) -> StreamingResponse:
    base_dir = _safe_output_dir(output_set)
    report = _read_markdown(base_dir / "compliance_drift_report.md")
    pdf_bytes = _render_report_pdf(report)

    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{output_set}_compliance_report.pdf"'},
    )


@app.get("/api/export/csv-bundle")
def export_csv_bundle(
    output_set: str = Query(default="outputs"),
    user: Dict[str, str] = Depends(get_current_user),
) -> StreamingResponse:
    base_dir = _safe_output_dir(output_set)
    artifacts = _collect_artifacts(base_dir)

    csv_targets = {
        "nist_controls_rev5.csv": artifacts["controls_csv"],
        "synthetic_cloudtrail_logs.csv": artifacts["synthetic_logs_csv"],
        "anomaly_scored_logs.csv": artifacts["anomaly_csv"],
    }

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        for archive_name, source_path in csv_targets.items():
            if source_path.exists():
                archive.write(source_path, arcname=archive_name)
        report_path = artifacts["report_md"]
        if report_path.exists():
            archive.write(report_path, arcname="compliance_drift_report.md")

    zip_buffer.seek(0)
    return StreamingResponse(
        zip_buffer,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{output_set}_grc_bundle.zip"'},
    )


@app.post("/api/run-pipeline", response_model=PipelineRunQueuedResponse)
def run_full_pipeline(
    payload: PipelineRunRequest,
    user: Dict[str, str] = Depends(require_roles("analyst", "admin")),
) -> PipelineRunQueuedResponse:
    run_id = str(uuid.uuid4())
    job_id = str(uuid.uuid4())
    JOBS[job_id] = {
        "job_id": job_id,
        "run_id": run_id,
        "status": "queued",
        "progress": 0,
        "stage": "Queued",
        "submitted_at": datetime.now(timezone.utc).isoformat(),
        "submitted_by": user["username"],
        "role": user["role"],
        "params": payload.model_dump(),
    }

    worker = threading.Thread(target=_run_pipeline_job, args=(job_id, run_id, payload, user), daemon=True)
    worker.start()

    return PipelineRunQueuedResponse(
        message="Pipeline job queued successfully.",
        job_id=job_id,
        run_id=run_id,
    )
