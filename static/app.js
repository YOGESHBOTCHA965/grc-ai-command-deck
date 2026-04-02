const outputSetSelect = document.getElementById("outputSetSelect");
const refreshBtn = document.getElementById("refreshBtn");
const runBtn = document.getElementById("runBtn");
const runStatus = document.getElementById("runStatus");
const jobProgressBar = document.getElementById("jobProgressBar");
const jobStage = document.getElementById("jobStage");
const logsCountInput = document.getElementById("logsCount");
const similarityThresholdInput = document.getElementById("similarityThreshold");
const loginForm = document.getElementById("loginForm");
const usernameInput = document.getElementById("username");
const passwordInput = document.getElementById("password");
const authBadge = document.getElementById("authBadge");
const logoutBtn = document.getElementById("logoutBtn");

const controlsCount = document.getElementById("controlsCount");
const logsCountMetric = document.getElementById("logsCountMetric");
const driftCount = document.getElementById("driftCount");
const hitlCount = document.getElementById("hitlCount");
const artifactsTableWrap = document.getElementById("artifactsTableWrap");
const mappingsList = document.getElementById("mappingsList");
const reportText = document.getElementById("reportText");
const historyTableWrap = document.getElementById("historyTableWrap");
const runDetailWrap = document.getElementById("runDetailWrap");
const downloadPdfBtn = document.getElementById("downloadPdfBtn");
const downloadBundleBtn = document.getElementById("downloadBundleBtn");

let chart;
let authToken = "";
let currentUser = null;
let activeJobId = "";

function animateMetric(element, nextValue) {
  const target = Number(nextValue) || 0;
  const current = Number((element.textContent || "0").replace(/,/g, "")) || 0;
  const durationMs = 420;
  const start = performance.now();

  function step(timestamp) {
    const t = Math.min((timestamp - start) / durationMs, 1);
    const eased = 1 - Math.pow(1 - t, 3);
    const value = Math.round(current + (target - current) * eased);
    element.textContent = value.toLocaleString();
    if (t < 1) {
      requestAnimationFrame(step);
    }
  }

  requestAnimationFrame(step);
}

async function fetchJSON(url, options = {}) {
  const headers = options.headers ? { ...options.headers } : {};
  if (authToken) {
    headers.Authorization = `Bearer ${authToken}`;
  }

  const response = await fetch(url, { ...options, headers });
  if (!response.ok) {
    const detail = await response.text();
    throw new Error(detail || `Request failed: ${response.status}`);
  }
  return response.json();
}

async function downloadWithAuth(url, filename) {
  const headers = authToken ? { Authorization: `Bearer ${authToken}` } : {};
  const response = await fetch(url, { headers });
  if (!response.ok) {
    const detail = await response.text();
    throw new Error(detail || `Download failed: ${response.status}`);
  }

  const blob = await response.blob();
  const objectUrl = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = objectUrl;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(objectUrl);
}

function renderChart(totalLogs, driftLogs) {
  const normalLogs = Math.max(totalLogs - driftLogs, 0);
  const ctx = document.getElementById("driftChart").getContext("2d");

  if (chart) {
    chart.destroy();
  }

  chart = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: ["Normal", "Potential Drift"],
      datasets: [
        {
          data: [normalLogs, driftLogs],
          backgroundColor: ["#007f91", "#ff6a3d"],
          borderWidth: 0,
        },
      ],
    },
    options: {
      animation: {
        duration: 700,
        easing: "easeOutQuart",
      },
      cutout: "62%",
      plugins: {
        legend: {
          labels: {
            color: "#d5e7ff",
            font: {
              family: "Space Grotesk",
            },
          },
        },
      },
    },
  });
}

function renderArtifacts(artifacts) {
  const rows = artifacts
    .map((item) => {
      const status = item.exists ? "Available" : "Missing";
      const sizeKb = (item.size_bytes / 1024).toFixed(2);
      return `<tr><td>${item.name}</td><td>${status}</td><td>${sizeKb} KB</td><td>${item.path}</td></tr>`;
    })
    .join("");

  artifactsTableWrap.innerHTML = `
    <table>
      <thead>
        <tr><th>Artifact</th><th>Status</th><th>Size</th><th>Path</th></tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>
  `;
}

function renderMappings(mappings) {
  if (!mappings.length) {
    mappingsList.innerHTML = "<p>No mappings available yet.</p>";
    return;
  }

  mappingsList.innerHTML = mappings
    .slice(0, 20)
    .map((item) => {
      const reason = item.DriftReason || "n/a";
      return `
        <article class="mapping-item">
          <p><strong>Control:</strong> ${item.selected_control_id || "UNKNOWN"} (${(item.selected_similarity || 0).toFixed(3)})</p>
          <p><strong>Resource:</strong> ${item.Resource || "Unknown"}</p>
          <p><strong>Reason:</strong> ${reason}</p>
          <p><strong>HITL:</strong> ${item.hitl_decision || "n/a"}</p>
        </article>
      `;
    })
    .join("");
}

function renderHistory(historyItems) {
  if (!historyItems.length) {
    historyTableWrap.innerHTML = "<p>No run history yet.</p>";
    return;
  }

  const rows = historyItems
    .map((item) => {
      const outSet = item.params?.output_set || "n/a";
      const logs = item.params?.logs_count || "n/a";
      const drift = item.summary?.drift_count ?? "n/a";
      const duration = item.duration_seconds ?? "n/a";
      const errorText = item.error ? String(item.error).replace(/</g, "&lt;") : "";
      return `
        <tr>
          <td>${item.started_at || "n/a"}</td>
          <td>${item.triggered_by || "unknown"}</td>
          <td>${item.status || "unknown"}</td>
          <td>${outSet}</td>
          <td>${logs}</td>
          <td>${drift}</td>
          <td>${duration}</td>
          <td>${errorText}</td>
          <td><button class="inline-btn" data-run-id="${item.run_id || ""}">View</button></td>
        </tr>
      `;
    })
    .join("");

  historyTableWrap.innerHTML = `
    <table>
      <thead>
        <tr>
          <th>Started</th>
          <th>User</th>
          <th>Status</th>
          <th>Output Set</th>
          <th>Logs</th>
          <th>Drift</th>
          <th>Duration (s)</th>
          <th>Error</th>
          <th>Detail</th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>
  `;

  historyTableWrap.querySelectorAll("button[data-run-id]").forEach((button) => {
    button.addEventListener("click", () => {
      const runId = button.getAttribute("data-run-id");
      if (runId) {
        loadRunDetail(runId).catch((error) => {
          runStatus.textContent = `Run detail failed: ${error.message}`;
        });
      }
    });
  });
}

function renderRunDetail(payload) {
  const run = payload.run || {};
  const artifacts = payload.artifacts || [];
  const summary = run.summary || {};

  const artifactRows = artifacts
    .map((item) => {
      const status = item.exists ? "Available" : "Missing";
      return `<tr><td>${item.name}</td><td>${status}</td><td>${item.path}</td></tr>`;
    })
    .join("");

  runDetailWrap.innerHTML = `
    <div class="detail-card">
      <p><strong>Run ID:</strong> ${run.run_id || "n/a"}</p>
      <p><strong>Status:</strong> ${run.status || "n/a"}</p>
      <p><strong>Triggered By:</strong> ${run.triggered_by || "n/a"} (${run.role || "n/a"})</p>
      <p><strong>Started:</strong> ${run.started_at || "n/a"}</p>
      <p><strong>Duration:</strong> ${run.duration_seconds ?? "n/a"}s</p>
      <p><strong>Logs:</strong> ${summary.logs_count ?? "n/a"} | <strong>Drift:</strong> ${summary.drift_count ?? "n/a"}</p>
    </div>
    <div style="margin-top:0.7rem;">
      <table>
        <thead><tr><th>Artifact</th><th>Status</th><th>Path</th></tr></thead>
        <tbody>${artifactRows}</tbody>
      </table>
    </div>
  `;
}

async function loadRunDetail(runId) {
  const detail = await fetchJSON(`/api/run-history/${encodeURIComponent(runId)}`);
  renderRunDetail(detail);
}

function updateJobProgress(progress, stage) {
  const clamped = Math.max(0, Math.min(100, Number(progress) || 0));
  jobProgressBar.style.width = `${clamped}%`;
  jobStage.textContent = stage || "Working...";
}

async function pollJobUntilDone(jobId) {
  activeJobId = jobId;
  while (activeJobId === jobId) {
    const job = await fetchJSON(`/api/jobs/${encodeURIComponent(jobId)}`);
    updateJobProgress(job.progress, `${job.stage} (${job.progress}%)`);

    if (job.status === "completed") {
      runStatus.textContent = "Pipeline job completed. Dashboard refreshed.";
      await refreshDashboard();
      if (job.run_id) {
        await loadRunDetail(job.run_id);
      }
      return;
    }

    if (job.status === "failed") {
      runStatus.textContent = `Pipeline failed: ${job.error || "Unknown error"}`;
      await refreshDashboard();
      return;
    }

    await new Promise((resolve) => setTimeout(resolve, 1500));
  }
}

function applyRoleState() {
  if (!currentUser) {
    authBadge.textContent = "Not logged in";
    runBtn.disabled = true;
    refreshBtn.disabled = true;
    downloadPdfBtn.disabled = true;
    downloadBundleBtn.disabled = true;
    updateJobProgress(0, "No active job.");
    return;
  }

  authBadge.textContent = `${currentUser.username} (${currentUser.role})`;
  refreshBtn.disabled = false;
  downloadPdfBtn.disabled = false;
  downloadBundleBtn.disabled = false;
  runBtn.disabled = !(currentUser.role === "admin" || currentUser.role === "analyst");
}

function initializePanelTilt() {
  document.querySelectorAll(".panel").forEach((panel) => {
    panel.addEventListener("mousemove", (event) => {
      const rect = panel.getBoundingClientRect();
      const x = (event.clientX - rect.left) / rect.width;
      const y = (event.clientY - rect.top) / rect.height;
      const rotateY = (x - 0.5) * 3.6;
      const rotateX = (0.5 - y) * 3.6;
      panel.style.transform = `perspective(900px) rotateX(${rotateX}deg) rotateY(${rotateY}deg)`;
    });

    panel.addEventListener("mouseleave", () => {
      panel.style.transform = "perspective(900px) rotateX(0deg) rotateY(0deg)";
    });
  });
}

async function loadOutputSets() {
  const data = await fetchJSON("/api/output-sets");
  outputSetSelect.innerHTML = data.output_sets
    .map((setName) => `<option value="${setName}">${setName}</option>`)
    .join("");
}

async function refreshDashboard() {
  if (!authToken) {
    return;
  }

  const outputSet = outputSetSelect.value || "outputs";

  const [summary, artifacts, mappings, report, history] = await Promise.all([
    fetchJSON(`/api/summary?output_set=${encodeURIComponent(outputSet)}`),
    fetchJSON(`/api/artifacts?output_set=${encodeURIComponent(outputSet)}`),
    fetchJSON(`/api/mappings?output_set=${encodeURIComponent(outputSet)}&limit=20`),
    fetchJSON(`/api/report?output_set=${encodeURIComponent(outputSet)}`),
    fetchJSON("/api/run-history?limit=15"),
  ]);

  animateMetric(controlsCount, summary.controls_count);
  animateMetric(logsCountMetric, summary.logs_count);
  animateMetric(driftCount, summary.drift_count);
  animateMetric(hitlCount, summary.hitl_required_count);

  renderChart(summary.logs_count, summary.drift_count);
  renderArtifacts(artifacts.artifacts);
  renderMappings(mappings.items);
  renderHistory(history.items || []);
  reportText.textContent = report.report_markdown;
}

async function runPipeline() {
  runBtn.disabled = true;
  runStatus.textContent = "Submitting job...";
  updateJobProgress(3, "Queued");

  try {
    const payload = {
      logs_count: Number(logsCountInput.value),
      similarity_threshold: Number(similarityThresholdInput.value),
      output_set: outputSetSelect.value || "outputs",
    };

    const queued = await fetchJSON("/api/run-pipeline", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    runStatus.textContent = `Job queued: ${queued.job_id}`;
    await pollJobUntilDone(queued.job_id);
  } catch (error) {
    runStatus.textContent = `Failed: ${error.message}`;
  } finally {
    applyRoleState();
  }
}

async function handleLogin(event) {
  event.preventDefault();
  runStatus.textContent = "Authenticating...";

  try {
    const payload = {
      username: usernameInput.value.trim(),
      password: passwordInput.value,
    };
    const session = await fetchJSON("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    authToken = session.access_token;
    currentUser = { username: session.username, role: session.role };
    applyRoleState();
    await loadOutputSets();
    await refreshDashboard();
    runStatus.textContent = "Login successful.";
  } catch (error) {
    authToken = "";
    currentUser = null;
    applyRoleState();
    runStatus.textContent = `Login failed: ${error.message}`;
  }
}

function handleLogout() {
  activeJobId = "";
  authToken = "";
  currentUser = null;
  outputSetSelect.innerHTML = "";
  historyTableWrap.innerHTML = "";
  runDetailWrap.innerHTML = "Select a run from history to inspect artifacts and metrics.";
  reportText.textContent = "Login required.";
  applyRoleState();
  runStatus.textContent = "Logged out.";
}

refreshBtn.addEventListener("click", () => {
  refreshDashboard().catch((error) => {
    runStatus.textContent = `Refresh failed: ${error.message}`;
  });
});

outputSetSelect.addEventListener("change", () => {
  refreshDashboard().catch((error) => {
    runStatus.textContent = `Refresh failed: ${error.message}`;
  });
});

runBtn.addEventListener("click", runPipeline);
loginForm.addEventListener("submit", handleLogin);
logoutBtn.addEventListener("click", handleLogout);
downloadPdfBtn.addEventListener("click", async () => {
  try {
    const outputSet = outputSetSelect.value || "outputs";
    await downloadWithAuth(
      `/api/export/report.pdf?output_set=${encodeURIComponent(outputSet)}`,
      `${outputSet}_compliance_report.pdf`
    );
    runStatus.textContent = "Report PDF downloaded.";
  } catch (error) {
    runStatus.textContent = `Export failed: ${error.message}`;
  }
});
downloadBundleBtn.addEventListener("click", async () => {
  try {
    const outputSet = outputSetSelect.value || "outputs";
    await downloadWithAuth(
      `/api/export/csv-bundle?output_set=${encodeURIComponent(outputSet)}`,
      `${outputSet}_grc_bundle.zip`
    );
    runStatus.textContent = "CSV bundle downloaded.";
  } catch (error) {
    runStatus.textContent = `Export failed: ${error.message}`;
  }
});

(async function init() {
  initializePanelTilt();
  applyRoleState();
  try {
    runStatus.textContent = "Login required. Use demo_admin / GrcAI_Demo@2026 for live demo.";
  } catch (error) {
    runStatus.textContent = `Startup error: ${error.message}`;
  }
})();
