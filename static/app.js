// State Management
let authToken = "";
let currentUser = null;
let activeJobId = "";
let chart = null;
let currentMappings = [];
let selectedMapping = null;

// Tab Configurations
const tabs = {
  overview: {
    title: "Compliance Cockpit",
    subtitle: "Real-time telemetry of security drift, NIST mapping coverage, and file audits."
  },
  mappings: {
    title: "Mappings & HITL Verification",
    subtitle: "Resolve low-confidence SBERT predictions and authorize policy alignments."
  },
  report: {
    title: "Compliance Drift Report",
    subtitle: "Review and export official, audit-ready compliance analysis evidence."
  },
  history: {
    title: "Job Run Audit History",
    subtitle: "Inspect execution metrics, configurations, and job output datasets."
  },
  instructions: {
    title: "System Operations Manual",
    subtitle: "Operational documentation, pipeline architectures, and quick-start instructions."
  }
};

// UI Selectors
const appContainer = document.getElementById("appContainer");
const loginScreen = document.getElementById("loginScreen");
const loginForm = document.getElementById("loginForm");
const usernameInput = document.getElementById("username");
const passwordInput = document.getElementById("password");

const navItems = document.querySelectorAll(".nav-item");
const tabContents = document.querySelectorAll(".tab-content");
const tabTitle = document.getElementById("tabTitle");
const tabSubtitle = document.getElementById("tabSubtitle");

const outputSetSelect = document.getElementById("outputSetSelect");
const refreshBtn = document.getElementById("refreshBtn");
const runBtn = document.getElementById("runBtn");
const runStatus = document.getElementById("runStatus");
const jobCard = document.getElementById("jobCard");
const jobProgressBar = document.getElementById("jobProgressBar");
const jobStage = document.getElementById("jobStage");
const jobProgressText = document.getElementById("jobProgressText");
const jobStatusMsg = document.getElementById("jobStatusMsg");

const logsCountInput = document.getElementById("logsCount");
const similarityThresholdInput = document.getElementById("similarityThreshold");
const logoutBtn = document.getElementById("logoutBtn");

const userAvatar = document.getElementById("userAvatar");
const userDisplayName = document.getElementById("userDisplayName");
const userRoleBadge = document.getElementById("userRoleBadge");

// Metric cards
const controlsCount = document.getElementById("controlsCount");
const logsCountMetric = document.getElementById("logsCountMetric");
const driftCount = document.getElementById("driftCount");
const hitlCount = document.getElementById("hitlCount");
const driftRatePercent = document.getElementById("driftRatePercent");

const artifactsTableWrap = document.getElementById("artifactsTableWrap");
const mappingsList = document.getElementById("mappingsList");

// HITL Editor selectors
const hitlEditorEmpty = document.getElementById("hitlEditorEmpty");
const hitlEditorContent = document.getElementById("hitlEditorContent");
const hitlDetailRawLog = document.getElementById("hitlDetailRawLog");
const hitlDetailStatus = document.getElementById("hitlDetailStatus");
const hitlSuggestionsList = document.getElementById("hitlSuggestionsList");
const overrideControlId = document.getElementById("overrideControlId");
const overrideMitreId = document.getElementById("overrideMitreId");
const overrideNotes = document.getElementById("overrideNotes");
const btnHitlAccept = document.getElementById("btnHitlAccept");
const btnHitlSubmit = document.getElementById("btnHitlSubmit");

// Report selectors
const reportRenderedHtml = document.getElementById("reportRenderedHtml");
const reportDriftStatusBadge = document.getElementById("reportDriftStatusBadge");
const reportMetaTime = document.getElementById("reportMetaTime");
const reportMetaControls = document.getElementById("reportMetaControls");
const reportMetaAnomalies = document.getElementById("reportMetaAnomalies");
const reportMetaPending = document.getElementById("reportMetaPending");
const downloadPdfBtn = document.getElementById("downloadPdfBtn");
const downloadBundleBtn = document.getElementById("downloadBundleBtn");

// History selectors
const historyTableWrap = document.getElementById("historyTableWrap");
const runDetailWrap = document.getElementById("runDetailWrap");

// ==========================================
// Toast System
// ==========================================
function showToast(message, type = "info") {
  const container = document.getElementById("toastContainer");
  const toast = document.createElement("div");
  toast.className = `toast toast-${type}`;
  
  let icon = "info";
  if (type === "success") icon = "check-circle";
  if (type === "error") icon = "x-circle";
  if (type === "warning") icon = "alert-triangle";
  
  toast.innerHTML = `
    <i data-lucide="${icon}"></i>
    <span>${message}</span>
  `;
  
  container.appendChild(toast);
  lucide.createIcons();
  
  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transform = "translateY(-15px) scale(0.95)";
    toast.style.transition = "all 0.3s ease";
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

// ==========================================
// API Helpers
// ==========================================
async function fetchJSON(url, options = {}) {
  const headers = options.headers ? { ...options.headers } : {};
  if (authToken) {
    headers.Authorization = `Bearer ${authToken}`;
  }

  const response = await fetch(url, { ...options, headers });
  if (!response.ok) {
    const detail = await response.text();
    let parsedDetail = detail;
    try {
      const jsonDetail = JSON.parse(detail);
      parsedDetail = jsonDetail.detail || detail;
    } catch(e) {}
    throw new Error(parsedDetail || `Request failed: ${response.status}`);
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

// ==========================================
// Metric Counter Animation
// ==========================================
function animateMetric(element, nextValue) {
  const target = Number(nextValue) || 0;
  const current = Number((element.textContent || "0").replace(/,/g, "")) || 0;
  const durationMs = 450;
  const start = performance.now();

  function step(timestamp) {
    const t = Math.min((timestamp - start) / durationMs, 1);
    const eased = 1 - Math.pow(1 - t, 3); // Cubic Ease Out
    const value = Math.round(current + (target - current) * eased);
    element.textContent = value.toLocaleString();
    if (t < 1) {
      requestAnimationFrame(step);
    }
  }

  requestAnimationFrame(step);
}

// ==========================================
// Chart.js Configuration
// ==========================================
function updateChart(totalLogs, driftLogs) {
  const normalLogs = Math.max(totalLogs - driftLogs, 0);
  const driftRate = totalLogs > 0 ? ((driftLogs / totalLogs) * 100).toFixed(1) : "0.0";
  driftRatePercent.textContent = `${driftRate}%`;

  const ctx = document.getElementById("driftChart").getContext("2d");
  
  if (chart) {
    chart.destroy();
  }

  chart = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: ["Compliant Operations", "Drift Anomalies"],
      datasets: [
        {
          data: [normalLogs, driftLogs],
          backgroundColor: ["#00b2c8", "#ff7a1a"],
          hoverBackgroundColor: ["#00cfe8", "#ff933b"],
          borderWidth: 1,
          borderColor: "#0d1527",
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: "80%",
      animation: {
        duration: 800,
        easing: "easeOutQuart",
      },
      plugins: {
        legend: {
          display: true,
          position: "bottom",
          labels: {
            color: "#8ca3c7",
            font: {
              family: "Space Grotesk",
              size: 11
            },
            padding: 15
          },
        },
        tooltip: {
          backgroundColor: "#0d1527",
          borderColor: "rgba(129, 170, 225, 0.15)",
          borderWidth: 1,
          titleColor: "#f0f5ff",
          bodyColor: "#8ca3c7",
          titleFont: { family: "Space Grotesk" },
          bodyFont: { family: "Space Grotesk" }
        }
      },
    },
  });
}

// ==========================================
// Render Layout Functions
// ==========================================
function renderArtifacts(artifacts) {
  if (!artifacts || !artifacts.length) {
    artifactsTableWrap.innerHTML = "<p style='padding: 1rem; text-align: center; color: var(--muted);'>No artifacts found.</p>";
    return;
  }

  const rows = artifacts
    .map((item) => {
      const statusBadge = item.exists 
        ? `<span class="badge badge-success"><i data-lucide="check-circle-2"></i> Ready</span>`
        : `<span class="badge badge-neutral"><i data-lucide="help-circle"></i> Missing</span>`;
      const sizeKb = (item.size_bytes / 1024).toFixed(2);
      
      return `
        <tr>
          <td style="font-weight: 600; color: #fff;"><i data-lucide="file" style="width:14px; display:inline-block; vertical-align:middle; margin-right:4px;"></i> ${item.name}</td>
          <td>${statusBadge}</td>
          <td><code>${sizeKb} KB</code></td>
          <td style="font-family:'IBM Plex Mono', monospace; font-size:0.75rem; opacity:0.8;">${item.path}</td>
        </tr>
      `;
    })
    .join("");

  artifactsTableWrap.innerHTML = `
    <table>
      <thead>
        <tr><th>Artifact File</th><th>Status</th><th>Size</th><th>Path Target</th></tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>
  `;
  lucide.createIcons();
}

function renderMappingsList(mappings) {
  if (!mappings || !mappings.length) {
    mappingsList.innerHTML = "<div class='hitl-empty-state'><i data-lucide='inbox'></i><p>No drift mappings found in outputs.</p></div>";
    lucide.createIcons();
    return;
  }

  mappingsList.innerHTML = mappings
    .map((item, index) => {
      const isSelected = selectedMapping && selectedMapping.RawLog === item.RawLog;
      const selectClass = isSelected ? "selected" : "";
      
      const nistSim = item.selected_similarity || 0;
      const mitreSim = item.selected_mitre_similarity || 0;
      const needsHitl = item.hitl_required || item.mitre_hitl_required;
      
      let simClass = "similarity-high";
      if (needsHitl) simClass = "similarity-low";
      else if (nistSim < 0.8 || mitreSim < 0.8) simClass = "similarity-warn";

      const hitlBadge = needsHitl
        ? `<span class="hitl-status-badge hitl-status-required"><i data-lucide="alert-circle" style="width:11px;height:11px;"></i> Pending Review</span>`
        : `<span class="hitl-status-badge hitl-status-resolved"><i data-lucide="check-circle" style="width:11px;height:11px;"></i> Resolved</span>`;

      return `
        <article class="mapping-card-item ${selectClass}" data-index="${index}">
          <div class="mapping-item-meta" style="flex-wrap: wrap; gap: 0.3rem;">
            <span class="mapping-control-id" style="background: rgba(162,89,255,0.15); color: #c084fc;">NIST: ${item.selected_control_id || "UNKNOWN"}</span>
            <span class="mapping-control-id" style="background: rgba(255,122,26,0.15); color: #ff9d4d;">MITRE: ${item.selected_mitre_id || "UNKNOWN"}</span>
            <span class="mapping-similarity ${simClass}">NIST: ${nistSim.toFixed(2)} | MITRE: ${mitreSim.toFixed(2)}</span>
          </div>
          <div class="mapping-item-log">${item.RawLog}</div>
          <div style="display:flex; justify-content:space-between; align-items:center; margin-top:0.4rem;">
            <span style="font-size:0.75rem; color:var(--muted);"><i data-lucide="cpu" style="width:11px;height:11px;display:inline-block;vertical-align:middle;margin-right:2px;"></i> ${item.Resource || "Unknown"}</span>
            ${hitlBadge}
          </div>
        </article>
      `;
    })
    .join("");

  lucide.createIcons();

  // Add click events to mapping cards
  mappingsList.querySelectorAll(".mapping-card-item").forEach((card) => {
    card.addEventListener("click", () => {
      const idx = card.getAttribute("data-index");
      selectMappingItem(mappings[idx]);
    });
  });
}

function selectMappingItem(item) {
  selectedMapping = item;
  
  // Highlight selection
  document.querySelectorAll(".mapping-card-item").forEach((card, idx) => {
    if (currentMappings[idx] && currentMappings[idx].RawLog === item.RawLog) {
      card.classList.add("selected");
    } else {
      card.classList.remove("selected");
    }
  });

  // Populate editor
  hitlEditorEmpty.style.display = "none";
  hitlEditorContent.style.display = "block";

  hitlDetailRawLog.textContent = item.RawLog;
  
  const needsHitl = item.hitl_required || item.mitre_hitl_required;
  if (needsHitl) {
    hitlDetailStatus.className = "badge badge-warning";
    hitlDetailStatus.innerHTML = "<i data-lucide='alert-circle'></i> Pending Human Verification";
  } else {
    hitlDetailStatus.className = "badge badge-success";
    hitlDetailStatus.innerHTML = `<i data-lucide='check-circle-2'></i> Verified (NIST: ${item.hitl_decision || 'Auto'} | MITRE: ${item.mitre_hitl_decision || 'Auto'})`;
  }

  // Clear overrides form inputs
  overrideControlId.value = item.selected_control_id || "";
  if (overrideMitreId) {
    overrideMitreId.value = item.selected_mitre_id || "";
  }
  overrideNotes.value = needsHitl ? "" : (item.hitl_decision || item.mitre_hitl_decision || "");

  // Generate recommendation lists
  let suggestionsHtml = "";
  
  if (item.top_matches && item.top_matches.length) {
    suggestionsHtml += `<h4 style="font-size:0.75rem; color:var(--muted); text-transform:uppercase; margin-bottom:0.4rem;">NIST SP 800-53 Suggestions</h4>`;
    suggestionsHtml += item.top_matches
      .map((match, idx) => {
        return `
          <div class="rec-item nist-rec" data-control-id="${match.control_id}" style="border-left: 2px solid #a259ff; padding: 0.5rem; margin-bottom: 0.4rem; background: rgba(162, 89, 255, 0.05); border-radius: 4px; cursor: pointer;">
            <div class="rec-item-title">
              <span style="color:#fff; font-weight:600;">${idx+1}. ${match.control_id.toUpperCase()}</span> 
              <span style="color:var(--muted); font-size:0.75rem; margin-left:6px;">${match.title}</span>
            </div>
            <div class="rec-item-score" style="font-size:0.72rem; color:var(--accent);">Match: ${(match.similarity * 100).toFixed(1)}%</div>
          </div>
        `;
      })
      .join("");
  }
  
  if (item.mitre_top_matches && item.mitre_top_matches.length) {
    suggestionsHtml += `<h4 style="font-size:0.75rem; color:var(--muted); text-transform:uppercase; margin: 0.8rem 0 0.4rem 0;">MITRE ATT&CK Cloud Suggestions</h4>`;
    suggestionsHtml += item.mitre_top_matches
      .map((match, idx) => {
        return `
          <div class="rec-item mitre-rec" data-mitre-id="${match.technique_id}" style="border-left: 2px solid #ff7a1a; padding: 0.5rem; margin-bottom: 0.4rem; background: rgba(255, 122, 26, 0.05); border-radius: 4px; cursor: pointer;">
            <div class="rec-item-title">
              <span style="color:#fff; font-weight:600;">${idx+1}. ${match.technique_id}</span> 
              <span style="color:var(--muted); font-size:0.75rem; margin-left:6px;">${match.name}</span>
            </div>
            <div class="rec-item-score" style="font-size:0.72rem; color: #ff9d4d;">Match: ${(match.similarity * 100).toFixed(1)}%</div>
          </div>
        `;
      })
      .join("");
  }
  
  if (!suggestionsHtml) {
    suggestionsHtml = "<p style='font-size:0.8rem; color:var(--muted); padding:0.4rem;'>No match recommendations returned.</p>";
  }
  
  hitlSuggestionsList.innerHTML = suggestionsHtml;

  // Make recommendations clickable to pre-fill inputs
  hitlSuggestionsList.querySelectorAll(".nist-rec").forEach((rec) => {
    rec.addEventListener("click", () => {
      const cId = rec.getAttribute("data-control-id");
      overrideControlId.value = cId;
      showToast(`Selected suggested NIST control: ${cId.toUpperCase()}`, "info");
    });
  });

  hitlSuggestionsList.querySelectorAll(".mitre-rec").forEach((rec) => {
    rec.addEventListener("click", () => {
      const mId = rec.getAttribute("data-mitre-id");
      if (overrideMitreId) {
        overrideMitreId.value = mId;
        showToast(`Selected suggested MITRE Technique: ${mId}`, "info");
      }
    });
  });
  lucide.createIcons();
}

function renderHistory(historyItems) {
  if (!historyItems || !historyItems.length) {
    historyTableWrap.innerHTML = "<p style='padding: 1rem; text-align: center; color: var(--muted);'>No execution logs found.</p>";
    return;
  }

  const rows = historyItems
    .map((item) => {
      const outSet = item.params?.output_set || "n/a";
      const logs = item.params?.logs_count || "n/a";
      const drift = item.summary?.drift_count ?? "n/a";
      const duration = item.duration_seconds ? `${item.duration_seconds}s` : "n/a";
      
      let statusBadge = `<span class="badge badge-success"><i data-lucide="check"></i> Success</span>`;
      if (item.status === "failed") {
        statusBadge = `<span class="badge badge-danger"><i data-lucide="x"></i> Failed</span>`;
      } else if (item.status === "running") {
        statusBadge = `<span class="badge badge-warning"><i data-lucide="refresh-cw" class="spin"></i> Running</span>`;
      }

      return `
        <tr>
          <td style="font-size:0.8rem; color:#fff;">${formatTimestamp(item.started_at)}</td>
          <td>${statusBadge}</td>
          <td><code>${outSet}</code></td>
          <td>${logs}</td>
          <td style="font-weight:600; color:var(--accent);">${drift}</td>
          <td>${duration}</td>
          <td><button class="btn btn-secondary inline-btn" data-run-id="${item.run_id || ""}">Inspect</button></td>
        </tr>
      `;
    })
    .join("");

  historyTableWrap.innerHTML = `
    <table>
      <thead>
        <tr>
          <th>Execution Date</th>
          <th>Status</th>
          <th>Dataset Name</th>
          <th>Logs Ingested</th>
          <th>Drifts Flagged</th>
          <th>Time Taken</th>
          <th>Action</th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>
  `;
  lucide.createIcons();

  // Attach click listener to history rows
  historyTableWrap.querySelectorAll("button[data-run-id]").forEach((button) => {
    button.addEventListener("click", () => {
      const runId = button.getAttribute("data-run-id");
      if (runId) {
        loadRunDetail(runId).catch((error) => {
          showToast(`Detail inspect failed: ${error.message}`, "error");
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
      const statusBadge = item.exists 
        ? `<span class="badge badge-success" style="font-size:0.7rem; padding:0.1rem 0.4rem;">Exists</span>`
        : `<span class="badge badge-neutral" style="font-size:0.7rem; padding:0.1rem 0.4rem;">Missing</span>`;
      return `<tr><td><code>${item.name}</code></td><td>${statusBadge}</td><td style="font-size:0.72rem; color:var(--muted); font-family:monospace;">${item.path}</td></tr>`;
    })
    .join("");

  runDetailWrap.innerHTML = `
    <div class="detail-card">
      <div class="detail-header-item">
        <h3>Pipeline Run GUID</h3>
        <p>${run.run_id || "n/a"}</p>
      </div>

      <div class="detail-grid">
        <div class="detail-cell">
          <label>Triggered By</label>
          <span>${run.triggered_by || "n/a"} (${run.role || "n/a"})</span>
        </div>
        <div class="detail-cell">
          <label>Execution Status</label>
          <span>${(run.status || "n/a").toUpperCase()}</span>
        </div>
        <div class="detail-cell">
          <label>Execution Duration</label>
          <span>${run.duration_seconds ?? "n/a"}s</span>
        </div>
        <div class="detail-cell">
          <label>Output Dataset</label>
          <span>${summary.output_set || "n/a"}</span>
        </div>
        <div class="detail-cell">
          <label>NIST Control References</label>
          <span>${summary.controls_count ?? "n/a"} parsed</span>
        </div>
        <div class="detail-cell">
          <label>Log Scopes / Drifts</label>
          <span>${summary.logs_count ?? "n/a"} / ${summary.drift_count ?? "n/a"}</span>
        </div>
      </div>

      <h4 style="font-size:0.8rem; color:var(--muted); text-transform:uppercase; margin:1rem 0 0.4rem;">Dataset Output Files</h4>
      <div class="table-wrap" style="margin-bottom:0; background:rgba(0,0,0,0.2);">
        <table>
          <thead>
            <tr><th>Name</th><th>State</th><th>Location</th></tr>
          </thead>
          <tbody>${artifactRows}</tbody>
        </table>
      </div>
      ${run.error ? `<div style="margin-top:1rem; padding:0.8rem; background:rgba(239,68,68,0.08); border:1px solid rgba(239,68,68,0.2); border-radius:8px; color:var(--danger); font-size:0.82rem; font-family:monospace; word-break:break-all;"><strong>Execution Error:</strong> ${run.error}</div>` : ''}
    </div>
  `;
}

// ==========================================
// Dashboard Sync & Loading Actions
// ==========================================
async function loadOutputSets() {
  try {
    const data = await fetchJSON("/api/output-sets");
    outputSetSelect.innerHTML = data.output_sets
      .map((setName) => `<option value="${setName}">${setName}</option>`)
      .join("");
      
    // Set default value if 'outputs' exists
    if (data.output_sets.includes("outputs")) {
      outputSetSelect.value = "outputs";
    }
  } catch(error) {
    showToast(`Load datasets failed: ${error.message}`, "error");
  }
}

async function refreshDashboard() {
  if (!authToken) return;

  const outputSet = outputSetSelect.value || "outputs";
  
  // Set current similarity threshold label
  currentThresholdVal.textContent = similarityThresholdInput.value;

  try {
    // Show skeleton/loading state
    refreshBtn.disabled = true;
    
    const [summary, artifacts, mappings, report, history] = await Promise.all([
      fetchJSON(`/api/summary?output_set=${encodeURIComponent(outputSet)}`),
      fetchJSON(`/api/artifacts?output_set=${encodeURIComponent(outputSet)}`),
      fetchJSON(`/api/mappings?output_set=${encodeURIComponent(outputSet)}&limit=100`),
      fetchJSON(`/api/report?output_set=${encodeURIComponent(outputSet)}`),
      fetchJSON("/api/run-history?limit=15"),
    ]);

    // Animate telemetry panels
    animateMetric(controlsCount, summary.controls_count);
    animateMetric(logsCountMetric, summary.logs_count);
    animateMetric(driftCount, summary.drift_count);
    animateMetric(hitlCount, summary.hitl_required_count);

    // Update Telemetry Chart
    updateChart(summary.logs_count, summary.drift_count);

    // Render artifacts list
    renderArtifacts(artifacts.artifacts);

    // Render history and mappings
    currentMappings = mappings.items || [];
    renderMappingsList(currentMappings);
    renderHistory(history.items || []);

    // Render markdown report to beautiful HTML
    if (report && report.report_markdown) {
      reportRenderedHtml.innerHTML = marked.parse(report.report_markdown);
    } else {
      reportRenderedHtml.innerHTML = "<p style='color:var(--muted);'>No compliance report has been compiled yet. Run the pipeline.</p>";
    }

    // Set report metadata side pane
    if (summary.drift_count > 0) {
      reportDriftStatusBadge.className = "badge badge-danger";
      reportDriftStatusBadge.innerHTML = "<i data-lucide='alert-triangle'></i> DRIFT DETECTED";
    } else {
      reportDriftStatusBadge.className = "badge badge-success";
      reportDriftStatusBadge.innerHTML = "<i data-lucide='shield-check'></i> COMPLIANT";
    }

    reportMetaTime.textContent = new Date().toLocaleTimeString();
    reportMetaControls.textContent = summary.controls_count;
    reportMetaAnomalies.textContent = summary.drift_count;
    reportMetaPending.textContent = summary.hitl_required_count;

    // Reset HITL override editor side pane
    selectedMapping = null;
    hitlEditorContent.style.display = "none";
    hitlEditorEmpty.style.display = "flex";

    showToast("Telemetry dashboard synchronized successfully.", "success");
  } catch (error) {
    showToast(`Dashboard sync failed: ${error.message}`, "error");
  } finally {
    refreshBtn.disabled = false;
    lucide.createIcons();
  }
}

async function loadRunDetail(runId) {
  try {
    const detail = await fetchJSON(`/api/run-history/${encodeURIComponent(runId)}`);
    renderRunDetail(detail);
    showToast(`Loaded details for run: ${runId.substring(0, 8)}...`, "info");
  } catch (error) {
    showToast(`Load run details failed: ${error.message}`, "error");
  }
}

// ==========================================
// Pipeline Worker Interactions (Poller)
// ==========================================
function updateJobProgress(progress, stage, status) {
  const clamped = Math.max(0, Math.min(100, Number(progress) || 0));
  jobProgressBar.style.width = `${clamped}%`;
  jobProgressText.textContent = `${clamped}%`;
  jobStage.textContent = stage || "In Queue";
  
  if (status === "running") {
    jobStatusMsg.className = "job-status-text pulse";
    jobStatusMsg.innerHTML = `<i data-lucide="refresh-cw" class="spin"></i> ${stage}...`;
  } else if (status === "completed") {
    jobStatusMsg.className = "job-status-text";
    jobStatusMsg.style.color = "var(--success)";
    jobStatusMsg.innerHTML = `<i data-lucide="check-circle-2"></i> Pipeline executed successfully.`;
  } else if (status === "failed") {
    jobStatusMsg.className = "job-status-text";
    jobStatusMsg.style.color = "var(--danger)";
    jobStatusMsg.innerHTML = `<i data-lucide="x-circle"></i> Pipeline failed.`;
  }
  lucide.createIcons();
}

async function pollJobUntilDone(jobId) {
  activeJobId = jobId;
  jobCard.style.display = "block";
  runStatus.textContent = "Pipeline executing in background worker...";

  while (activeJobId === jobId) {
    try {
      const job = await fetchJSON(`/api/jobs/${encodeURIComponent(jobId)}`);
      updateJobProgress(job.progress, job.stage, job.status);

      if (job.status === "completed") {
        runStatus.textContent = "Pipeline completed successfully. Updating local workspace...";
        showToast("Compliance pipeline task succeeded.", "success");
        await refreshDashboard();
        if (job.run_id) {
          await loadRunDetail(job.run_id);
          // Switch to run history tab to show details
          switchTab("history");
        }
        
        // Hide job progress card after a small delay
        setTimeout(() => {
          jobCard.style.display = "none";
          runStatus.textContent = "Ready.";
        }, 5000);
        return;
      }

      if (job.status === "failed") {
        runStatus.textContent = `Pipeline failed: ${job.error || "Unknown error"}`;
        showToast(`Pipeline execution error: ${job.error}`, "error");
        await refreshDashboard();
        return;
      }
    } catch(err) {
      runStatus.textContent = `Polling error: ${err.message}`;
    }

    await new Promise((resolve) => setTimeout(resolve, 1500));
  }
}

async function runPipeline() {
  runBtn.disabled = true;
  runStatus.textContent = "Submitting pipeline configuration...";
  
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

    showToast("Pipeline job queued successfully.", "info");
    await pollJobUntilDone(queued.job_id);
  } catch (error) {
    runStatus.textContent = `Submission failed: ${error.message}`;
    showToast(`Execution failed: ${error.message}`, "error");
  } finally {
    applyRoleState();
  }
}

// ==========================================
// HITL Submission Override
// ==========================================
async function submitHitlResolution(controlId, mitreId, notes) {
  if (!selectedMapping) {
    showToast("No mapping item selected for resolution.", "warning");
    return;
  }
  
  const formattedControlId = controlId ? controlId.trim().toLowerCase() : "";
  const formattedMitreId = mitreId ? mitreId.trim() : "";
  
  if (!formattedControlId && !formattedMitreId) {
    showToast("Please assign a valid NIST Control ID or MITRE Technique ID.", "warning");
    return;
  }

  try {
    btnHitlSubmit.disabled = true;
    const outputSet = outputSetSelect.value || "outputs";
    
    const payload = {
      output_set: outputSet,
      raw_log: selectedMapping.RawLog,
      selected_control_id: formattedControlId || null,
      selected_mitre_id: formattedMitreId || null,
      hitl_decision: notes || "Human verified and matching framework mapping assigned"
    };

    const response = await fetchJSON("/api/mappings/resolve", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    showToast("HITL override applied and saved successfully.", "success");
    
    // Refresh dashboard data to sync mappings list and report content
    await refreshDashboard();
  } catch(error) {
    showToast(`Failed to save resolution: ${error.message}`, "error");
  } finally {
    btnHitlSubmit.disabled = false;
  }
}

// ==========================================
// Authentication State Management
// ==========================================
async function handleLogin(event) {
  event.preventDefault();
  runStatus.textContent = "Checking authorization...";

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
    
    // Transition UI
    loginScreen.classList.add("hidden");
    appContainer.classList.remove("blur-bg");
    
    showToast(`Authenticated as ${session.username}. Console loaded.`, "success");
    
    // Populate display profile
    userAvatar.textContent = session.username.charAt(0).toUpperCase();
    userDisplayName.textContent = session.username;
    userRoleBadge.textContent = session.role;

    applyRoleState();
    await loadOutputSets();
    await refreshDashboard();
  } catch (error) {
    authToken = "";
    currentUser = null;
    applyRoleState();
    showToast(`Authentication failed: ${error.message}`, "error");
  }
}

function handleLogout() {
  activeJobId = "";
  authToken = "";
  currentUser = null;
  
  // Transition UI
  loginScreen.classList.remove("hidden");
  appContainer.classList.add("blur-bg");
  
  outputSetSelect.innerHTML = "<option value='outputs'>outputs</option>";
  historyTableWrap.innerHTML = "";
  runDetailWrap.innerHTML = `
    <div style="color: var(--muted); padding: 2rem 1rem; text-align: center;">
      <i data-lucide="list" style="font-size: 2rem; margin-bottom: 0.5rem; color: rgba(129, 170, 225, 0.15); display: block;"></i>
      Select a pipeline run from history to view details.
    </div>
  `;
  reportRenderedHtml.innerHTML = "<p>Authentication Required.</p>";
  
  applyRoleState();
  showToast("Session disconnected. Logged out.", "info");
}

function applyRoleState() {
  if (!currentUser) {
    runBtn.disabled = true;
    refreshBtn.disabled = true;
    downloadPdfBtn.disabled = true;
    downloadBundleBtn.disabled = true;
    return;
  }

  refreshBtn.disabled = false;
  downloadPdfBtn.disabled = false;
  downloadBundleBtn.disabled = false;
  
  // Role verification: Analysts and Admins can trigger pipeline. Reviewers can only read/override HITL.
  const hasExecuteAccess = currentUser.role === "admin" || currentUser.role === "analyst";
  runBtn.disabled = !hasExecuteAccess;
}

// ==========================================
// Tabs Switching Navigation
// ==========================================
function switchTab(tabId) {
  // Update nav active classes
  navItems.forEach((item) => {
    if (item.getAttribute("data-tab") === tabId) {
      item.classList.add("active");
    } else {
      item.classList.remove("active");
    }
  });

  // Show/Hide tab content panels
  tabContents.forEach((content) => {
    if (content.id === `tab-${tabId}`) {
      content.classList.add("active");
    } else {
      content.classList.remove("active");
    }
  });

  // Update top title titles
  if (tabs[tabId]) {
    tabTitle.textContent = tabs[tabId].title;
    tabSubtitle.textContent = tabs[tabId].subtitle;
  }
}

// ==========================================
// Utilities
// ==========================================
function formatTimestamp(isoString) {
  if (!isoString) return "n/a";
  try {
    const d = new Date(isoString);
    return d.toLocaleString();
  } catch(e) {
    return isoString;
  }
}

// ==========================================
// Event Listeners Initialization
// ==========================================
navItems.forEach((item) => {
  item.addEventListener("click", () => {
    const tabId = item.getAttribute("data-tab");
    switchTab(tabId);
  });
});

refreshBtn.addEventListener("click", () => {
  refreshDashboard();
});

outputSetSelect.addEventListener("change", () => {
  refreshDashboard();
});

runBtn.addEventListener("click", runPipeline);
loginForm.addEventListener("submit", handleLogin);
logoutBtn.addEventListener("click", handleLogout);

// HITL Overrides Buttons
btnHitlAccept.addEventListener("click", () => {
  if (!selectedMapping) return;
  const topControlId = selectedMapping.top_matches && selectedMapping.top_matches[0]
    ? selectedMapping.top_matches[0].control_id
    : "";
  const topMitreId = selectedMapping.mitre_top_matches && selectedMapping.mitre_top_matches[0]
    ? selectedMapping.mitre_top_matches[0].technique_id
    : "";
    
  if (topControlId || topMitreId) {
    if (topControlId) overrideControlId.value = topControlId;
    if (topMitreId && overrideMitreId) overrideMitreId.value = topMitreId;
    submitHitlResolution(topControlId, topMitreId, "Accepted SBERT model recommendation");
  } else {
    showToast("No recommendation matches to accept.", "warning");
  }
});

btnHitlSubmit.addEventListener("click", () => {
  const mitreVal = overrideMitreId ? overrideMitreId.value : "";
  submitHitlResolution(overrideControlId.value, mitreVal, overrideNotes.value);
});

// Download/Export Files
downloadPdfBtn.addEventListener("click", async () => {
  try {
    const outputSet = outputSetSelect.value || "outputs";
    showToast("Generating compliance report PDF...", "info");
    await downloadWithAuth(
      `/api/export/report.pdf?output_set=${encodeURIComponent(outputSet)}`,
      `${outputSet}_compliance_report.pdf`
    );
    showToast("Report PDF downloaded successfully.", "success");
  } catch (error) {
    showToast(`PDF Export failed: ${error.message}`, "error");
  }
});

downloadBundleBtn.addEventListener("click", async () => {
  try {
    const outputSet = outputSetSelect.value || "outputs";
    showToast("Compressing CSV artifact files...", "info");
    await downloadWithAuth(
      `/api/export/csv-bundle?output_set=${encodeURIComponent(outputSet)}`,
      `${outputSet}_grc_bundle.zip`
    );
    showToast("Evidence ZIP bundle downloaded successfully.", "success");
  } catch (error) {
    showToast(`ZIP Bundle download failed: ${error.message}`, "error");
  }
});

// App Startup Init
(function init() {
  // Clear any existing session settings
  applyRoleState();
  // Load Lucide Icons
  lucide.createIcons();
})();
