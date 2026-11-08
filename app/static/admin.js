const passwordForm = document.getElementById("passwordForm");
const passwordMessage = document.getElementById("passwordMessage");

passwordForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const newPassword = document.getElementById("newAdminPassword").value;
  const confirmation = document.getElementById("confirmAdminPassword").value;
  if (newPassword !== confirmation) {
    passwordMessage.textContent = "The new passwords do not match.";
    return;
  }

  const submitButton = passwordForm.querySelector("button[type='submit']");
  submitButton.disabled = true;
  passwordMessage.textContent = "Updating password...";
  try {
    const response = await fetch("/api/admin/password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ new_password: newPassword }),
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) {
      passwordMessage.textContent = result.detail || "Could not update the admin password.";
      submitButton.disabled = false;
      return;
    }

    passwordForm.reset();
    passwordMessage.textContent = "Password updated. Sign in again with your new password...";
    window.setTimeout(() => window.location.replace("/admin"), 500);
  } catch (error) {
    passwordMessage.textContent = `Could not update the admin password: ${error.message}`;
    submitButton.disabled = false;
  }
});

if (document.body.dataset.passwordChangeRequired !== "true") {
const targetForm = document.getElementById("targetForm");
const targetRows = document.getElementById("targetRows");
const targetMessage = document.getElementById("targetMessage");
const saveTargetBtn = document.getElementById("saveTargetBtn");
const clearTargetBtn = document.getElementById("clearTargetBtn");
const autoRetentionDays = document.getElementById("autoRetentionDays");
const saveRetentionBtn = document.getElementById("saveRetentionBtn");
const retentionDays = document.getElementById("retentionDays");
const pruneBtn = document.getElementById("pruneBtn");
const vacuumBtn = document.getElementById("vacuumBtn");
const maintenanceMessage = document.getElementById("maintenanceMessage");
const helpBtn = document.getElementById("helpBtn");
const closeHelpBtn = document.getElementById("closeHelpBtn");
const helpDrawer = document.getElementById("helpDrawer");
const helpBackdrop = document.getElementById("helpBackdrop");

let editingHost = null;
let targets = [];

function escapeHTML(value) {
  return String(value ?? "").replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  })[character]);
}

function setHelpOpen(open) {
  helpDrawer.classList.toggle("open", open);
  helpDrawer.setAttribute("aria-hidden", open ? "false" : "true");
  helpBackdrop.classList.toggle("hidden", !open);
}

function numberOrNull(value) {
  if (value === "" || value === null || value === undefined) return null;
  const num = Number(value);
  return Number.isFinite(num) ? num : null;
}

function portsFromInput() {
  const value = document.getElementById("targetPorts").value.trim();
  if (!value) return [];
  return value
    .split(",")
    .map((port) => port.trim())
    .filter(Boolean)
    .map((port) => Number(port))
    .filter((port) => Number.isInteger(port));
}

function updateMtrPortState() {
  const port = document.getElementById("mtrPort");
  const isIcmp = document.getElementById("mtrProtocol").value === "icmp";
  port.disabled = isIcmp;
  port.classList.toggle("hidden", isIcmp);
  if (isIcmp) port.value = "";
  else if (!port.value) port.value = "443";
}

function updateEndpointPortState() {
  const port = document.getElementById("endpointPort");
  const isIcmp = document.getElementById("endpointProtocol").value === "icmp";
  port.disabled = isIcmp;
  port.classList.toggle("hidden", isIcmp);
  if (isIcmp) port.value = "";
}

function formPayload() {
  const endpointPort = numberOrNull(document.getElementById("endpointPort").value);
  const endpointCount = numberOrNull(document.getElementById("endpointCount").value);
  const dscpValue = numberOrNull(document.getElementById("dscpSelect").value);
  const mtrProtocol = document.getElementById("mtrProtocol").value;
  const mtrPort = numberOrNull(document.getElementById("mtrPort").value);
  return {
    host: document.getElementById("targetHost").value.trim(),
    label: document.getElementById("targetLabel").value.trim() || null,
    tcp_ports: portsFromInput(),
    mtr_protocol: mtrProtocol,
    mtr_port: mtrProtocol === "icmp" ? null : mtrPort,
    alert_latency_ms: numberOrNull(document.getElementById("thresholdLatency").value),
    alert_jitter_ms: numberOrNull(document.getElementById("thresholdJitter").value),
    alert_loss_pct: numberOrNull(document.getElementById("thresholdLoss").value),
    alert_path_change: document.getElementById("thresholdPathChange").checked,
    endpoint_probe_enabled: document.getElementById("endpointEnabled").checked,
    endpoint_probe_protocol: document.getElementById("endpointProtocol").value,
    endpoint_probe_count: endpointCount,
    endpoint_probe_port: endpointPort,
    dscp: dscpValue,
  };
}

function clearForm() {
  editingHost = null;
  targetForm.reset();
  document.getElementById("targetPorts").value = "";
  document.getElementById("mtrProtocol").value = "tcp";
  document.getElementById("mtrPort").value = "443";
  updateMtrPortState();
  document.getElementById("thresholdPathChange").checked = false;
  document.getElementById("endpointEnabled").checked = true;
  document.getElementById("endpointProtocol").value = "tcp";
  document.getElementById("endpointCount").value = "5";
  document.getElementById("endpointPort").value = "";
  updateEndpointPortState();
  document.getElementById("dscpSelect").value = "";
  document.getElementById("targetHost").disabled = false;
  saveTargetBtn.textContent = "Add Target";
}

async function loadTargets() {
  const res = await fetch("/api/targets");
  targets = await res.json();
  renderTargets();
}

async function loadRetentionSettings() {
  const res = await fetch("/api/settings/retention");
  if (!res.ok) return;
  const settings = await res.json();
  autoRetentionDays.value = settings.retention_days;
}

function renderTargets() {
  targetRows.innerHTML = "";
  targets.forEach((target) => {
    const row = document.createElement("div");
    row.className = "target-row";
    row.innerHTML = `
      <div>
        <strong>${escapeHTML(target.label)}</strong>
        <span>${escapeHTML(target.host)}</span>
      </div>
      <div class="target-thresholds">
        <span>TCP/TLS checks ${escapeHTML(target.tcp_ports.length ? target.tcp_ports.join(",") : "none")}</span>
        <span>MTR ${escapeHTML(target.effective_mtr.protocol)}${target.effective_mtr.protocol === "icmp" ? "" : `/${escapeHTML(target.effective_mtr.port)}`}</span>
        <span>Latency ${escapeHTML(target.alert_latency_ms ?? target.effective_alerts.latency_ms)} ms</span>
        <span>Jitter ${escapeHTML(target.alert_jitter_ms ?? target.effective_alerts.jitter_ms)} ms</span>
        <span>Loss ${escapeHTML(target.alert_loss_pct ?? target.effective_alerts.loss_pct)}%</span>
        <span>Path ${target.alert_path_change ?? target.effective_alerts.path_change ? "on" : "off"}</span>
        <span>Endpoint ${target.effective_endpoint_probe.enabled ? `${escapeHTML(target.effective_endpoint_probe.protocol)}/${escapeHTML(target.effective_endpoint_probe.port ?? "default")} x${escapeHTML(target.effective_endpoint_probe.count)}` : "off"}</span>
        <span>DSCP ${escapeHTML(target.dscp ?? "default")}${target.tos_byte !== null ? ` / TOS ${escapeHTML(target.tos_byte)}` : ""}</span>
      </div>
      <div class="target-actions">
        <button type="button" data-action="edit" data-host="${escapeHTML(target.host)}">Edit</button>
        <button type="button" class="danger" data-action="delete" data-host="${escapeHTML(target.host)}">Delete</button>
      </div>
    `;
    targetRows.appendChild(row);
  });
}

targetRows.addEventListener("click", async (event) => {
  const button = event.target.closest("button[data-action]");
  if (!button) return;
  const target = targets.find((item) => item.host === button.dataset.host);
  if (!target) return;

  if (button.dataset.action === "edit") {
    editingHost = target.host;
    document.getElementById("targetHost").value = target.host;
    document.getElementById("targetHost").disabled = true;
    document.getElementById("targetLabel").value = target.label;
    document.getElementById("targetPorts").value = target.tcp_ports.join(",");
    document.getElementById("mtrProtocol").value = target.mtr_protocol ?? target.effective_mtr.protocol;
    document.getElementById("mtrPort").value = (target.mtr_protocol ?? target.effective_mtr.protocol) === "icmp" ? "" : target.mtr_port ?? target.effective_mtr.port;
    updateMtrPortState();
    document.getElementById("thresholdLatency").value = target.alert_latency_ms ?? "";
    document.getElementById("thresholdJitter").value = target.alert_jitter_ms ?? "";
    document.getElementById("thresholdLoss").value = target.alert_loss_pct ?? "";
    document.getElementById("thresholdPathChange").checked = target.alert_path_change ?? target.effective_alerts.path_change;
    document.getElementById("endpointEnabled").checked = target.endpoint_probe_enabled ?? target.effective_endpoint_probe.enabled;
    document.getElementById("endpointProtocol").value = target.endpoint_probe_protocol ?? target.effective_endpoint_probe.protocol;
    document.getElementById("endpointCount").value = target.endpoint_probe_count ?? target.effective_endpoint_probe.count;
    document.getElementById("endpointPort").value = target.endpoint_probe_port ?? "";
    updateEndpointPortState();
    document.getElementById("dscpSelect").value = target.dscp ?? "";
    saveTargetBtn.textContent = "Update Target";
    targetMessage.textContent = `Editing ${target.host}`;
    return;
  }

  const deleteHistory = window.confirm(`Also delete historical data for ${target.host}? Choose OK to delete history, Cancel to keep history.`);
  if (!window.confirm(`Remove ${target.host} from monitoring?`)) return;

  const res = await fetch(`/api/targets/${encodeURIComponent(target.host)}?delete_history=${deleteHistory}`, { method: "DELETE" });
  const result = await res.json().catch(() => ({}));
  targetMessage.textContent = res.ok ? `${target.host} removed.${deleteHistory ? ` Deleted ${result.history_deleted} runs.` : ""}` : result.detail || "Delete failed";
  clearForm();
  await loadTargets();
});

targetForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const payload = formPayload();
  const url = editingHost ? `/api/targets/${encodeURIComponent(editingHost)}` : "/api/targets";
  const method = editingHost ? "PUT" : "POST";
  const res = await fetch(url, {
    method,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const result = await res.json().catch(() => ({}));
  if (!res.ok) {
    targetMessage.textContent = result.detail || "Save failed";
    return;
  }
  targetMessage.textContent = `${result.host} saved.`;
  clearForm();
  await loadTargets();
});

clearTargetBtn.addEventListener("click", clearForm);
document.getElementById("mtrProtocol").addEventListener("change", updateMtrPortState);
document.getElementById("endpointProtocol").addEventListener("change", updateEndpointPortState);
helpBtn.addEventListener("click", () => setHelpOpen(true));
closeHelpBtn.addEventListener("click", () => setHelpOpen(false));
helpBackdrop.addEventListener("click", () => setHelpOpen(false));
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") setHelpOpen(false);
});

pruneBtn.addEventListener("click", async () => {
  const days = Number(retentionDays.value || 30);
  if (!window.confirm(`Delete history older than ${days} days?`)) return;
  maintenanceMessage.textContent = "Pruning old history...";
  const res = await fetch(`/api/maintenance/prune?retention_days=${encodeURIComponent(days)}`, { method: "POST" });
  const result = await res.json().catch(() => ({}));
  maintenanceMessage.textContent = res.ok ? `Pruned ${result.deleted_runs || 0} runs.` : result.detail || "Prune failed";
});

saveRetentionBtn.addEventListener("click", async () => {
  const days = Number(autoRetentionDays.value || 30);
  const res = await fetch("/api/settings/retention", {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ retention_days: days }),
  });
  const result = await res.json().catch(() => ({}));
  maintenanceMessage.textContent = res.ok
    ? `Automatic purge will keep ${result.retention_days} days of history (runs every ${result.prune_interval_hours} hours).`
    : result.detail || "Failed to save auto purge setting";
});

vacuumBtn.addEventListener("click", async () => {
  if (!window.confirm("Compact the SQLite database now? This may pause the app briefly.")) return;
  maintenanceMessage.textContent = "Compacting database...";
  const res = await fetch("/api/maintenance/vacuum", { method: "POST" });
  const result = await res.json().catch(() => ({}));
  maintenanceMessage.textContent = res.ok ? `Database compacted (${result.db_size_bytes || 0} bytes).` : result.detail || "Compact failed";
});

loadTargets();
loadRetentionSettings();
clearForm();
}
