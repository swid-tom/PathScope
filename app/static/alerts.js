const alertsPageList = document.getElementById("alertsPageList");
const alertLimit = document.getElementById("alertLimit");
const clearAlertsBtn = document.getElementById("clearAlertsBtn");
const helpBtn = document.getElementById("helpBtn");
const closeHelpBtn = document.getElementById("closeHelpBtn");
const helpDrawer = document.getElementById("helpDrawer");
const helpBackdrop = document.getElementById("helpBackdrop");

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

function fmtEastern(timestamp) {
  if (!timestamp) return "-";
  return new Intl.DateTimeFormat("en-US", {
    timeZone: "America/New_York",
    month: "2-digit",
    day: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
    timeZoneName: "short",
  }).format(new Date(timestamp));
}

function renderDetails(details) {
  if (!details || !Object.keys(details).length) return "";
  if (details.current_path || details.previous_path) {
    const added = escapeHTML((details.added_hops || []).join(" -> ") || "none");
    const removed = escapeHTML((details.removed_hops || []).join(" -> ") || "none");
    const previous = escapeHTML((details.previous_path || []).join(" -> ") || "none");
    const current = escapeHTML((details.current_path || []).join(" -> ") || "none");
    return `
      <details class="alert-details">
        <summary>Path change details</summary>
        <div><strong>Previous run:</strong> ${escapeHTML(details.previous_run_id ?? "-")} ${escapeHTML(details.previous_timestamp || "")}</div>
        <div><strong>Previous path (${escapeHTML(details.previous_hop_count ?? 0)}):</strong> ${previous}</div>
        <div><strong>Current path (${escapeHTML(details.current_hop_count ?? 0)}):</strong> ${current}</div>
        <div><strong>Added hops:</strong> ${added}</div>
        <div><strong>Removed hops:</strong> ${removed}</div>
      </details>
    `;
  }

  const metricRows = Object.entries(details)
    .map(([key, value]) => {
      const renderedValue = value !== null && typeof value === "object" ? JSON.stringify(value) : value;
      return `<div><strong>${escapeHTML(key)}:</strong> ${escapeHTML(renderedValue)}</div>`;
    })
    .join("");
  return `<details class="alert-details"><summary>Metric details</summary>${metricRows}</details>`;
}

async function loadAlertHistory() {
  const res = await fetch(`/api/alerts?limit=${encodeURIComponent(alertLimit.value)}`);
  const alerts = await res.json();
  alertsPageList.innerHTML = "";
  if (!alerts.length) {
    alertsPageList.innerHTML = '<div class="alert-empty">No alerts recorded.</div>';
    return;
  }
  alerts.forEach((alert) => {
    const row = document.createElement("div");
    row.className = `alert-item ${alert.severity}`;
    row.innerHTML = `
      <div class="alert-row-main">
        <strong>${escapeHTML(alert.kind)}</strong>
        <span>${escapeHTML(alert.severity)}</span>
        <span>${escapeHTML(alert.target)}</span>
        <small>${escapeHTML(fmtEastern(alert.timestamp))}</small>
      </div>
      <div>${escapeHTML(alert.message)}</div>
      <small>run_id: ${escapeHTML(alert.run_id ?? "-")}</small>
      ${renderDetails(alert.details)}
    `;
    alertsPageList.appendChild(row);
  });
}

alertLimit.addEventListener("change", loadAlertHistory);
helpBtn.addEventListener("click", () => setHelpOpen(true));
closeHelpBtn.addEventListener("click", () => setHelpOpen(false));
helpBackdrop.addEventListener("click", () => setHelpOpen(false));
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") setHelpOpen(false);
});
clearAlertsBtn.addEventListener("click", async () => {
  if (!window.confirm("Clear all logged alerts? Monitoring history and probe data will remain.")) return;
  const res = await fetch("/api/alerts", { method: "DELETE" });
  const result = await res.json().catch(() => ({}));
  if (!res.ok) {
    window.alert(result.detail || "Failed to clear alerts");
    return;
  }
  await loadAlertHistory();
});
loadAlertHistory();
setInterval(loadAlertHistory, 30000);
