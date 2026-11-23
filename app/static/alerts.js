const alertsPageList = document.getElementById("alertsPageList");
const alertLimit = document.getElementById("alertLimit");
const clearAlertsBtn = document.getElementById("clearAlertsBtn");
const helpBtn = document.getElementById("helpBtn");
const closeHelpBtn = document.getElementById("closeHelpBtn");
const helpDrawer = document.getElementById("helpDrawer");
const helpBackdrop = document.getElementById("helpBackdrop");
const refreshAlertsBtn = document.getElementById("refreshAlertsBtn");

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
    const addedHops = Array.isArray(details.added_hops) ? details.added_hops : [];
    const removedHops = Array.isArray(details.removed_hops) ? details.removed_hops : [];
    const renderPath = (hops, changedHops, direction) => {
      if (!hops.length) return `<span class="path-hops-none">none</span>`;
      const changedSet = new Set(changedHops);
      return hops
        .map((hop) => {
          if (!changedSet.has(hop)) {
            return `<span class="path-ip-neutral">${escapeHTML(hop)}</span>`;
          }
          return `<span class="path-ip path-ip-${direction}">${escapeHTML(hop)}</span>`;
        })
        .join('<span class="path-hop-arrow" aria-hidden="true"> &rarr; </span>');
    };
    const previous = renderPath(details.previous_path || [], removedHops, "removed");
    const current = renderPath(details.current_path || [], addedHops, "added");
    return `
      <details class="alert-details">
        <summary>Path change details</summary>
        <div class="path-change-meta"><strong>Previous run:</strong> ${escapeHTML(details.previous_run_id ?? "-")} ${escapeHTML(details.previous_timestamp || "")}</div>
        <div class="path-change-path"><strong>Previous path (${escapeHTML(details.previous_hop_count ?? 0)}):</strong> ${previous}</div>
        <div class="path-change-path"><strong>Current path (${escapeHTML(details.current_hop_count ?? 0)}):</strong> ${current}</div>
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
  const openAlertIds = new Set(
    [...alertsPageList.querySelectorAll(".alert-item")]
      .filter((row) => row.querySelector("details.alert-details")?.open)
      .map((row) => row.dataset.alertId)
  );

  const res = await fetch(`/api/alerts?limit=${encodeURIComponent(alertLimit.value)}`);
  const alerts = await res.json();
  if (!alerts.length) {
    alertsPageList.replaceChildren();
    const empty = document.createElement("div");
    empty.className = "alert-empty";
    empty.textContent = "No alerts recorded.";
    alertsPageList.appendChild(empty);
    return;
  }
  const fragment = document.createDocumentFragment();
  alerts.forEach((alert) => {
    const row = document.createElement("div");
    row.className = `alert-item ${alert.severity}`;
    row.dataset.alertId = String(alert.id);
    const detailsOpen = openAlertIds.has(String(alert.id));
    row.innerHTML = `
      <div class="alert-row-main">
        <strong>${escapeHTML(alert.kind)}</strong>
        <span>${escapeHTML(alert.severity)}</span>
        <span>${escapeHTML(alert.target)}</span>
        <small>${escapeHTML(fmtEastern(alert.timestamp))}</small>
      </div>
      <div>${escapeHTML(alert.message)}</div>
      <small>run_id: ${escapeHTML(alert.run_id ?? "-")}</small>
      ${renderDetails(alert.details).replace("<details class=\"alert-details\">", `<details class="alert-details"${detailsOpen ? " open" : ""}>`)}
    `;
    fragment.appendChild(row);
  });
  alertsPageList.replaceChildren(fragment);
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

refreshAlertsBtn.addEventListener("click", async () => {
  refreshAlertsBtn.disabled = true;
  refreshAlertsBtn.classList.add("refreshing");
  try {
    await loadAlertHistory();
  } finally {
    refreshAlertsBtn.disabled = false;
    refreshAlertsBtn.classList.remove("refreshing");
  }
});
loadAlertHistory();
