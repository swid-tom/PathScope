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

function alertIdFromLocation() {
  const alertId = Number(new URLSearchParams(window.location.search).get("alert_id"));
  return Number.isSafeInteger(alertId) && alertId > 0 ? alertId : null;
}

async function loadAlertHistory(focusAlertId = null) {
  const openAlertIds = new Set(
    [...alertsPageList.querySelectorAll(".alert-item")]
      .filter((row) => row.querySelector("details.alert-details")?.open)
      .map((row) => row.dataset.alertId)
  );

  const res = await fetch(`/api/alerts?limit=${encodeURIComponent(alertLimit.value)}`);
  const alerts = await res.json();
  if (focusAlertId && !alerts.some((alert) => alert.id === focusAlertId)) {
    const targetRes = await fetch(`/api/alerts?limit=1&alert_id=${encodeURIComponent(focusAlertId)}`);
    const [targetAlert] = await targetRes.json();
    if (targetAlert) alerts.push(targetAlert);
  }
  alerts.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
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
    const isFocusedAlert = alert.id === focusAlertId;
    const presentation = window.PathScopeAlertDetails.presentAlert(alert);
    row.className = `alert-item ${presentation.severityClass}${isFocusedAlert ? " alert-highlight" : ""}`;
    row.dataset.alertId = String(alert.id);
    row.id = `alert-${alert.id}`;
    if (isFocusedAlert) row.tabIndex = -1;
    const detailsOpen = isFocusedAlert || openAlertIds.has(String(alert.id));
    const eventLink = alert.kind === "path_change" && alert.run_id
      ? `<a class="alert-event-link" href="/events?event_id=${encodeURIComponent(alert.run_id)}">View event details</a>`
      : "";
    row.innerHTML = `
      <div class="alert-row-main">
        <strong>${escapeHTML(presentation.title)}</strong>
        <span class="alert-severity alert-severity-${presentation.severityClass}">${escapeHTML(presentation.severityLabel)}</span>
        <span>${escapeHTML(alert.target)}</span>
        <small>${escapeHTML(fmtEastern(alert.timestamp))}</small>
      </div>
      <p class="alert-summary">${escapeHTML(presentation.summary)}</p>
      <small class="alert-meta">Check #${escapeHTML(alert.run_id ?? "-")}</small>
      ${eventLink ? `<div class="alert-row-actions">${eventLink}</div>` : ""}
      ${window.PathScopeAlertDetails.renderDetails(alert.details, alert.kind, detailsOpen)}
    `;
    fragment.appendChild(row);
  });
  alertsPageList.replaceChildren(fragment);
  if (focusAlertId) {
    const focusedAlert = document.getElementById(`alert-${focusAlertId}`);
    if (focusedAlert) {
      focusedAlert.scrollIntoView({ behavior: "smooth", block: "center" });
      focusedAlert.focus({ preventScroll: true });
    }
  }
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
loadAlertHistory(alertIdFromLocation());
