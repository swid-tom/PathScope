const targetSelect = document.getElementById("targetSelect");
const windowSelect = document.getElementById("windowSelect");
const customWindowControls = document.getElementById("customWindowControls");
const customStart = document.getElementById("customStart");
const customEnd = document.getElementById("customEnd");
const applyCustomWindow = document.getElementById("applyCustomWindow");
const exportBtn = document.getElementById("exportBtn");
const helpBtn = document.getElementById("helpBtn");
const closeHelpBtn = document.getElementById("closeHelpBtn");
const helpDrawer = document.getElementById("helpDrawer");
const helpBackdrop = document.getElementById("helpBackdrop");
const showUnknownHops = document.getElementById("showUnknownHops");
const statusCards = document.getElementById("statusCards");
const alertsList = document.getElementById("alertsList");
const toggleAlertsBtn = document.getElementById("toggleAlertsBtn");
const pathViz = document.getElementById("pathViz");
const pathHoverDetails = document.getElementById("pathHoverDetails");
const hopsTableBody = document.querySelector("#hopsTable tbody");

let latencyChart, hopCountChart;
let recentAlerts = [];
let alertsMinimized = false;
let draggedTarget = null;
let cardDragMoved = false;

const cardOrderKey = "pathscope.targetCardOrder";

const chartSeriesVariables = [
  "--series-latency",
  "--series-endpoint",
  "--series-jitter",
  "--series-loss",
  "--series-endpoint-loss",
  "--series-hops",
];

function themeColor(variable, fallback) {
  return getComputedStyle(document.documentElement).getPropertyValue(variable).trim() || fallback;
}

function chartSeriesColors() {
  return chartSeriesVariables.map((variable) => themeColor(variable, "#4287a5"));
}

function syncChartTheme() {
  const textColor = themeColor("--chart-text", "#e8eff7");
  const mutedColor = themeColor("--chart-muted", "#afbdd0");
  const gridColor = themeColor("--chart-grid", "rgba(175, 195, 220, 0.2)");
  const seriesColors = chartSeriesColors();

  [latencyChart, hopCountChart].filter(Boolean).forEach((chart) => {
    if (chart === latencyChart) {
      chart.data.datasets.forEach((dataset, index) => {
        dataset.borderColor = seriesColors[index];
        if (index === 4) dataset.backgroundColor = seriesColors[index];
      });
    } else {
      chart.data.datasets[0].borderColor = seriesColors[5];
    }
    chart.options.plugins.legend.labels.color = textColor;
    Object.entries(chart.options.scales).forEach(([axis, scale]) => {
      if (scale.ticks) scale.ticks.color = axis === "x" ? mutedColor : textColor;
      if (scale.title) scale.title.color = textColor;
      if (scale.grid && scale.grid.drawOnChartArea !== false) scale.grid.color = gridColor;
    });
    chart.update("none");
  });

}

function escapeHTML(value) {
  return String(value ?? "").replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  })[character]);
}

function fmt(n, digits = 1) {
  return n === null || n === undefined ? "-" : Number(n).toFixed(digits);
}

function getSavedCardOrder() {
  try {
    return JSON.parse(localStorage.getItem(cardOrderKey) || "[]");
  } catch {
    return [];
  }
}

function saveCardOrder() {
  const order = [...statusCards.querySelectorAll(".target-card")].map((card) => card.dataset.target);
  localStorage.setItem(cardOrderKey, JSON.stringify(order));
}

function applySavedCardOrder(data) {
  const order = getSavedCardOrder();
  if (!order.length) return data;
  const rank = new Map(order.map((target, index) => [target, index]));
  return [...data].sort((a, b) => {
    const aRank = rank.has(a.target) ? rank.get(a.target) : Number.MAX_SAFE_INTEGER;
    const bRank = rank.has(b.target) ? rank.get(b.target) : Number.MAX_SAFE_INTEGER;
    if (aRank !== bRank) return aRank - bRank;
    return a.target.localeCompare(b.target);
  });
}

function clearCardDragStyles() {
  statusCards.querySelectorAll(".target-card").forEach((card) => card.classList.remove("drag-over", "dragging"));
}

function setHelpOpen(open) {
  helpDrawer.classList.toggle("open", open);
  helpDrawer.setAttribute("aria-hidden", open ? "false" : "true");
  helpBackdrop.classList.toggle("hidden", !open);
}

function fmtEastern(timestamp, includeDate = true) {
  if (!timestamp) return "-";
  const date = new Date(timestamp);
  return new Intl.DateTimeFormat("en-US", {
    timeZone: "America/New_York",
    month: includeDate ? "2-digit" : undefined,
    day: includeDate ? "2-digit" : undefined,
    year: includeDate ? "numeric" : undefined,
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
    timeZoneName: includeDate ? "short" : undefined,
  }).format(date);
}

function customInputToIso(input) {
  if (!input.value) return null;
  return new Date(input.value).toISOString();
}

function rangeParams() {
  const params = new URLSearchParams({ window: windowSelect.value });
  if (windowSelect.value === "custom") {
    const startIso = customInputToIso(customStart);
    const endIso = customInputToIso(customEnd);
    if (startIso) params.set("start", startIso);
    if (endIso) params.set("end", endIso);
  }
  return params;
}

function updateCustomWindowVisibility() {
  if (windowSelect.value === "custom" && !customStart.value) {
    const end = new Date();
    const start = new Date(end.getTime() - 60 * 60 * 1000);
    customStart.value = start.toISOString().slice(0, 16);
    customEnd.value = end.toISOString().slice(0, 16);
  }
  customWindowControls.classList.toggle("hidden", windowSelect.value !== "custom");
}

function drawFallbackChart(canvas, labels, series) {
  const ratio = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  const width = Math.max(rect.width || 900, 320);
  const height = Math.max(rect.height || canvas.height || 220, 160);
  canvas.width = width * ratio;
  canvas.height = height * ratio;
  const ctx = canvas.getContext("2d");
  ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
  ctx.clearRect(0, 0, width, height);

  const values = series.flatMap((s) => s.data).filter((v) => v !== null && v !== undefined && Number.isFinite(Number(v))).map(Number);
  if (!values.length) {
    ctx.fillStyle = themeColor("--chart-muted", "#afbdd0");
    ctx.fillText("No chart data yet", 16, 28);
    return;
  }

  const padding = { left: 46, right: 16, top: 18, bottom: 30 };
  const min = Math.min(0, ...values);
  const max = Math.max(...values);
  const span = max === min ? 1 : max - min;
  const plotWidth = width - padding.left - padding.right;
  const plotHeight = height - padding.top - padding.bottom;

  ctx.strokeStyle = themeColor("--chart-grid", "rgba(175, 195, 220, 0.2)");
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(padding.left, padding.top);
  ctx.lineTo(padding.left, padding.top + plotHeight);
  ctx.lineTo(padding.left + plotWidth, padding.top + plotHeight);
  ctx.stroke();

  ctx.fillStyle = themeColor("--chart-muted", "#afbdd0");
  ctx.font = "12px sans-serif";
  ctx.fillText(max.toFixed(1), 4, padding.top + 4);
  ctx.fillText(min.toFixed(1), 4, padding.top + plotHeight);
  if (labels.length) {
    ctx.fillText(labels[0], padding.left, height - 8);
    ctx.fillText(labels[labels.length - 1], Math.max(padding.left, width - 76), height - 8);
  }

  series.forEach((s) => {
    ctx.strokeStyle = s.color;
    ctx.lineWidth = 2;
    ctx.beginPath();
    let started = false;
    s.data.forEach((value, index) => {
      if (value === null || value === undefined || !Number.isFinite(Number(value))) return;
      const x = padding.left + (labels.length <= 1 ? 0 : (index / (labels.length - 1)) * plotWidth);
      const y = padding.top + plotHeight - ((Number(value) - min) / span) * plotHeight;
      if (!started) {
        ctx.moveTo(x, y);
        started = true;
      } else {
        ctx.lineTo(x, y);
      }
    });
    ctx.stroke();
  });
}

async function loadStatusCards() {
  const res = await fetch("/api/latest");
  const data = applySavedCardOrder(await res.json());
  const fragment = document.createDocumentFragment();
  data.forEach((t) => {
    const lossClass = t.dest_loss_pct > 5 ? "bad" : (t.dest_loss_pct > 0 || t.dns_validation_warning) ? "warn" : "";
    const div = document.createElement("div");
    div.className = `card target-card ${lossClass} ${t.target === targetSelect.value ? "selected" : ""}`;
    div.dataset.target = t.target;
    div.draggable = true;
    div.tabIndex = 0;
    div.setAttribute("role", "button");
    div.setAttribute("aria-label", `Select ${t.label || t.target}`);
    div.addEventListener("click", async () => {
      if (cardDragMoved) return;
      targetSelect.value = t.target;
      await refreshAll();
    });
    div.addEventListener("dragstart", (event) => {
      draggedTarget = t.target;
      cardDragMoved = true;
      div.classList.add("dragging");
      event.dataTransfer.effectAllowed = "move";
      event.dataTransfer.setData("text/plain", t.target);
    });
    div.addEventListener("dragover", (event) => {
      event.preventDefault();
      if (draggedTarget && draggedTarget !== t.target) div.classList.add("drag-over");
    });
    div.addEventListener("dragleave", () => div.classList.remove("drag-over"));
    div.addEventListener("drop", (event) => {
      event.preventDefault();
      const source = statusCards.querySelector(`[data-target="${CSS.escape(draggedTarget || "")}"]`);
      if (!source || source === div) return;
      const cards = [...statusCards.querySelectorAll(".target-card")];
      const sourceIndex = cards.indexOf(source);
      const targetIndex = cards.indexOf(div);
      if (sourceIndex < targetIndex) div.after(source);
      else div.before(source);
      saveCardOrder();
      clearCardDragStyles();
    });
    div.addEventListener("dragend", () => {
      draggedTarget = null;
      clearCardDragStyles();
      setTimeout(() => { cardDragMoved = false; }, 0);
    });
    div.addEventListener("keydown", async (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        targetSelect.value = t.target;
        await refreshAll();
      }
    });
    div.innerHTML = `
      <div class="card-heading">
        <div>
          <h3>${escapeHTML(t.label || t.target)}</h3>
          <div class="target-hostname">${escapeHTML(t.target)}</div>
        </div>
        <span class="quality-badge ${escapeHTML(String(t.quality?.grade || "").toLowerCase())}">${escapeHTML(t.quality?.score ?? "-")} ${escapeHTML(t.quality?.grade || "")}</span>
      </div>
      <div class="row"><span>Resolved IP</span><b>${escapeHTML(t.resolved_ip || "-")}</b></div>
      ${t.dns_sinkhole_match ? `<div class="row warn-text"><span>DNS security range</span><b>${escapeHTML(t.dns_sinkhole_range)}</b></div>` : ""}
      ${t.dns_validation_warning ? `<div class="row warn-text"><span>DNS warning</span><b>${escapeHTML(t.dns_validation_warning)}</b></div>` : ""}
      <div class="row"><span>Quality reason</span><b>${escapeHTML((t.quality?.reasons || ["-"])[0])}</b></div>
      <div class="row"><span>DNS time</span><b>${fmt(t.dns_ms)} ms</b></div>
      <div class="row"><span>Hop count</span><b>${t.hop_count ?? "-"}</b></div>
      <div class="row"><span>Dest avg latency</span><b>${fmt(t.dest_avg_ms)} ms</b></div>
      <div class="row"><span>Probe jitter</span><b>${fmt(t.dest_jitter_ms)} ms</b></div>
      <div class="row"><span>Dest loss</span><b>${fmt(t.dest_loss_pct)}%</b></div>
      <div class="row"><span>Endpoint ${escapeHTML(t.endpoint_probe_protocol || "probe")}</span><b>${fmt(t.endpoint_avg_ms)} ms</b></div>
      <div class="row"><span>Endpoint jitter/loss</span><b>${fmt(t.endpoint_jitter_ms)} ms / ${fmt(t.endpoint_loss_pct)}%</b></div>
      <div class="row"><span>Latency vs baseline</span><b>${fmt(t.latency_deviation_pct)}%</b></div>
      <div class="row"><span>Path changed</span><b>${t.path_changed ? "YES" : "no"}</b></div>
      <div class="row"><span>Last check (ET)</span><b>${fmtEastern(t.timestamp)}</b></div>
      ${(t.ports || [])
        .map(
          (p) =>
            `<div class="row"><span>${escapeHTML(p.protocol.toUpperCase())}/${escapeHTML(p.port)}</span><b>${p.success ? fmt(p.latency_ms) + " ms" : "FAIL"}</b></div>`
        )
        .join("")}
    `;
    fragment.appendChild(div);
  });
  statusCards.replaceChildren(fragment);
}

async function loadAlerts() {
  const res = await fetch("/api/alerts?limit=5&recent_minutes=30");
  recentAlerts = await res.json();
  renderRecentAlert();
}

function renderRecentAlert() {
  alertsList.classList.toggle("minimized", alertsMinimized);
  toggleAlertsBtn.textContent = alertsMinimized ? "Show" : "Minimize";
  if (alertsMinimized) {
    alertsList.replaceChildren();
    return;
  }

  if (!recentAlerts.length) {
    alertsList.innerHTML = '<div class="alert-empty">No recent alerts. Full history is on the Alerts page.</div>';
    return;
  }

  const fragment = document.createDocumentFragment();
  recentAlerts.forEach((alert, index) => {
    const div = document.createElement("div");
    div.className = `alert-item ${alert.severity}`;
    div.innerHTML = `
      <div><strong>${index + 1}. ${escapeHTML(alert.kind)}</strong> <span>${escapeHTML(alert.target)}</span></div>
      <div>${escapeHTML(alert.message)}</div>
      <small>${escapeHTML(fmtEastern(alert.timestamp))}</small>
    `;
    fragment.appendChild(div);
  });
  alertsList.replaceChildren(fragment);
}

async function loadTargets(selectedTarget = targetSelect.value) {
  const res = await fetch("/api/targets");
  const targets = await res.json();
  targetSelect.innerHTML = "";
  targets.forEach((target) => {
    const option = document.createElement("option");
    option.value = target.host;
    option.textContent = `${target.label} (${target.host})`;
    targetSelect.appendChild(option);
  });
  if (targets.some((target) => target.host === selectedTarget)) {
    targetSelect.value = selectedTarget;
  } else if (targets.length) {
    targetSelect.value = targets[0].host;
  }
}

async function loadCharts() {
  const target = targetSelect.value;
  if (!target) return;
  const params = rangeParams();
  params.set("target", target);
  const res = await fetch(`/api/summary?${params.toString()}`);
  const points = await res.json();

  const labels = points.map((p) => fmtEastern(p.timestamp, false));
  const avgMs = points.map((p) => p.avg_ms);
  const jitterMs = points.map((p) => p.jitter_ms);
  const lossPct = points.map((p) => p.loss_pct);
  const endpointAvgMs = points.map((p) => p.endpoint_avg_ms);
  const endpointLossPct = points.map((p) => p.endpoint_loss_pct);
  const hopCounts = points.map((p) => p.hop_count);
  const seriesColors = chartSeriesColors();

  if (typeof Chart === "undefined") {
    drawFallbackChart(document.getElementById("latencyChart"), labels, [
      { data: avgMs, color: seriesColors[0] },
      { data: endpointAvgMs, color: seriesColors[1] },
      { data: jitterMs, color: seriesColors[2] },
      { data: lossPct, color: seriesColors[3] },
      { data: endpointLossPct, color: seriesColors[4] },
    ]);
    drawFallbackChart(document.getElementById("hopCountChart"), labels, [{ data: hopCounts, color: seriesColors[5] }]);
    return;
  }

  if (latencyChart) {
    latencyChart.data.labels = labels;
    [avgMs, endpointAvgMs, jitterMs, lossPct, endpointLossPct].forEach((series, i) => {
      latencyChart.data.datasets[i].data = series;
    });
    latencyChart.update("none");
  } else {
  latencyChart = new Chart(document.getElementById("latencyChart"), {
    type: "line",
    data: {
      labels,
      datasets: [
        { label: "Avg latency (ms)", data: avgMs, borderColor: seriesColors[0], borderWidth: 1.5, yAxisID: "y", tension: 0.2, pointRadius: 0 },
        { label: "Endpoint RTT (ms)", data: endpointAvgMs, borderColor: seriesColors[1], borderWidth: 1.5, yAxisID: "y", tension: 0.2, pointRadius: 0 },
        { label: "Probe jitter (ms)", data: jitterMs, borderColor: seriesColors[2], borderWidth: 1.25, yAxisID: "y", tension: 0.2, pointRadius: 0 },
        { label: "Loss %", data: lossPct, borderColor: seriesColors[3], borderWidth: 1.25, yAxisID: "y1", tension: 0.2, pointRadius: 0 },
        {
          label: "Endpoint loss %",
          data: endpointLossPct,
          borderColor: seriesColors[4],
          backgroundColor: seriesColors[4],
          borderDash: [5, 4],
          borderWidth: 1.75,
          yAxisID: "y1",
          tension: 0.2,
          pointRadius: 1.5,
          pointHoverRadius: 4,
          spanGaps: true,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: "index", intersect: false },
      plugins: { legend: { labels: { boxWidth: 10, color: themeColor("--chart-text", "#e8eff7"), font: { size: 11, weight: "600" } } } },
      scales: {
        x: {
          grid: { color: themeColor("--chart-grid", "rgba(175, 195, 220, 0.2)") },
          ticks: { color: themeColor("--chart-muted", "#afbdd0"), maxTicksLimit: 8, font: { size: 10, weight: "600" } },
        },
        y: {
          position: "left",
          grid: { color: themeColor("--chart-grid", "rgba(175, 195, 220, 0.2)") },
          title: { display: true, text: "ms", color: themeColor("--chart-text", "#e8eff7"), font: { size: 12, weight: "700" } },
          ticks: { color: themeColor("--chart-text", "#e8eff7"), font: { size: 10, weight: "600" } },
        },
        y1: {
          position: "right",
          beginAtZero: true,
          suggestedMax: 5,
          title: { display: true, text: "%", color: themeColor("--chart-text", "#e8eff7"), font: { size: 12, weight: "700" } },
          grid: { drawOnChartArea: false },
          ticks: { color: themeColor("--chart-text", "#e8eff7"), font: { size: 10, weight: "600" } },
        },
      },
    },
  });
  }

  if (hopCountChart) {
    hopCountChart.data.labels = labels;
    hopCountChart.data.datasets[0].data = hopCounts;
    hopCountChart.update("none");
  } else {
  hopCountChart = new Chart(document.getElementById("hopCountChart"), {
    type: "line",
    data: {
      labels,
      datasets: [{ label: "Hop count", data: hopCounts, borderColor: seriesColors[5], borderWidth: 1.5, stepped: true, pointRadius: 0 }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { labels: { boxWidth: 10, color: themeColor("--chart-text", "#e8eff7"), font: { size: 11, weight: "600" } } } },
      scales: {
        x: { grid: { color: themeColor("--chart-grid", "rgba(175, 195, 220, 0.2)") }, ticks: { color: themeColor("--chart-muted", "#afbdd0"), maxTicksLimit: 8, font: { size: 10, weight: "600" } } },
        y: {
          grid: { color: themeColor("--chart-grid", "rgba(175, 195, 220, 0.2)") },
          title: { display: true, text: "hops", color: themeColor("--chart-text", "#e8eff7"), font: { size: 12, weight: "700" } },
          ticks: { color: themeColor("--chart-text", "#e8eff7"), font: { size: 10, weight: "600" } },
        },
      },
    },
  });
  }
}

async function loadLatestHops() {
  const target = targetSelect.value;
  if (!target) {
    hopsTableBody.replaceChildren();
    renderPathViz([]);
    return;
  }
  const params = rangeParams();
  params.set("target", target);
  params.set("limit", "1");
  const runsRes = await fetch(`/api/runs?${params.toString()}`);
  const runs = await runsRes.json();
  if (!runs.length) {
    hopsTableBody.replaceChildren();
    renderPathViz([]);
    return;
  }

  const hopsRes = await fetch(`/api/runs/${runs[0].id}/hops`);
  const hops = await hopsRes.json();
  const visibleHops = showUnknownHops.checked ? hops : hops.filter((h) => h.host !== "???");
  renderPathViz(visibleHops);
  const rows = document.createDocumentFragment();
  visibleHops.forEach((h) => {
    const tr = document.createElement("tr");
    if (h.loss_pct > 0) tr.className = "loss";
    tr.innerHTML = `
      <td>${escapeHTML(h.hop_num)}</td><td>${escapeHTML(h.host)}</td><td>${fmt(h.loss_pct)}</td><td>${escapeHTML(h.sent ?? "-")}</td>
      <td>${fmt(h.last_ms)}</td><td>${fmt(h.avg_ms)}</td><td>${fmt(h.best_ms)}</td><td>${fmt(h.worst_ms)}</td><td>${fmt(h.stdev_ms)}</td>
      <td>${escapeHTML(h.asn || "-")}</td><td>${escapeHTML(h.org || "-")}</td><td>${escapeHTML(h.country || "-")}</td><td>${escapeHTML(h.city || "-")}</td>
    `;
    rows.appendChild(tr);
  });
  hopsTableBody.replaceChildren(rows);
}

function renderPathViz(hops) {
  const railWidth = Math.max(pathViz.clientWidth - 28, 420);
  const previousScrollLeft = pathViz.scrollLeft;
  pathHoverDetails.textContent = hops.length ? "Hover a hop for quick route details." : "No path data yet.";
  Object.assign(pathViz.style, {
    display: "block",
    overflowX: "auto",
    overflowY: "hidden",
    whiteSpace: "nowrap",
  });

  const track = document.createElement("div");
  track.className = "path-track";
  const minStep = 112;
  const nodeWidth = 38;
  const edgePad = 42;
  const step = hops.length > 1 ? Math.max(minStep, (railWidth - (edgePad * 2)) / (hops.length - 1)) : 0;
  const trackWidth = hops.length > 1 ? Math.max(railWidth, (edgePad * 2) + (step * (hops.length - 1)) + nodeWidth) : railWidth;
  const nodeLeft = (index) => hops.length > 1 ? edgePad + (index * step) : Math.max(edgePad, (trackWidth - nodeWidth) / 2);
  track.style.width = `${trackWidth}px`;
  Object.assign(track.style, {
    height: "92px",
    minWidth: "100%",
    position: "relative",
    display: "block",
  });

  hops.forEach((hop, index) => {
    const item = document.createElement("div");
    item.className = "path-hop";
    Object.assign(item.style, {
      display: "block",
      left: `${nodeLeft(index)}px`,
      position: "absolute",
      top: "10px",
      zIndex: "2",
    });
    if (index === 0) item.classList.add("source");
    if (index === hops.length - 1) item.classList.add("destination");

    if (index > 0) {
      const connector = document.createElement("div");
      connector.className = "path-connector";
      if ((hop.loss_pct || 0) > 0) connector.classList.add("bad");
      else if ((hop.avg_ms || 0) >= 150) connector.classList.add("warn");
      const connectorLeft = nodeLeft(index - 1) + nodeWidth;
      const connectorWidth = Math.max(18, nodeLeft(index) - connectorLeft);
      Object.assign(connector.style, {
        height: "3px",
        left: `${connectorLeft}px`,
        position: "absolute",
        top: "28px",
        width: `${connectorWidth}px`,
        zIndex: "1",
      });
      track.appendChild(connector);
    }

    const card = document.createElement("button");
    card.type = "button";
    card.className = "path-card";
    Object.assign(card.style, {
      alignItems: "center",
      borderRadius: "999px",
      display: "flex",
      height: "38px",
      justifyContent: "center",
      padding: "0",
      textAlign: "center",
      width: "38px",
    });
    if ((hop.loss_pct || 0) > 0) card.classList.add("bad");
    else if ((hop.avg_ms || 0) >= 150) card.classList.add("warn");

    const role = index === 0 ? "Client" : index === hops.length - 1 ? "Target" : `H${hop.hop_num}`;
    const avg = `${fmt(hop.avg_ms, 0)} ms`;

    const details = `Hop ${hop.hop_num}: ${hop.host} | avg ${fmt(hop.avg_ms)} ms | loss ${fmt(hop.loss_pct)}% | ${hop.asn || "ASN unknown"} | ${hop.org || "Org unknown"}`;
    card.title = details;
    card.addEventListener("mouseenter", () => { pathHoverDetails.textContent = details; });
    card.addEventListener("focus", () => { pathHoverDetails.textContent = details; });

    card.innerHTML = `
      <span class="path-badge">${escapeHTML(role)}</span>
    `;

    item.appendChild(card);

    const label = document.createElement("div");
    label.className = "path-node-label";
    label.innerHTML = `
      <div class="path-host">${escapeHTML(hop.host)}</div>
      <div><span class="path-metric">${avg}</span> <span class="path-loss ${hop.loss_pct > 0 ? "bad" : ""}">${fmt(hop.loss_pct, 0)}%</span></div>
    `;
    item.appendChild(label);

    track.appendChild(item);
  });

  pathViz.replaceChildren(track);
  pathViz.scrollLeft = previousScrollLeft;
}

let refreshInFlight = false;

async function refreshAll() {
  if (refreshInFlight) return;
  refreshInFlight = true;
  try {
    await Promise.allSettled([loadStatusCards(), loadAlerts(), loadCharts(), loadLatestHops()]);
  } finally {
    refreshInFlight = false;
  }
}

async function init() {
  await loadTargets();
  await refreshAll();
  setInterval(() => {
    // Skip background refreshes while hidden or mid-drag so they don't disrupt the user.
    if (document.hidden || draggedTarget) return;
    refreshAll();
  }, 15000);
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) refreshAll();
  });
}

targetSelect.addEventListener("change", refreshAll);
document.addEventListener("pathscope-theme-change", () => {
  syncChartTheme();
  if (typeof Chart === "undefined") loadCharts();
});
windowSelect.addEventListener("change", async () => {
  updateCustomWindowVisibility();
  await refreshAll();
});
applyCustomWindow.addEventListener("click", refreshAll);
showUnknownHops.addEventListener("change", loadLatestHops);
window.addEventListener("resize", () => {
  window.clearTimeout(window.__pathScopePathResizeTimer);
  window.__pathScopePathResizeTimer = window.setTimeout(loadLatestHops, 150);
});
helpBtn.addEventListener("click", () => setHelpOpen(true));
closeHelpBtn.addEventListener("click", () => setHelpOpen(false));
helpBackdrop.addEventListener("click", () => setHelpOpen(false));
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") setHelpOpen(false);
});
toggleAlertsBtn.addEventListener("click", () => {
  alertsMinimized = !alertsMinimized;
  renderRecentAlert();
});
exportBtn.addEventListener("click", () => {
  const target = targetSelect.value;
  if (!target) return;
  const params = rangeParams();
  params.set("target", target);
  window.location = `/api/export.csv?${params.toString()}`;
});

updateCustomWindowVisibility();
init();
