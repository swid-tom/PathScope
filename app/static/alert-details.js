(() => {
  const escapeHTML = (value) => String(value ?? "").replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  })[character]);

  const labels = {
    measured_ms: "Measured",
    measured_pct: "Measured packet loss",
    threshold_ms: "Alert threshold",
    threshold_pct: "Alert threshold",
    source: "Measurement source",
    endpoint_probe_protocol: "Probe",
    endpoint_avg_ms: "Endpoint latency",
    endpoint_jitter_ms: "Endpoint jitter",
    endpoint_loss_pct: "Endpoint loss",
    hop_num: "Hop number",
    host: "Address",
    avg_ms: "Average latency",
    loss_pct: "Packet loss",
    jitter_ms: "Jitter",
    stdev_ms: "Jitter",
    error: "Probe error",
    previous_run_id: "Previous run",
    previous_error: "Previous error",
    previous_hop_count: "Previous hop count",
    current_hop_count: "Current hop count",
  };

  const alertTitles = {
    probe_failure: "Probe failed",
    probe_recovery: "Connection recovered",
    path_change: "Network path changed",
    latency: "High latency",
    jitter: "High jitter",
    loss: "Packet loss detected",
  };

  const severityLabels = {
    critical: "Critical",
    warning: "Warning",
    info: "Informational",
  };

  const metricAlertLabels = {
    latency: { name: "Latency", measuredKey: "measured_ms", thresholdKey: "threshold_ms", unit: "ms" },
    jitter: { name: "Jitter", measuredKey: "measured_ms", thresholdKey: "threshold_ms", unit: "ms" },
    loss: { name: "Packet loss", measuredKey: "measured_pct", thresholdKey: "threshold_pct", unit: "%" },
  };

  function humanize(value) {
    return String(value || "Alert")
      .replace(/_/g, " ")
      .replace(/\b\w/g, (letter) => letter.toUpperCase());
  }

  function formatMeasurement(value, unit) {
    if (typeof value !== "number" || !Number.isFinite(value)) return null;
    return `${new Intl.NumberFormat("en-US", { maximumFractionDigits: 2 }).format(value)} ${unit}`;
  }

  function presentAlert(alert) {
    const kind = String(alert.kind || "");
    const details = alert.details && typeof alert.details === "object" ? alert.details : {};
    let summary = String(alert.message || "An alert was recorded.");

    if (metricAlertLabels[kind]) {
      const metric = metricAlertLabels[kind];
      const measured = formatMeasurement(details[metric.measuredKey], metric.unit);
      const threshold = formatMeasurement(details[metric.thresholdKey], metric.unit);
      if (measured && threshold) {
        summary = `${metric.name} reached ${measured} (alert limit: ${threshold}).`;
      }
    } else if (kind === "path_change") {
      const added = Array.isArray(details.added_hops) ? details.added_hops.length : 0;
      const removed = Array.isArray(details.removed_hops) ? details.removed_hops.length : 0;
      const changes = [];
      if (added) changes.push(`${added} new ${added === 1 ? "hop" : "hops"}`);
      if (removed) changes.push(`${removed} ${removed === 1 ? "hop" : "hops"} removed`);
      summary = changes.length
        ? `The route changed since the previous successful check: ${changes.join(", ")}.`
        : "The route changed since the previous successful check.";
    } else if (kind === "probe_failure") {
      const reason = String(details.error || alert.message || "")
        .replace(/^probe failed:\s*/i, "")
        .trim();
      summary = reason
        ? `The probe could not reach the target. ${reason}`
        : "The probe could not reach the target.";
    } else if (kind === "probe_recovery") {
      summary = "The target responded again after a failed check.";
    }

    const severity = String(alert.severity || "").toLowerCase();
    const severityClass = Object.hasOwn(severityLabels, severity) ? severity : "unknown";
    return {
      title: alertTitles[kind] || humanize(kind),
      summary,
      severityLabel: severityLabels[severity] || humanize(severity),
      severityClass,
    };
  }

  function formatTimestamp(value) {
    if (!value) return "-";
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
    }).format(new Date(value));
  }

  function labelFor(key, alertKind) {
    if (key === "measured_ms") {
      if (alertKind === "jitter") return "Measured jitter";
      if (alertKind === "latency") return "Measured latency";
    }
    if (key === "measured_pct" && alertKind === "loss") return "Measured packet loss";
    if (key === "source") return "Measurement source";
    return labels[key] || key.replace(/_/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
  }

  function formatValue(key, value) {
    if (value === null || value === undefined) return "Not available";
    if (typeof value === "number") {
      const formatted = new Intl.NumberFormat("en-US", { maximumFractionDigits: 2 }).format(value);
      if (key.endsWith("_ms")) return `${formatted} ms`;
      if (key.endsWith("_pct")) return `${formatted}%`;
      return formatted;
    }
    if (typeof value === "boolean") return value ? "Yes" : "No";
    if (key.endsWith("_timestamp")) return formatTimestamp(value);
    if (key === "source") {
      if (value === "endpoint") return "Endpoint probe";
      if (value === "mtr_effective_hop") return "MTR effective hop";
    }
    if (key === "endpoint_probe_protocol") return String(value).toUpperCase();
    if (Array.isArray(value)) return value.length ? value.join(" → ") : "None";
    if (typeof value === "object") return Object.entries(value)
      .map(([childKey, childValue]) => `${labelFor(childKey)}: ${formatValue(childKey, childValue)}`)
      .join(" · ");
    return String(value);
  }

  function renderRow(key, value, alertKind, emphasized = false) {
    return `
      <div class="alert-detail-row${emphasized ? " emphasized" : ""}">
        <span>${escapeHTML(labelFor(key, alertKind))}</span>
        <strong>${escapeHTML(formatValue(key, value))}</strong>
      </div>
    `;
  }

  function renderPath(details) {
    const addedHops = Array.isArray(details.added_hops) ? details.added_hops : [];
    const removedHops = Array.isArray(details.removed_hops) ? details.removed_hops : [];
    const renderHops = (hops, changedHops, direction) => {
      if (!hops.length) return '<span class="path-hops-none">none</span>';
      const changedSet = new Set(changedHops);
      return hops
        .map((hop) => changedSet.has(hop)
          ? `<span class="path-ip path-ip-${direction}">${escapeHTML(hop)}</span>`
          : `<span class="path-ip-neutral">${escapeHTML(hop)}</span>`)
        .join('<span class="path-hop-arrow" aria-hidden="true"> &rarr; </span>');
    };

    return `
      <div class="path-change-meta"><strong>Previous run:</strong> ${escapeHTML(details.previous_run_id ?? "-")} ${escapeHTML(formatTimestamp(details.previous_timestamp))}</div>
      <div class="path-change-path"><strong>Previous path (${escapeHTML(details.previous_hop_count ?? 0)}):</strong> ${renderHops(details.previous_path || [], removedHops, "removed")}</div>
      <div class="path-change-path"><strong>Current path (${escapeHTML(details.current_hop_count ?? 0)}):</strong> ${renderHops(details.current_path || [], addedHops, "added")}</div>
    `;
  }

  function renderMetricContent(details, alertKind) {
    const primaryKeys = ["measured_ms", "measured_pct", "threshold_ms", "threshold_pct"];
    const primaryRows = primaryKeys
      .filter((key) => details[key] !== null && details[key] !== undefined)
      .map((key) => renderRow(key, details[key], alertKind, key.startsWith("measured_")));

    const matchingEndpointKey = {
      latency: "endpoint_avg_ms",
      jitter: "endpoint_jitter_ms",
      loss: "endpoint_loss_pct",
    }[alertKind];
    const measuredKey = details.measured_ms !== undefined ? "measured_ms" : "measured_pct";
    const detailsEntries = Object.entries(details).filter(([key, value]) => (
      !primaryKeys.includes(key)
      && key !== "mtr_effective_hop"
      && value !== null
      && value !== undefined
      && !(key === matchingEndpointKey && value === details[measuredKey])
    ));
    const detailRows = detailsEntries
      .map(([key, value]) => renderRow(key, value, alertKind))
      .join("");

    const hop = details.mtr_effective_hop;
    const hopContent = hop && typeof hop === "object"
      ? `
        <div class="alert-detail-group">
          <strong>MTR effective-hop comparison</strong>
          <div class="alert-detail-grid">
            ${Object.entries(hop).map(([key, value]) => renderRow(key, value, alertKind)).join("")}
          </div>
        </div>
      `
      : "";

    return `
      <div class="alert-detail-content">
        ${primaryRows.length ? `<div class="alert-detail-primary">${primaryRows.join("")}</div>` : ""}
        ${detailRows ? `<div class="alert-detail-grid">${detailRows}</div>` : ""}
        ${hopContent}
      </div>
    `;
  }

  function renderContent(details, alertKind) {
    if (!details || !Object.keys(details).length) {
      return '<div class="alert-details-empty">No alert details recorded.</div>';
    }
    if (details.current_path || details.previous_path) return renderPath(details);
    return renderMetricContent(details, alertKind);
  }

  function renderDetails(details, alertKind, open = false) {
    if ((!details || !Object.keys(details).length) && !open) return "";
    const isPathChange = Boolean(details?.current_path || details?.previous_path);
    const summary = isPathChange ? "Path change details" : "Details";
    return `<details class="alert-details"${open ? " open" : ""}><summary>${summary}</summary>${renderContent(details, alertKind)}</details>`;
  }

  window.PathScopeAlertDetails = { presentAlert, renderContent, renderDetails };
})();
