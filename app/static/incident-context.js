(() => {
  const reasonLabels = {
    path_change: "Network path changed",
    dns_failure: "DNS lookup failed",
    mtr_failure: "Path probe failed",
    endpoint_failure: "Endpoint probe failed",
    endpoint_loss: "Endpoint packet loss detected",
    service_failure: "Service check failed",
  };

  const confidenceLabels = {
    corroborated: "Corroborated signals",
    suggestive: "Suggestive correlation",
    inconclusive: "Inconclusive",
  };

  function formatTimestamp(value) {
    if (!value) return "-";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "-";
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
    }).format(date);
  }

  function formatNumber(value, unit = "") {
    if (typeof value !== "number" || !Number.isFinite(value)) return null;
    const formatted = new Intl.NumberFormat("en-US", { maximumFractionDigits: 2 }).format(value);
    return unit === "%" ? `${formatted}%` : `${formatted}${unit ? ` ${unit}` : ""}`;
  }

  function eventTitle(context) {
    const labels = (context.trigger_reasons || []).map((reason) => reasonLabels[reason] || String(reason).replaceAll("_", " "));
    return labels.length ? labels.join(" · ") : "Monitoring event";
  }

  function addDetail(container, label, value) {
    if (value === null || value === undefined || value === "") return;
    const row = document.createElement("div");
    row.className = "context-detail";
    const name = document.createElement("strong");
    name.textContent = `${label}:`;
    const detail = document.createElement("span");
    detail.textContent = String(value);
    row.append(name, detail);
    container.appendChild(row);
  }

  function addSection(container, title) {
    const section = document.createElement("section");
    section.className = "context-source";
    const heading = document.createElement("h3");
    heading.textContent = title;
    section.appendChild(heading);
    container.appendChild(section);
    return section;
  }

  function routeText(route) {
    return (route || [])
      .map((hop) => hop.asn || hop.host)
      .filter(Boolean)
      .join(" → ");
  }

  function addStatusDetails(section, context) {
    const statusPage = context.status_page || {};
    const discovery = statusPage.discovery || context.status_page_discovery || {};
    if (discovery.url) {
      addDetail(section, "Status page URL", discovery.url);
      addDetail(section, "Provider", discovery.provider);
      addDetail(section, "Discovery source", discovery.source);
      addDetail(section, "URL confidence", discovery.confidence);
      try {
        const url = new URL(discovery.url);
        if (url.protocol === "https:") {
          const link = document.createElement("a");
          link.href = url.href;
          link.target = "_blank";
          link.rel = "noopener noreferrer";
          link.textContent = "Open status source";
          section.appendChild(link);
        }
      } catch {
        addDetail(section, "Status source link", "Invalid URL");
      }
    }

    if (statusPage.status === "available") {
      addDetail(section, "Provider status", `${statusPage.indicator} · ${statusPage.description}`);
      addDetail(
        section,
        "Status page updated",
        statusPage.page_updated_at ? formatTimestamp(statusPage.page_updated_at) : "not provided",
      );
      (statusPage.active_incidents || []).forEach((incident) => {
        addDetail(
          section,
          incident.name,
          `${incident.status}${incident.updated_at ? ` · updated ${formatTimestamp(incident.updated_at)}` : ""}`,
        );
      });
    } else {
      const message = statusPage.status === "unavailable"
        ? "temporarily unavailable or not recognized"
        : statusPage.status === "not_found"
          ? "no supported status page found; this does not mean the target is healthy"
          : "no status page configured or discovered";
      addDetail(section, "Status feed", message);
    }
  }

  function renderSnapshotDetails(event) {
    const context = event.context || {};
    const content = document.createElement("div");
    content.className = "event-snapshot-content";

    const assessment = document.createElement("p");
    assessment.className = "context-assessment";
    assessment.textContent = context.assessment?.summary || "The available evidence does not establish a cause.";
    content.appendChild(assessment);

    const local = context.local || {};
    const localSection = addSection(content, "PathScope observations");
    addDetail(localSection, "Event", eventTitle(context));
    addDetail(localSection, "Recorded", formatTimestamp(context.event_timestamp || event.timestamp));
    addDetail(localSection, "Context collected", formatTimestamp(context.collected_at));
    addDetail(localSection, "Probe run", `#${event.id}`);
    addDetail(localSection, "Destination", local.resolved_ip);
    addDetail(localSection, "MTR", local.mtr_success ? "path responded" : local.mtr_error || "failed");
    addDetail(localSection, "Endpoint probe", local.endpoint_error ? `failed (${local.endpoint_error})` : local.endpoint_protocol || "not measured");
    addDetail(localSection, "Endpoint latency", formatNumber(local.endpoint_avg_ms, "ms"));
    addDetail(localSection, "Endpoint jitter", formatNumber(local.endpoint_jitter_ms, "ms"));
    addDetail(localSection, "Endpoint loss", formatNumber(local.endpoint_loss_pct, "%"));
    if (local.path_changed) {
      addDetail(localSection, "Previous route", routeText(local.previous_path) || "unavailable");
      addDetail(localSection, "Observed route", routeText(local.current_path) || "unavailable");
    }
    (local.service_checks || []).forEach((check) => {
      addDetail(
        localSection,
        `${String(check.protocol || "service").toUpperCase()}/${check.port}`,
        check.success ? "reachable" : `failed${check.error ? ` (${check.error})` : ""}`,
      );
    });

    const bgp = context.bgp || {};
    const bgpSection = addSection(content, "BGP control-plane context");
    if (bgp.status === "available") {
      addDetail(bgpSection, "Destination prefix", bgp.prefix);
      addDetail(bgpSection, "Collector routes", bgp.collector_routes);
      addDetail(
        bgpSection,
        "Updates",
        `${bgp.announcements || 0} announcements, ${bgp.withdrawals || 0} withdrawals in ${bgp.window_minutes} minutes`,
      );
      addDetail(bgpSection, "Observed origins", (bgp.observed_origins || []).map((asn) => `AS${asn}`).join(", ") || "none");
      (bgp.events || []).forEach((item) => {
        addDetail(
          bgpSection,
          item.timestamp ? formatTimestamp(item.timestamp) : "BGP event",
          [item.type, item.source, item.origin_asn ? `AS${item.origin_asn}` : ""].filter(Boolean).join(" · "),
        );
      });
    } else {
      addDetail(bgpSection, "RIPEstat", bgp.status === "unavailable" ? "temporarily unavailable" : "not available for this destination");
    }

    const rpkiSection = addSection(content, "RPKI origin validation");
    if ((context.rpki || []).length) {
      context.rpki.forEach((result) => {
        addDetail(rpkiSection, `${result.asn} · ${result.prefix}`, result.status);
      });
    } else {
      addDetail(
        rpkiSection,
        "RIPEstat",
        context.rpki_status === "unavailable" ? "temporarily unavailable" : "no validation result for the observed origin",
      );
    }

    addStatusDetails(addSection(content, "Public service status"), context);
    addDetail(
      content,
      "Evidence sources",
      (context.sources || []).join(", ") || "Local PathScope probes only",
    );
    return content;
  }

  function createEventCard(event, { detailed = false, expanded = false, focused = false } = {}) {
    const context = event.context || {};
    const confidence = context.assessment?.confidence || "inconclusive";
    const confidenceClass = Object.hasOwn(confidenceLabels, confidence) ? confidence : "inconclusive";
    const card = document.createElement("article");
    card.className = `context-event-card${detailed ? " context-event-history-card" : ""}${focused ? " event-highlight" : ""}`;
    card.id = `event-${event.id}`;
    if (focused) card.tabIndex = -1;

    const header = document.createElement("div");
    header.className = "context-event-header";
    const identity = document.createElement("div");
    identity.className = "context-event-identity";
    const title = document.createElement("h3");
    title.textContent = eventTitle(context);
    const target = document.createElement("span");
    target.className = "context-event-target";
    target.textContent = event.target || "Unknown target";
    identity.append(title, target);

    const badge = document.createElement("span");
    badge.className = `context-confidence ${confidenceClass}`;
    badge.textContent = confidenceLabels[confidence] || confidenceLabels.inconclusive;
    header.append(identity, badge);
    card.appendChild(header);

    const timestamp = document.createElement("time");
    timestamp.className = "context-event-time";
    timestamp.dateTime = event.timestamp || "";
    timestamp.textContent = formatTimestamp(event.timestamp);
    card.appendChild(timestamp);

    const runId = document.createElement("small");
    runId.className = "context-event-run-id";
    runId.textContent = `Probe run #${event.id}`;
    card.appendChild(runId);

    const summary = document.createElement("p");
    summary.className = "context-event-summary";
    summary.textContent = context.assessment?.summary || "The available evidence does not establish a cause.";
    card.appendChild(summary);

    if (detailed) {
      const disclosure = document.createElement("details");
      disclosure.className = "context-event-details";
      disclosure.open = expanded;
      const disclosureSummary = document.createElement("summary");
      disclosureSummary.textContent = "Event snapshot details";
      disclosure.append(disclosureSummary, renderSnapshotDetails(event));
      card.appendChild(disclosure);
    } else {
      const link = document.createElement("a");
      link.className = "context-event-link";
      link.href = `/events?event_id=${encodeURIComponent(event.id)}`;
      link.textContent = "View event details";
      card.appendChild(link);
    }
    return card;
  }

  window.PathScopeIncidentContext = { createEventCard };
})();
