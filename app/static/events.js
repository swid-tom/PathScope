const eventsPageList = document.getElementById("eventsPageList");
const eventLimit = document.getElementById("eventLimit");
const refreshEventsBtn = document.getElementById("refreshEventsBtn");

function eventIdFromLocation() {
  const eventId = Number(new URLSearchParams(window.location.search).get("event_id"));
  return Number.isSafeInteger(eventId) && eventId > 0 ? eventId : null;
}

function showLoadError() {
  if (!eventsPageList.childElementCount) {
    eventsPageList.textContent = "Could not load event snapshots. Check API access and refresh.";
    return;
  }
  if (!eventsPageList.querySelector(".event-load-error")) {
    const error = document.createElement("p");
    error.className = "event-load-error";
    error.textContent = "Could not refresh event snapshots. Showing the last loaded data.";
    eventsPageList.appendChild(error);
  }
}

async function fetchEvents(params) {
  const response = await fetch(`/api/events?${params.toString()}`);
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.json();
}

async function loadEventHistory(focusEventId = null) {
  const openEventIds = new Set(
    [...eventsPageList.querySelectorAll(".context-event-history-card")]
      .filter((card) => card.querySelector("details.context-event-details")?.open)
      .map((card) => card.id.replace("event-", "")),
  );
  const params = new URLSearchParams({ limit: eventLimit.value });
  let events = await fetchEvents(params);
  let focusEventMissing = false;
  if (focusEventId && !events.some((event) => event.id === focusEventId)) {
    const targetParams = new URLSearchParams({ limit: "1", event_id: String(focusEventId) });
    const [targetEvent] = await fetchEvents(targetParams);
    if (targetEvent) events = [...events, targetEvent];
    else focusEventMissing = true;
  }
  events.sort((left, right) => new Date(right.timestamp) - new Date(left.timestamp));

  if (!events.length) {
    eventsPageList.replaceChildren();
    const empty = document.createElement("div");
    empty.className = "event-empty";
    empty.textContent = focusEventId
      ? "This event snapshot is unavailable; it may have been pruned."
      : "No event snapshots have been recorded.";
    eventsPageList.appendChild(empty);
    return;
  }

  const fragment = document.createDocumentFragment();
  if (focusEventMissing) {
    const notice = document.createElement("p");
    notice.className = "event-empty";
    notice.textContent = `Event snapshot #${focusEventId} is unavailable; it may have been pruned.`;
    fragment.appendChild(notice);
  }
  events.forEach((event) => {
    const isFocused = event.id === focusEventId;
    fragment.appendChild(window.PathScopeIncidentContext.createEventCard(event, {
      detailed: true,
      expanded: isFocused || openEventIds.has(String(event.id)),
      focused: isFocused,
    }));
  });
  eventsPageList.replaceChildren(fragment);

  if (focusEventId) {
    const focusedEvent = document.getElementById(`event-${focusEventId}`);
    if (focusedEvent) {
      focusedEvent.scrollIntoView({ behavior: "smooth", block: "center" });
      focusedEvent.focus({ preventScroll: true });
    }
  }
}

eventLimit.addEventListener("change", () => {
  loadEventHistory(eventIdFromLocation()).catch(showLoadError);
});
refreshEventsBtn.addEventListener("click", async () => {
  refreshEventsBtn.disabled = true;
  refreshEventsBtn.classList.add("refreshing");
  try {
    await loadEventHistory(eventIdFromLocation());
  } catch {
    showLoadError();
  } finally {
    refreshEventsBtn.disabled = false;
    refreshEventsBtn.classList.remove("refreshing");
  }
});

loadEventHistory(eventIdFromLocation()).catch(() => {
  showLoadError();
});
