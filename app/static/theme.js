const themeStorageKey = "pathscope.colorTheme";
const daylightStops = [
  [0, 0],
  [5, 0],
  [7, 0.12],
  [9, 0.4],
  [12, 0.86],
  [14, 1],
  [16, 0.86],
  [18, 0.55],
  [20, 0.24],
  [22, 0.05],
  [24, 0],
];

function readSavedTheme() {
  try {
    const saved = localStorage.getItem(themeStorageKey);
    return ["dark", "light", "full"].includes(saved) ? saved : "dark";
  } catch {
    return "dark";
  }
}

function daylightAtLocalTime(date = new Date()) {
  const hour = date.getHours() + date.getMinutes() / 60;
  const nextStopIndex = daylightStops.findIndex(([stopHour]) => stopHour >= hour);
  if (nextStopIndex <= 0) return daylightStops[0][1];

  const [startHour, startLevel] = daylightStops[nextStopIndex - 1];
  const [endHour, endLevel] = daylightStops[nextStopIndex];
  const progress = (hour - startHour) / (endHour - startHour);
  const easedProgress = progress * progress * (3 - 2 * progress);
  return startLevel + (endLevel - startLevel) * easedProgress;
}

function applyTheme(mode) {
  const root = document.documentElement;
  root.dataset.theme = mode;

  if (mode === "full") {
    const daylight = daylightAtLocalTime();
    root.style.setProperty("--daylight", `${(daylight * 100).toFixed(2)}%`);
  } else {
    root.style.removeProperty("--daylight");
  }

  document.dispatchEvent(new CustomEvent("pathscope-theme-change", { detail: { mode } }));
}

function initializeHeaderMenu() {
  const menu = document.querySelector(".header-menu");
  if (!menu) return;

  document.addEventListener("click", (event) => {
    if (menu.open && !menu.contains(event.target)) menu.open = false;
  });

  menu.addEventListener("click", (event) => {
    if (event.target.closest("a, button")) menu.open = false;
  });

  menu.addEventListener("keydown", (event) => {
    if (event.key !== "Escape" || !menu.open) return;
    menu.open = false;
    menu.querySelector("summary").focus();
    event.preventDefault();
  });
}

function initializeThemeSelector() {
  initializeHeaderMenu();
  const selector = document.getElementById("themeSelect");
  let mode = readSavedTheme();
  selector.value = mode;
  applyTheme(mode);

  selector.addEventListener("change", () => {
    mode = selector.value;
    try {
      localStorage.setItem(themeStorageKey, mode);
    } catch {
      // Keep the selected theme for this page when browser storage is unavailable.
    }
    applyTheme(mode);
  });

  window.addEventListener("storage", (event) => {
    if (event.key !== themeStorageKey) return;
    mode = readSavedTheme();
    selector.value = mode;
    applyTheme(mode);
  });

  window.setInterval(() => {
    if (mode === "full" && !document.hidden) applyTheme(mode);
  }, 60000);

  document.addEventListener("visibilitychange", () => {
    if (mode === "full" && !document.hidden) applyTheme(mode);
  });
}

const initialTheme = readSavedTheme();
document.documentElement.dataset.theme = initialTheme;
if (initialTheme === "full") {
  const daylight = daylightAtLocalTime();
  document.documentElement.style.setProperty("--daylight", `${(daylight * 100).toFixed(2)}%`);
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initializeThemeSelector, { once: true });
} else {
  initializeThemeSelector();
}
