# Team Agent Instructions: Network Utility Apps

Use these instructions when modifying this repository or building related internal network utility apps.

## Product Direction

Build practical internal network engineering tools, not marketing sites.

The standard pattern is:

- FastAPI backend
- Jinja templates for server-rendered pages
- Small focused JavaScript files in `app/static/`
- SQLite for local/small deployments
- optional PostgreSQL/TimescaleDB roadmap for long-term time-series scale
- systemd/native Linux preferred for tools that depend on MTR, ping, tcpdump, DSCP/TOS, or raw socket behavior
- Docker/Podman acceptable only when it does not break network fidelity

For `PathScope`, preserve the current role:

- network-to-edge latency/path monitor
- DNS, MTR, endpoint probe, TCP/TLS, jitter/loss, alerts, DSCP/TOS, quality score
- integration point for external monitoring systems

## UI / Theme Standard

Use a clear, high-contrast visual language suitable for network operations:

- blue-toned background and accent colors
- readable panels with clear separation
- high-contrast primary text and subdued secondary text
- status colors:
  - green: `#4CAF50`
  - red: `#f44336`
  - amber: `#ff9800`

Header standard:

- app logo on the left
- transparent logo background with subtle drop shadow
- professional title block next to logo
- controls on the right
- shared nav links to Dashboard/Admin/Alerts when applicable

Logo asset convention:

- prefer official transparent PNG or SVG
- current app logo path: `app/static/pathscope-logo.svg`
- avoid white logo boxes unless contrast requires it

## Page Structure Standard

For internal utility apps, prefer this structure:

- `/` dashboard / operational view
- `/admin` configuration and maintenance
- `/alerts` alert history, if alerts exist
- `/api/...` JSON APIs
- `docs/` for architecture notes and integration notes

Keep configuration controls off the main dashboard when they are not part of daily monitoring.

## Data / Monitoring Standards

When adding new measurements, distinguish:

- path measurement (MTR/hops)
- endpoint measurement (final destination only)
- service measurement (TCP/TLS/HTTP/etc.)
- synthetic application measurement (future WebRTC/ICE/etc.)

For alerts:

- keep main dashboard alerts concise
- store structured details for the full `/alerts` page
- include enough context to explain what changed
- avoid spammy alerts when a single sustained condition can be summarized

For charts:

- support preset windows and custom start/end windows
- keep axis labels high contrast
- ensure CSV export includes the same metrics shown in charts
- update existing chart instances in place (`chart.update("none")`) instead of destroying and recreating them on refresh

For auto-refreshing dashboards:

- never clear a section before its new data arrives; build new DOM off-screen and swap with `replaceChildren()`
- preserve scroll position (page and horizontal rails) across refreshes
- skip overlapping refreshes, and pause while the tab is hidden or the user is dragging/interacting

## Network Tooling Guidance

Be careful with containers for network probes.

Known pattern:

- native WSL/Linux or systemd service gives the most accurate MTR/path behavior
- rootless Podman may collapse MTR path visibility or block raw sockets
- TCP/443 MTR can be useful for service edges where default probes may be filtered
- DSCP/TOS mapping is `TOS = DSCP << 2`

## Security Standard

Admin/config pages must be protected before broad exposure.

Preferred production pattern:

- reverse proxy handles TLS and SSO/LDAP/OIDC/MFA
- app remains internal/private
- local HTTP Basic auth is acceptable for small/lab deployments

Never store plaintext admin passwords in config. Use hashes or environment variables.

## Documentation Standard

Update README when changing user-visible behavior.

Create focused docs under `docs/` for larger design topics, for example:

- storage/time-series roadmap
- external monitoring integration
- utility server strategy
- future WebRTC synthetic testing

Do not create extra docs for tiny implementation-only changes.

## Validation Standard

After backend changes:

```bash
.venv/bin/python -m py_compile app/main.py app/config.py app/scheduler.py
```

After frontend/template changes:

- run diagnostics if available
- bump static asset query versions in templates when browser cache may hide changes

After DB schema changes:

- add lightweight SQLite migration in `app/db.py`
- validate `init_db()` against an existing database

## Code Style

- Keep changes small and focused.
- Prefer simple functions over heavy frameworks.
- Avoid unrelated refactors.
- Preserve existing API behavior unless intentionally changing it.
- Use clear field names: `endpoint_avg_ms`, `dest_jitter_ms`, `path_changed`, etc.
- Keep UI text direct and operational.
