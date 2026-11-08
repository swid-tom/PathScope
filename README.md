<p align="center">
  <img src="app/static/pathscope-logo.svg" alt="PathScope" width="300" />
</p>

# PathScope — Network Path & Edge Monitor

PathScope helps you keep an eye on network latency, routes, DNS, and service availability.
Add a hostname in Admin to start monitoring it.

> **First time opening Admin?** Sign in with username **`admin`** and password **`password`**.
> PathScope will ask you to choose a new password before you can use the rest of Admin.
> Change it before making the app available to anyone you don’t trust: `password` is a
> shared default, not a secret.

Targets are loaded from `config.yaml` and can be added or edited from the Admin page.

Every 60s by default, each target runs:

1. **DNS timing and resolved-IP tracking** using the system/local resolver, so internal DNS,
  VPN DNS, and split-horizon names can be monitored.
2. **TCP/443 MTR path discovery** for hop-by-hop path, loss, latency, jitter/stdev, and ASN/org enrichment.
3. **Final-destination endpoint probe** via per-target TCP-connect or ICMP ping settings.
4. **TCP connect checks** to configured target ports.
5. **TLS handshake timing** with SNI, including certificate-expiry warning text.
6. Optional **UDP STUN Binding Request** check when a target/port is confirmed to answer STUN.
7. **Path-change detection** by comparing responsive-hop signatures between successful runs.
8. **Baseline/anomaly context** against a configurable lookback window.
9. **Alert event logging** for latency, jitter, loss, path changes, and deduplicated probe failure/recovery transitions, with optional webhook delivery.

Results are stored in SQLite (`data/monitor.db`) and shown in a FastAPI + Chart.js UI with:

- status cards
- recent alert strip
- full logged alerts page
- latency/loss/jitter charts
- hop-count/path stability chart
- custom time windows
- horizontal path visualization
- latest hop table
- CSV export

## Pages

- Dashboard: `http://localhost:8000/`
- Admin/config: `http://localhost:8000/admin`
- Alert history: `http://localhost:8000/alerts`

The dashboard shows only the recent alert window. The `/alerts` page keeps the logged alert history until you clear alerts or prune the database.

The dashboard auto-refreshes every 15 seconds without reloading the page. Each section is replaced in a single step and charts are updated in place, so the scroll position, selected target, and path-rail scroll are kept. Refreshes pause while the browser tab is hidden or a status card is being dragged, and run immediately when the tab becomes visible again.

## Appearance

Open **Options** in the page header to change the monitored target, time window, theme, or page actions. Choose **Dark**, **Light**, or **Full**; your choice is saved in this browser and shared across the Dashboard, Admin, and Alerts pages.

**Full** gradually shifts from deep navy at night to a lighter blue-toned palette in daytime, then dims toward evening, using the browser's local time. It keeps foreground text high-contrast throughout. The theme refreshes periodically and when a background tab becomes active.

## Quick start (native WSL/Linux recommended for path fidelity)

`mtr` needs Linux networking/raw-socket behavior. For best path fidelity on Windows, run the app natively in WSL instead of rootless Podman.

```bash
cd ~/Codes/PathScope
cp config.example.yaml config.yaml
sudo apt-get update
sudo apt-get install -y mtr-tiny python3-full python3-venv python3-pip
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
sudo .venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Then open [http://localhost:8000](http://localhost:8000)

## Docker / Podman notes
`mtr` needs raw-socket privileges, so this is packaged for Linux/Docker (works fine on
Windows via Docker Desktop for basic use):

```powershell
docker compose up --build -d
```

Then open [http://localhost:8000](http://localhost:8000)

Rootless Podman can run the web app, but MTR path discovery may collapse to only the destination hop or fail raw-socket access depending on network mode. For a production utility VM, either run natively under systemd with a low-privilege user and capabilities, or use a rootful/container setup that preserves MTR behavior.

The Compose file mounts `config.yaml` read/write so Admin changes are saved on the host.
Before starting, copy `config.example.yaml` to `config.yaml` if you have not already done
so. `config.yaml` is local and excluded from Git. Admin sign-in uses HTTP Basic
authentication. On first startup, use **`admin` / `password`**; Admin will guide you
through setting a new password (at least 12 characters). You can change it later from
the same page. Until you do, keep PathScope on your own computer or trusted network.

## Configuration

Use `/admin` for routine changes:

- add/edit/delete targets
- optionally delete target history when removing a target
- set per-target alert thresholds
- set per-target endpoint probe mode/count/port
- prune old history
- compact/VACUUM the SQLite database

Changes made in Admin are persisted back to `config.yaml` and scheduled immediately.

Important config blocks:

```yaml
mtr:
  count: 5
  protocol: tcp
  port: 443
  interval_seconds: 60

endpoint_probe:
  enabled: true
  protocol: tcp
  count: 5
  port: null

dns_sinkhole_ranges: []

baseline:
  days: 7

alerts:
  enabled: true
  webhook_url: null
  latency_ms: 250
  jitter_ms: 50
  loss_pct: 2
  path_change: true
```

Per-target overrides can be set from `/admin` or directly in YAML:

```yaml
- host: target.example.com
  label: Primary service endpoint
  tcp_ports:
    - 443
  alert_latency_ms: 220
  alert_jitter_ms: 45
  alert_loss_pct: 1
  alert_path_change: true
  endpoint_probe_enabled: true
  endpoint_probe_protocol: tcp
  endpoint_probe_count: 5
  endpoint_probe_port: 443
```

## API

- `GET /api/targets` — configured targets
- `POST /api/targets` / `PUT /api/targets/{host}` / `DELETE /api/targets/{host}` — target configuration
- `POST /api/admin/password` — set a new admin password (requires current HTTP Basic authentication; new password must be at least 12 characters)
- `GET /api/status?target=` — compact RAG/quality status for one target, suitable for external monitoring integrations
- `GET /api/latest` — current status per target (for status cards / alerting integration)
- `GET /api/alerts?limit=50` — logged alert events
- `GET /api/alerts?limit=10&recent_minutes=30` — recent dashboard alert window
- `DELETE /api/alerts` — clear logged alert events only
- `GET /api/maintenance/stats` — row counts and DB size
- `GET /api/settings/retention` / `PUT /api/settings/retention` — automatic prune retention days
- `POST /api/maintenance/prune?retention_days=30` — prune old run history
- `POST /api/maintenance/vacuum` — compact SQLite DB/WAL
- `GET /api/summary?target=&window=1h|24h|7d|30d|custom` — time series for charts
- `GET /api/runs?target=&window=&limit=` — raw run list
- `GET /api/runs/{id}/hops` — full hop-by-hop path for one run
- `GET /api/export.csv?target=&window=` — CSV export for reports

Custom windows use ISO datetimes:

```text
/api/summary?target=target.example.com&window=custom&start=2026-09-24T12:00:00Z&end=2026-09-24T14:00:00Z
```

Invalid windows and malformed or reversed custom ranges return HTTP 400. Chart summaries
are evenly sampled to at most 2,000 points for responsiveness; CSV exports retain every
run in the selected range. In `/api/status`, `service_reachable` is `null` when no
service-port or endpoint probe is configured; an unconfigured service is not treated as
unreachable.

## Notes / things to double-check for your environment

- **Admin sign-in**: Admin is protected by a username and password. The first-time
  password is `password`; change it when prompted. Your new password is saved as a hash
  in your local `config.yaml`. If you manage the password with the
  `PATHSCOPE_ADMIN_PASSWORD_SHA256` environment variable, update that variable and restart
  PathScope instead; the password form will be disabled.
- **Read-only API access**: Dashboard and monitoring APIs are public by default so
  integrations can use them. To require the Admin credentials for these APIs, set
  `read_api_auth_required: true` in `config.yaml` or `PATHSCOPE_READ_API_AUTH_REQUIRED=true`.
  This also means the dashboard needs those credentials to load its data.
- **LDAP/SSO**: for Active Directory, Entra ID, Okta, Duo, or other SSO, put the app
  behind a reverse proxy such as NGINX, Caddy, Traefik, oauth2-proxy, Authelia, or
  an enterprise access gateway. Keep the app bound internally and let the proxy handle
  OIDC/SAML/LDAP auth, session cookies, MFA, groups, and TLS.

- **Exact firewall ports**: Service ports vary by provider and deployment. Confirm the
  requirements for your environment and update `tcp_ports` (and the STUN port, if used) in
  `config.yaml` — this app does not guess vendor-specific port ranges. Add any additional
  signaling or service hosts as new entries under `targets:`.
- **MTR probe type**: Some service edges may drop default ICMP/UDP-style traceroute probes
  while still answering TCP/443. The bundled config uses `mtr.protocol: tcp` and
  `mtr.port: 443` as a common starting point; adjust these settings for your environment.
  You can test TCP/443 manually with `mtr --tcp -P 443`.
  Each target can override MTR mode from `/admin`: TCP, UDP, or ICMP/ping-style MTR. ICMP
  MTR does not use a port; TCP/UDP MTR use the configured MTR port.
- **Endpoint probe mode**: the global `endpoint_probe:` block provides defaults, and each
  target can override endpoint probe enabled/protocol/count/port from `/admin`. TCP connect
  probes are the most reliable final-destination signal when ICMP is blocked. Use ICMP only
  when your network and target allow classic ping.
- **DNS sinkhole detection**: `dns_sinkhole_ranges` flags resolved IPs that land in
  configured security redirect/sinkhole networks. Set the ranges used by your environment;
  this uses only local/internal DNS resolution and does not call external public resolvers.
- **DSCP/TOS marking**: each target can set a DSCP value from `/admin`. The app applies it
  to MTR, TCP connect checks, TLS checks, endpoint probes, and STUN where the OS/tool supports
  setting IPv4 TOS. Linux tools use the TOS byte, so the app maps `TOS = DSCP << 2` (for
  example EF/46 becomes TOS byte 184). Common choices are CS0/0 for best effort, AF41/34 for
  video, CS5/40 for signaling, and EF/46 for voice/media testing.
- **Jitter meaning**: `dest_jitter_ms` is MTR probe standard deviation at the effective
  destination hop. It is a useful early-warning signal for unstable latency, but it is not
  true RTP/WebRTC media jitter. True media jitter requires a cooperating RTP/WebRTC/UDP
  receiver or a successful STUN/TURN synthetic check.
- **TLS timing**: `tls.enabled: true` adds a `tls/443` check beside `tcp/443` in status cards.
  It measures TCP+TLS handshake time using SNI for the target hostname.
- **Path-change detection**: a path-change alert means the responsive hop signature changed
  from the previous successful run. This is useful for carrier/routing drift, but it may fire
  when DNS load-balancing legitimately moves the target to a different edge.
- **Alerting**: configure thresholds and optional webhook under `alerts:` in `config.yaml`.
  Webhooks receive JSON with `target`, `severity`, `kind`, `message`, and `run_id`.
  Individual targets can override `alert_latency_ms`, `alert_jitter_ms`, `alert_loss_pct`,
  and `alert_path_change` from the `/admin` page or directly in `config.yaml`.
- **GeoIP accuracy**: `ip-api.com`'s free tier is rate-limited (45 req/min) and best-effort.
  For production-scale or offline use, swap `app/probes/geoip.py` to a local MaxMind
  GeoLite2 `.mmdb` file via the `geoip2` package instead of the HTTP calls.
- **Multiple vantage points**: you can run this same container from multiple sites/regions
  (branch offices, cloud regions, home ISP) against
  the same or a shared dashboard/DB to compare path/latency by location — that's the
  biggest "what am I missing" gap versus a single-host MTR: MTR only tells you the path
  *from where you run it*, not from your agents' actual locations.
- **Target management security**: Admin can add/edit/remove monitored targets and write them
  back to `config.yaml`. Keep this app on a trusted internal network, enable local admin auth,
  or put SSO/IP allow-listing in front of it before exposing it more broadly.
- **Database cleanup**: `/admin` includes maintenance actions to prune history older than a
  chosen number of days and compact the SQLite database (`VACUUM`) afterward.

## Storage roadmap

See [docs/storage-and-timeseries-roadmap.md](docs/storage-and-timeseries-roadmap.md) for SQLite growth estimates, rollup ideas, and a future PostgreSQL/TimescaleDB migration path.

## Monitoring integrations

External monitoring systems can use `GET /api/status?target=<host>` for a compact per-target
health summary or `GET /api/latest` for all configured targets. The full dashboard remains
available for charts, alerts, and hop-level troubleshooting.

Run the focused regression suite with:

```bash
python -m unittest discover -s tests -v
```
