# Storage and Time-Series Roadmap

This note captures expected database growth and the recommended path if PathScope grows from a small local monitor into a multi-site network-monitoring platform.

## Current SQLite posture

SQLite is fine for the current shape of the app:

- A few targets
- One local vantage point
- One probe per target per minute
- 30-day raw retention

Example estimate:

```text
2 targets * 1,440 runs/day = 2,880 runs/day
2,880 runs/day * ~20 hops = ~57,600 hop rows/day
```

Expected storage is roughly:

```text
~10 MB to 60 MB/day
~300 MB to 1.5 GB over 30 days
```

Actual size depends on:

- hop count
- number of targets
- probe interval
- retention window
- alert volume
- ASN/org/city metadata string duplication
- SQLite WAL/checkpoint behavior

SQLite sidecar files may appear:

```text
data/monitor.db
data/monitor.db-wal
data/monitor.db-shm
```

The Admin page's **Compact Database** action runs checkpoint/VACUUM to reclaim space after pruning/deletes.

## First optimization: reduce duplicated hop metadata

Current hop rows include repeated metadata:

```text
asn
org
country
city
```

That is convenient but wasteful because the same hop IP appears across many runs.

Recommended SQLite optimization:

```text
hop_ip_metadata
- ip
- asn
- org
- country
- city
- last_seen

hops
- run_id
- hop_num
- ip
- loss_pct
- sent
- last_ms
- avg_ms
- best_ms
- worst_ms
- stdev_ms
```

Benefits:

- smaller hop rows
- less repeated text
- easier metadata refresh/update
- lower long-term DB growth

## Second optimization: rollups

Keep raw per-run/per-hop data for troubleshooting, but do not keep it forever.

Recommended retention model:

```text
Raw runs/hops/port checks: 30 days
5-minute target rollups: 180 days
Hourly target rollups: 1-2 years
Alerts: 1 year, or separate policy
```

Useful rollup fields:

```text
target_rollups_5m
- bucket_start
- target
- samples
- avg_latency_ms
- p95_latency_ms
- avg_endpoint_ms
- p95_endpoint_ms
- avg_jitter_ms
- p95_jitter_ms
- avg_loss_pct
- max_loss_pct
- path_change_count
- availability_pct
```

This preserves long-term trend visibility without keeping every raw hop forever.

## Best production backend: PostgreSQL + TimescaleDB

If this app becomes multi-target, multi-site, or multi-year, use TimescaleDB.

Why TimescaleDB fits:

- SQL remains familiar
- hypertables are purpose-built for time-series data
- compression reduces long-term storage cost
- retention policies can automatically prune raw data
- continuous aggregates handle 5-minute/hourly summaries
- still supports relational questions about targets, paths, alerts, and metadata

Good fit for queries like:

- show latency/jitter/loss over time by target
- compare vantage points
- detect path changes by carrier/ASN
- find runs where a specific ASN appeared
- keep raw data short-term and summaries long-term

## Less ideal alternatives

### InfluxDB

Good for basic metrics:

- latency
- jitter
- loss
- availability

Less ideal for:

- hop-by-hop path rows
- ASN/org metadata joins
- path signature history
- relational alert/run/hop queries

### Prometheus / VictoriaMetrics

Excellent for gauges/counters and alerting, but not ideal for storing full per-run path topology.

### ClickHouse

Very strong for large analytical/event histories. Good future option if the data volume becomes huge, but more operational complexity than TimescaleDB for this app's expected path.

## Recommended migration phases

### Phase 1: Optimize SQLite

- add `hop_ip_metadata`
- reduce repeated hop metadata
- add Admin DB stats page/section
- keep raw retention at 30 days
- continue using SQLite for local/small deployments

### Phase 2: Add rollups

- add 5-minute rollup table
- optionally add hourly rollup table
- expose rollup-backed charts for windows beyond raw retention
- prune raw rows aggressively while retaining summary history

### Phase 3: Add optional TimescaleDB backend

Add config support:

```yaml
database:
  url: sqlite:///data/monitor.db
```

or:

```yaml
database:
  url: postgresql+psycopg://pathscope:password@timescale:5432/pathscope
```

Implementation notes:

- keep SQLAlchemy models where practical
- use PostgreSQL/Timescale-specific migrations only when the URL is Postgres
- create hypertables for runs/hops/checks/rollups
- enable compression for older raw chunks
- add Timescale retention policies
- keep SQLite as the dev/local/small-site mode

## Practical recommendation

For current local testing:

```text
SQLite + 30-day retention is enough.
```

For production utility VM with a few targets:

```text
SQLite is still acceptable, especially with pruning and VACUUM.
```

For multiple sites/vantage points or long-term history:

```text
Move to PostgreSQL + TimescaleDB with rollups and retention policies.
```
