# osquery_exporter

Exporter for exposing [osquery](https://osquery.io) query results to [Prometheus](https://prometheus.io).

This is a fork of the original `zwopir/osquery_exporter` prototype, modernized for current Go and Prometheus client libraries.

## Installation

Install osquery from <https://osquery.io/downloads/>.

Build requires Go 1.27 or later:

```bash
git clone https://github.com/stefanamaerz/osquery_exporter.git
cd osquery_exporter
go build
```

## Usage

The exporter connects to a running `osqueryd` over its Thrift extension socket. Start `osqueryd` with an extensions socket, for example:

```bash
osqueryd --extensions_socket=/var/run/osquery/osquery.em
```

Then run the exporter:

```bash
./osquery_exporter -config.file=config.yaml
```

Command-line flags:

```
-config.file string
    Config file (default "config.yaml")
-web.listen-address string
    Address on which to expose metrics and web interface. (default ":9232")
-web.telemetry-path string
    Path under which to expose metrics. (default "/metrics")
```

The configuration file is mandatory; flags have sensible defaults.

## Configuration

The exporter is driven by a YAML config file. See `config_example.yaml` for a full example.

```yaml
runtime:
  socket_path: "/var/run/osquery/osquery.em"
  timeout: 10s

metrics:
  counters: []
  countervecs: []
  gauges:
    - name: history_lines_count
      help: "number of entries in the history"
      query: "select count(*) as count from shell_history"
      valueidentifier: count
    - name: block_devices
      help: "number of block devices which are not partitions"
      query: "select count(*) as count from block_devices where parent = ''"
      valueidentifier: count
  gaugevecs:
    - name: last_users_count
      help: "number of last logins by username and tty"
      query: "select username, tty, count(*) as count from last where username != '' group by username, tty"
      valueidentifier: count
      labelidentifier:
        - username
        - tty
    - name: users_by_shell
      help: "number of users by login shell"
      query: "select count(*) as count, shell from users group by shell"
      valueidentifier: count
      labelidentifier:
        - shell
```

`runtime.socket_path` is required and must point at `osqueryd`'s Thrift extension socket.

`runtime.timeout` bounds both the socket wait time and the query execution time.

### Metric types

- `counters` and `gauges` expect queries that return a single row with a single numeric value.
- `countervecs` and `gaugevecs` expect queries that return multiple rows. Each row must include the columns listed in `labelidentifier`, plus the value column named by `valueidentifier`.

**Important:** Only use `counters`/`countervecs` for values that are monotonically increasing over time. Most `count(*)` queries in osquery return values that can decrease (history truncation, log rotation, row deletion), so they should be `gauges`/`gaugevecs`. Using a `counter` for a non-monotonic value causes `rate()` and `increase()` to produce spurious counter-reset artifacts. See:

- <https://prometheus.io/docs/concepts/metric_types/>
- <https://prometheus.io/docs/practices/naming/>

### Implicit exporter metrics

In addition to metrics defined in the config, the exporter exposes:

- `osquery_exporter_query_duration_seconds{name="..."}` — query execution duration summary.
- `osquery_exporter_query_success{name="..."}` — `1` success, `0` error.
- `osquery_exporter_resultsets{name="..."}` — number of result rows per defined query.

## Development

```bash
go build ./...
go vet ./...
go test ./...
```

### Load testing

`util/test_exporter.py` (Linux only) checks correctness and measures CPU/RSS of `osqueryd` and the exporter under load. By default it drives max throughput (closed-loop); use `--load-rps` for a realistic, fixed scrape rate (open-loop):

```bash
# Simulate Prometheus scraping once every 5s for 60s
python3 util/test_exporter.py --load-only --load-duration 60 --load-rps 0.2
```

Latency is measured per request after the rate limiter grants a slot, so throttling never inflates p50/p95. Omit `--load-rps` for unthrottled max-throughput.

## License

See [LICENSE](LICENSE).
