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

The exporter is driven by a YAML config file. See `config_example.yaml` for a generic Linux/standard osqueryi setup, or `config.macos.yaml` for an example of running against a macOS Fleet/orbit-managed osqueryd binary.

```yaml
runtime:
  osquery: "osqueryi"
  timeout: 10s
  # Optional default flags prepended to every osqueryi invocation.
  default_flags: []

metrics:
  counters:
    - name: history_lines_count
      help: "number of entries in the history"
      query: "select count(*) as count from shell_history"
      valueidentifier: count
  countervecs:
    - name: last_users_count
      help: "number of last logins by username and tty"
      query: "select username, tty, count(*) as count from last where username != '' group by username, tty"
      valueidentifier: count
      labelidentifier:
        - username
        - tty
  gauges:
    - name: block_devices
      help: "number of block devices which are not partitions"
      query: "select count(*) as count from block_devices where parent = ''"
      valueidentifier: count
  gaugevecs:
    - name: users_by_shell
      help: "number of users by login shell"
      query: "select count(*) as count, shell from users group by shell"
      valueidentifier: count
      labelidentifier:
        - shell
```

### Metric types

- `counters` and `gauges` expect queries that return a single row with a single numeric value.
- `countervecs` and `gaugevecs` expect queries that return multiple rows. Each row must include the columns listed in `labelidentifier`, plus the value column named by `valueidentifier`.

It is up to the user to decide whether an osquery query result is semantically a counter or a gauge. See:

- <https://prometheus.io/docs/concepts/metric_types/>
- <https://prometheus.io/docs/practices/naming/>

### Default flags

If your `osqueryi` binary requires extra flags to run in your environment (for example, some macOS installs need a private database path and socket), you can supply them once in `runtime.default_flags` instead of defining a wrapper script.

Example for a Fleet/orbit-managed osqueryd binary:

```yaml
runtime:
  osquery: "/opt/orbit/bin/osqueryd/macos-app/stable/osquery.app/Contents/MacOS/osqueryd"
  timeout: 15s
  default_flags:
    - "--pidfile=/tmp/osquery.pid"
    - "--database_path=/tmp/osquery.db"
    - "--extensions_socket=/tmp/osquery.em"
    - "--logger_plugin=stderr"
    - "--disable_logging=true"
    - "--disable_extensions"
    - "--ephemeral"
    - "--S"
```

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

## License

See [LICENSE](LICENSE).
