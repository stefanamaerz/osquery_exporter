package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/stefanamaerz/osquery_exporter/collector"
	"github.com/stefanamaerz/osquery_exporter/model"
	"github.com/stefanamaerz/osquery_exporter/osquery"
	"gopkg.in/yaml.v3"
)

func main() {
	var (
		configFile    = flag.String("config.file", "config.yaml", "Config file")
		listenAddress = flag.String("web.listen-address", ":9232", "Address on which to expose metrics and web interface.")
		metricsPath   = flag.String("web.telemetry-path", "/metrics", "Path under which to expose metrics.")
	)
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	var config model.Config

	data, err := os.ReadFile(*configFile)
	if err != nil {
		log.Error("failed to read config file", "file", *configFile, "error", err)
		os.Exit(1)
	}
	if err := yaml.Unmarshal(data, &config); err != nil {
		log.Error("failed to parse config file", "file", *configFile, "error", err)
		os.Exit(1)
	}

	r, err := osquery.NewRunner(config.OsQueryRuntime.Binary, config.OsQueryRuntime.Timeout, config.OsQueryRuntime.DefaultFlags, log)
	if err != nil {
		log.Error("failed to create osquery runner", "error", err)
		os.Exit(1)
	}

	c := collector.NewOsqueryCollector(r, config.Metrics, log)
	prometheus.MustRegister(c)

	handler := promhttp.HandlerFor(prometheus.DefaultGatherer, promhttp.HandlerOpts{})

	http.Handle(*metricsPath, handler)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(fmt.Sprintf(`<html>
<head><title>Osquery Exporter</title></head>
<body>
<h1>Osquery Exporter</h1>
<p><a href="%s">Metrics</a></p>
</body>
</html>`, *metricsPath)))
	})

	log.Info("listening", "address", *listenAddress)
	if err := http.ListenAndServe(*listenAddress, nil); err != nil {
		log.Error("http server failed", "error", err)
		os.Exit(1)
	}
}
