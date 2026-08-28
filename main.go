package main

import (
	"context"
	"flag"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/stefanamaerz/osquery_exporter/collector"
	"github.com/stefanamaerz/osquery_exporter/model"
	"github.com/stefanamaerz/osquery_exporter/osquery"
	"github.com/stefanamaerz/osquery_exporter/version"
	"gopkg.in/yaml.v3"
)

func main() {
	var (
		configFile             = flag.String("config.file", "config.yaml", "Config file")
		listenAddress          = flag.String("web.listen-address", ":9232", "Address on which to expose metrics and web interface.")
		metricsPath            = flag.String("web.telemetry-path", "/metrics", "Path under which to expose metrics.")
		enableRuntimeGoMetrics = flag.Bool("web.enable-runtime-golang-metrics", true, "Expose Go runtime and process metrics on /metrics.")
		maxRequestsInFlight    = flag.Int("web.max-requests-in-flight", 2, "Maximum number of simultaneous /metrics scrapes. 0 disables the limit.")
		printVersion           = flag.Bool("version", false, "Print version and exit")
	)
	flag.Parse()

	if *printVersion {
		fmt.Println(version.Version)
		os.Exit(0)
	}

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

	if config.OsQueryRuntime.SocketPath == "" {
		log.Error("missing required runtime.socket_path")
		os.Exit(1)
	}

	if err := model.ResolveQueryRefs(&config); err != nil {
		log.Error("invalid metric configuration", "error", err)
		os.Exit(1)
	}

	log.Info("connecting to osqueryd", "socket_path", config.OsQueryRuntime.SocketPath, "timeout", config.OsQueryRuntime.Timeout)
	runner, err := osquery.NewThriftRunner(config.OsQueryRuntime.SocketPath, config.OsQueryRuntime.Timeout, log)
	if err != nil {
		log.Error("failed to create osquery runner", "error", err)
		os.Exit(1)
	}
	defer runner.Close()

	c, err := collector.NewOsqueryCollector(runner, config.Metrics, log)
	if err != nil {
		log.Error("invalid metric configuration", "error", err)
		os.Exit(1)
	}

	reg := prometheus.NewRegistry()
	reg.MustRegister(c)
	if *enableRuntimeGoMetrics {
		reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	}

	prometheus.DefaultRegisterer = reg
	prometheus.DefaultGatherer = reg

	handler := promhttp.HandlerFor(prometheus.DefaultGatherer, promhttp.HandlerOpts{
		ErrorHandling:       promhttp.ContinueOnError,
		ErrorLog:            slog.NewLogLogger(log.Handler(), slog.LevelError),
		MaxRequestsInFlight: *maxRequestsInFlight,
		Timeout:             60 * time.Second,
		Registry:            prometheus.DefaultRegisterer, // exposes promhttp_metric_handler_errors_total
	})

	mux := http.NewServeMux()
	mux.Handle(*metricsPath, handler)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(fmt.Sprintf(`<html>
<head><title>Osquery Exporter</title></head>
<body>
<h1>Osquery Exporter</h1>
<p><a href="%s">Metrics</a></p>
</body>
</html>`, html.EscapeString(*metricsPath))))
	})

	srv := &http.Server{
		Addr:              *listenAddress,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      90 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	log.Info("listening", "address", *listenAddress)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Error("http server failed", "error", err)
		os.Exit(1)
	}
}
