package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"html"
	"log/slog"
	"net"
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

// shutdownGracePeriod is the maximum time graceful shutdown waits for
// in-flight HTTP requests and osquery queries to finish.
const shutdownGracePeriod = 10 * time.Second

// parseCacheTTL parses a cache_ttl string. An empty string disables caching.
func parseCacheTTL(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	ttl, err := time.ParseDuration(s)
	if err != nil {
		return 0, err
	}
	if ttl < 0 {
		return 0, fmt.Errorf("negative duration %v", ttl)
	}
	return ttl, nil
}

// runConfig groups the command-line settings that influence HTTP serving.
type runConfig struct {
	metricsPath            string
	enableRuntimeGoMetrics bool
	maxRequestsInFlight    int
	defaultCacheTTL        time.Duration
}

// run builds the collector and HTTP server, serves until ctx is cancelled, then
// performs a graceful shutdown. It returns after srv.Shutdown has returned so
// callers can release resources deterministically.
func run(ctx context.Context, log *slog.Logger, runner collector.Runner, config model.Config, rc runConfig, ln net.Listener) error {
	c, err := collector.NewOsqueryCollector(runner, config.Metrics, log, collector.NewOsqueryCollectorOptions{
		DefaultCacheTTL: rc.defaultCacheTTL,
	})
	if err != nil {
		return fmt.Errorf("invalid metric configuration: %w", err)
	}
	// Propagate the shutdown context into running scrapes. When the context is
	// cancelled (SIGINT/SIGTERM), in-flight osquery queries are interrupted
	// safely: the Thrift client respects context cancellation and the runner
	// only reconnects on transport errors, not on context cancellation.
	c.ShutdownContext(ctx)

	reg := prometheus.NewRegistry()
	reg.MustRegister(c)
	if rc.enableRuntimeGoMetrics {
		reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	}

	prometheus.DefaultRegisterer = reg
	prometheus.DefaultGatherer = reg

	handler := promhttp.HandlerFor(prometheus.DefaultGatherer, promhttp.HandlerOpts{
		ErrorHandling:       promhttp.ContinueOnError,
		ErrorLog:            slog.NewLogLogger(log.Handler(), slog.LevelError),
		MaxRequestsInFlight: rc.maxRequestsInFlight,
		Timeout:             60 * time.Second,
		Registry:            prometheus.DefaultRegisterer, // exposes promhttp_metric_handler_errors_total
	})

	mux := http.NewServeMux()
	mux.Handle(rc.metricsPath, handler)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(fmt.Sprintf(`<html>
<head><title>Osquery Exporter</title></head>
<body>
<h1>Osquery Exporter</h1>
<p><a href="%s">Metrics</a></p>
</body>
</html>`, html.EscapeString(rc.metricsPath))))
	})

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      90 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	shutdownDone := make(chan struct{})
	go func() {
		<-ctx.Done()
		log.Info("received shutdown signal", "reason", ctx.Err())

		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGracePeriod)
		defer cancel()

		log.Info("starting graceful shutdown", "grace_period", shutdownGracePeriod)
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Error("graceful shutdown timed out or failed", "error", err)
		} else {
			log.Info("graceful shutdown complete")
		}
		close(shutdownDone)
	}()

	log.Info("listening", "address", ln.Addr().String())
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("http server failed: %w", err)
	}

	<-shutdownDone
	return nil
}

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

	defaultCacheTTL, err := parseCacheTTL(config.OsQueryRuntime.CacheTTL)
	if err != nil {
		log.Error("invalid runtime.cache_ttl", "value", config.OsQueryRuntime.CacheTTL, "error", err)
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ln, err := net.Listen("tcp", *listenAddress)
	if err != nil {
		log.Error("failed to listen", "address", *listenAddress, "error", err)
		os.Exit(1)
	}

	rc := runConfig{
		metricsPath:            *metricsPath,
		enableRuntimeGoMetrics: *enableRuntimeGoMetrics,
		maxRequestsInFlight:    *maxRequestsInFlight,
		defaultCacheTTL:        defaultCacheTTL,
	}

	if err := run(ctx, log, runner, config, rc, ln); err != nil {
		log.Error("run failed", "error", err)
		os.Exit(1)
	}

	log.Info("shutdown complete, exiting")
}
