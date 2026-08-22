package integration

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stefanamaerz/osquery_exporter/collector"
	"github.com/stefanamaerz/osquery_exporter/model"
	"github.com/stefanamaerz/osquery_exporter/osquery"
)

func lookupOsqueryd(t *testing.T) (string, bool) {
	t.Helper()
	exe, err := exec.LookPath("osqueryd")
	if err != nil {
		return "", false
	}
	return exe, true
}

func skipIfNoOsqueryd(t *testing.T) string {
	t.Helper()
	exe, ok := lookupOsqueryd(t)
	if !ok {
		t.Skip("osqueryd not found in PATH; skipping integration test")
	}
	return exe
}

func infoLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

func TestThriftRunnerWithRealOsqueryd(t *testing.T) {
	socketPath := startOsqueryd(t)

	r, err := osquery.NewThriftRunner(socketPath, "10s", infoLog())
	if err != nil {
		t.Fatalf("NewThriftRunner failed: %v", err)
	}
	t.Cleanup(r.Close)

	res, err := r.Run(context.Background(), "SELECT 1 AS one")
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(res.Items) != 1 {
		t.Fatalf("expected 1 row, got %d", len(res.Items))
	}
	if got := res.Items[0]["one"]; got != "1" {
		t.Fatalf("one = %q, want 1", got)
	}
	if res.Runtime <= 0 {
		t.Fatalf("Runtime = %v, want positive", res.Runtime)
	}
}

func TestCollectorWithRealOsqueryd(t *testing.T) {
	socketPath := startOsqueryd(t)

	r, err := osquery.NewThriftRunner(socketPath, "10s", infoLog())
	if err != nil {
		t.Fatalf("NewThriftRunner failed: %v", err)
	}
	t.Cleanup(r.Close)

	m := model.Metrics{
		Gauges: []model.Gauge{
			{Metric: model.Metric{Name: "osquery_info_up", Help: "up metric", Querystring: "SELECT 1 AS up FROM osquery_info", ValueIdentifier: "up"}},
		},
	}
	c := collector.NewOsqueryCollector(r, m, infoLog())
	ch := make(chan prometheus.Metric, 10)
	go func() {
		c.Collect(ch)
		close(ch)
	}()

	count := 0
	for range ch {
		count++
	}
	if count < 1 {
		t.Fatalf("expected at least 1 metric, got %d", count)
	}
}

// startOsqueryd launches a real osqueryd in ephemeral mode and returns the
// extension socket path. It skips the test if osqueryd is not installed.
func startOsqueryd(t *testing.T) string {
	t.Helper()
	skipIfNoOsqueryd(t)

	dir := t.TempDir()
	socketPath := dir + "/osquery.em"

	cmd := exec.Command("osqueryd",
		"--pidfile="+dir+"/osquery.pid",
		"--database_path="+dir+"/osquery.db",
		"--extensions_socket="+socketPath,
		"--logger_plugin=stdout",
		"--disable_logging=true",
		"--disable_events",
		"--ephemeral",
	)
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start osqueryd: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })

	// Wait for the socket to appear.
	waitForSocket(t, socketPath)
	return socketPath
}

func waitForSocket(t *testing.T, socketPath string) {
	t.Helper()
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(socketPath); err == nil {
			return
		}
	}
	t.Fatalf("osqueryd extension socket %q did not appear", socketPath)
}
