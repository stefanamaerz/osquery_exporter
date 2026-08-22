package integration

import (
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stefanamaerz/osquery_exporter/collector"
	"github.com/stefanamaerz/osquery_exporter/model"
	"github.com/stefanamaerz/osquery_exporter/osquery"
)

func lookupOsqueryi(t *testing.T) (string, bool) {
	t.Helper()
	exe, err := exec.LookPath("osqueryi")
	if err != nil {
		return "", false
	}
	return exe, true
}

func skipIfNoOsqueryi(t *testing.T) string {
	t.Helper()
	exe, ok := lookupOsqueryi(t)
	if !ok {
		t.Skip("osqueryi not found in PATH; skipping integration test")
	}
	return exe
}

func infoLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

func TestRunnerWithRealOsqueryi(t *testing.T) {
	skipIfNoOsqueryi(t)

	r, err := osquery.NewRunner("osqueryi", "10s", nil, infoLog())
	if err != nil {
		t.Fatalf("NewRunner failed: %v", err)
	}
	res, err := r.Run("SELECT 1 AS one")
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

func TestCollectorWithRealOsqueryi(t *testing.T) {
	skipIfNoOsqueryi(t)

	r, err := osquery.NewRunner("osqueryi", "10s", nil, infoLog())
	if err != nil {
		t.Fatalf("NewRunner failed: %v", err)
	}
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

func TestRunnerWithFakeBinary(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "osqueryi")
	script := `#!/bin/sh
printf '[{"answer":"42"}]\n'
`
	if err := os.WriteFile(fake, []byte(script), 0755); err != nil {
		t.Fatalf("failed to write fake binary: %v", err)
	}

	r, err := osquery.NewRunner(fake, "10s", nil, infoLog())
	if err != nil {
		t.Fatalf("NewRunner failed: %v", err)
	}
	res, err := r.Run("SELECT 42 AS answer")
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if got := res.Items[0]["answer"]; got != "42" {
		t.Fatalf("answer = %q, want 42", got)
	}
}

func TestRunnerTimeout(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "osqueryi")
	// Loop forever so the context cancellation is the only way out.
	// Using a shell loop instead of `sleep` avoids relying on signal handling
	// for child process group termination.
	script := `#!/bin/sh
while true; do
  true
 done
`
	if err := os.WriteFile(fake, []byte(script), 0755); err != nil {
		t.Fatalf("failed to write fake binary: %v", err)
	}

	r, err := osquery.NewRunner(fake, "50ms", nil, infoLog())
	if err != nil {
		t.Fatalf("NewRunner failed: %v", err)
	}
	start := time.Now()
	_, err = r.Run("SELECT 1")
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("timeout took too long: %v", time.Since(start))
	}
}
