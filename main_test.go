package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stefanamaerz/osquery_exporter/model"
)

func TestParseCacheTTL(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    time.Duration
		wantErr bool
	}{
		{"empty disables caching", "", 0, false},
		{"zero explicit", "0", 0, false},
		{"zero seconds", "0s", 0, false},
		{"positive seconds", "30s", 30 * time.Second, false},
		{"minutes", "5m", 5 * time.Minute, false},
		{"negative", "-5s", 0, true},
		{"invalid", "garbage", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseCacheTTL(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseCacheTTL(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("parseCacheTTL(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

type controlledRunner struct {
	started chan struct{}
	finish  chan struct{}
}

func (r *controlledRunner) Run(ctx context.Context, query string) (*model.OsqueryResult, error) {
	_ = ctx
	close(r.started)
	<-r.finish
	return &model.OsqueryResult{Items: []model.OsqueryItem{{"count": "1"}}}, nil
}

type fastRunner struct{}

func (fastRunner) Run(ctx context.Context, query string) (*model.OsqueryResult, error) {
	return &model.OsqueryResult{Items: []model.OsqueryItem{{"count": "1"}}}, nil
}

func testConfig() model.Config {
	return model.Config{
		Metrics: model.Metrics{
			Counters: []model.Counter{
				{Metric: model.Metric{Name: "ones", Help: "ones", Querystring: "SELECT 1", ValueIdentifier: "count"}},
			},
		},
	}
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestRunGracefulShutdown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	rc := runConfig{
		metricsPath:         "/metrics",
		maxRequestsInFlight: 2,
	}

	done := make(chan error, 1)
	go func() {
		done <- run(ctx, discardLogger(), fastRunner{}, testConfig(), rc, ln)
	}()

	// Wait briefly for the server to start accepting.
	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not shut down gracefully")
	}
}

func TestRunShutdownWaitsForInFlightRequest(t *testing.T) {
	runner := &controlledRunner{
		started: make(chan struct{}),
		finish:  make(chan struct{}),
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	rc := runConfig{
		metricsPath:         "/metrics",
		maxRequestsInFlight: 2,
	}

	done := make(chan error, 1)
	go func() {
		done <- run(ctx, discardLogger(), runner, testConfig(), rc, ln)
	}()

	// Start a request so there is an in-flight scrape during shutdown.
	url := "http://" + ln.Addr().String() + rc.metricsPath
	reqDone := make(chan struct{})
	go func() {
		defer close(reqDone)
		//nolint:bodyclose // test request; response body is empty
		_, _ = http.Get(url)
	}()

	select {
	case <-runner.started:
	case <-time.After(2 * time.Second):
		t.Fatal("runner did not start")
	}

	// Initiate shutdown while the scrape is still running.
	cancel()

	// Give run a moment to enter Shutdown; it should still be waiting for runner.
	select {
	case <-done:
		t.Fatal("run returned before in-flight request completed")
	case <-time.After(200 * time.Millisecond):
	}

	// Allow the in-flight request to finish.
	close(runner.finish)

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not finish after in-flight request completed")
	}

	select {
	case <-reqDone:
	case <-time.After(2 * time.Second):
		t.Fatal("in-flight request did not complete")
	}
}

func startTestServer(t *testing.T, rc runConfig) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- run(ctx, discardLogger(), fastRunner{}, testConfig(), rc, ln)
	}()

	url := "http://" + ln.Addr().String() + rc.metricsPath
	cleanup := func() {
		cancel()
		<-done
	}
	return url, cleanup
}

func TestRunRejectsOversizedHeaders(t *testing.T) {
	rc := runConfig{
		metricsPath:         "/metrics",
		maxRequestsInFlight: 2,
		maxHeaderBytes:      8 << 10,
	}
	url, cleanup := startTestServer(t, rc)
	defer cleanup()

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	// A single 16 KiB header exceeds the 8 KiB MaxHeaderBytes limit.
	req.Header.Set("X-Large", strings.Repeat("x", 16<<10))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusRequestHeaderFieldsTooLarge)
	}
}

func TestRunAllowsNormalHeaders(t *testing.T) {
	rc := runConfig{
		metricsPath:         "/metrics",
		maxRequestsInFlight: 2,
		maxHeaderBytes:      8 << 10,
	}
	url, cleanup := startTestServer(t, rc)
	defer cleanup()

	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("get failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

func TestParseByteSize(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"1024", 1024},
		{"1KB", 1024},
		{"1KiB", 1024},
		{"2MB", 2 << 20},
		{"1.5MB", 1572864},
		{"  8KB  ", 8192},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := parseByteSize(tt.input)
			if err != nil {
				t.Fatalf("parseByteSize(%q) error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Fatalf("parseByteSize(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}

	if _, err := parseByteSize("-1"); err == nil {
		t.Fatal("expected error for negative size")
	}
	if _, err := parseByteSize("abc"); err == nil {
		t.Fatal("expected error for invalid size")
	}
}
