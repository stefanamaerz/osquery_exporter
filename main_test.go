package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
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
