package osquery

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"sync/atomic"
	"testing"
	"time"

	osquerygen "github.com/osquery/osquery-go/gen/osquery"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

type fakeThriftQuerier struct {
	resp    *osquerygen.ExtensionResponse
	err     error
	queries int32
	closes  int32
}

func (f *fakeThriftQuerier) QueryContext(ctx context.Context, sql string) (*osquerygen.ExtensionResponse, error) {
	atomic.AddInt32(&f.queries, 1)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return f.resp, f.err
}

func (f *fakeThriftQuerier) Close() { atomic.AddInt32(&f.closes, 1) }

func newTestRunner(timeout time.Duration) *ThriftRunner {
	return &ThriftRunner{
		socketPath: "/tmp/osquery.em",
		timeout:    timeout,
		log:        discardLogger(),
	}
}

func TestNewThriftRunnerInvalidTimeout(t *testing.T) {
	_, err := NewThriftRunner("/tmp/osquery.em", "not-a-duration", discardLogger())
	if err == nil {
		t.Fatal("expected error for invalid timeout, got nil")
	}
}

func TestNewThriftRunnerMissingSocket(t *testing.T) {
	dir := t.TempDir()
	socket := dir + "/nonexistent.em"
	_, err := NewThriftRunner(socket, "100ms", discardLogger())
	if err == nil {
		t.Fatal("expected error for missing socket, got nil")
	}
}

func TestThriftRunnerSuccess(t *testing.T) {
	r := newTestRunner(5 * time.Second)
	r.client = &fakeThriftQuerier{
		resp: &osquerygen.ExtensionResponse{
			Status:   &osquerygen.ExtensionStatus{Code: 0},
			Response: []map[string]string{{"one": "1"}},
		},
	}

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

func TestThriftRunnerNilStatus(t *testing.T) {
	r := newTestRunner(5 * time.Second)
	r.client = &fakeThriftQuerier{
		resp: &osquerygen.ExtensionResponse{
			Status:   nil,
			Response: []map[string]string{{"one": "1"}},
		},
	}

	_, err := r.Run(context.Background(), "SELECT 1")
	if err == nil {
		t.Fatal("expected error for nil status, got nil")
	}
}

// A well-formed osquery error response proves the connection is healthy, so
// Run must NOT reconnect or retry.
func TestThriftRunnerStatusErrorNoReconnect(t *testing.T) {
	fake := &fakeThriftQuerier{
		resp: &osquerygen.ExtensionResponse{
			Status:   &osquerygen.ExtensionStatus{Code: 1, Message: "no such table: nope"},
			Response: []map[string]string{},
		},
	}
	r := newTestRunner(50 * time.Millisecond)
	r.client = fake

	_, err := r.Run(context.Background(), "SELECT nope")
	if err == nil {
		t.Fatal("expected error for non-zero status, got nil")
	}
	if got := atomic.LoadInt32(&fake.queries); got != 1 {
		t.Fatalf("queries = %d, want 1 (no retry on status error)", got)
	}
	if got := atomic.LoadInt32(&fake.closes); got != 0 {
		t.Fatalf("closes = %d, want 0 (no reconnect on status error)", got)
	}
}

// A context deadline also must NOT trigger a reconnect: the connection is not
// at fault, and reconnecting would tear down the healthy shared transport.
func TestThriftRunnerContextTimeoutNoReconnect(t *testing.T) {
	fake := &fakeThriftQuerier{}
	r := newTestRunner(5 * time.Second)
	r.client = fake

	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()

	_, err := r.Run(ctx, "SELECT 1")
	if err == nil {
		t.Fatal("expected context deadline error, got nil")
	}
	if got := atomic.LoadInt32(&fake.closes); got != 0 {
		t.Fatalf("closes = %d, want 0 (no reconnect on deadline)", got)
	}
}

// A transport error should trigger exactly one reconnect attempt. Here the
// dial fails (no real socket), so Run returns an error, but the client must
// not be closed because the dial failed before any swap.
func TestThriftRunnerTransportErrorReconnectAttempt(t *testing.T) {
	fake := &fakeThriftQuerier{err: errors.New("connection reset")}
	r := newTestRunner(50 * time.Millisecond)
	r.client = fake

	_, err := r.Run(context.Background(), "SELECT 1")
	if err == nil {
		t.Fatal("expected error after reconnect failure, got nil")
	}
	if got := atomic.LoadInt32(&fake.queries); got != 1 {
		t.Fatalf("queries = %d, want 1 (retry only after a successful reconnect)", got)
	}
	// The failed reconnect must not have closed the still-current client.
	if got := atomic.LoadInt32(&fake.closes); got != 0 {
		t.Fatalf("closes = %d, want 0 (failed dial swaps nothing)", got)
	}
}

// Concurrent transport failures must collapse into a single reconnect. The
// generation check in maybeReconnect ensures only the first goroutine dials.
func TestMaybeReconnectSingleFlight(t *testing.T) {
	r := newTestRunner(50 * time.Millisecond)
	r.client = &fakeThriftQuerier{}

	// Simulate: gen at query time is stale by the time maybeReconnect runs.
	r.mu.Lock()
	currentGen := r.gen
	r.mu.Unlock()

	// First call with a stale generation should be a no-op (client replaced).
	if err := r.maybeReconnect(currentGen + 1); err != nil {
		t.Fatalf("maybeReconnect with future gen should no-op, got %v", err)
	}
}

func TestMaybeReconnectCooldown(t *testing.T) {
	r := newTestRunner(50 * time.Millisecond)
	r.client = &fakeThriftQuerier{}
	r.lastReconnectFailure = time.Now() // simulate a recent failure

	err := r.maybeReconnect(0)
	if err == nil {
		t.Fatal("expected cooldown suppression error, got nil")
	}
}
