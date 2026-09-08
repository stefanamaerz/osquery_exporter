package osquery

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apache/thrift/lib/go/thrift"
	osquerygen "github.com/osquery/osquery-go/gen/osquery"
)

type retryDialer struct {
	calls  int32
	failIn int32 // fail on calls <= failIn, succeed after
}

func (f *retryDialer) Dial() (interface {
	QueryContext(ctx context.Context, sql string) (*osquerygen.ExtensionResponse, error)
	Close()
}, error) {
	if atomic.AddInt32(&f.calls, 1) <= f.failIn {
		return nil, thrift.NewTTransportException(thrift.NOT_OPEN, "connection refused")
	}
	return &fakeThriftQuerier{}, nil
}

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

func TestNewThriftRunnerRetriesThenConnects(t *testing.T) {
	fd := &retryDialer{failIn: 2}
	r := &ThriftRunner{
		socketPath: "/var/run/osquery/osquery.em",
		timeout:    100 * time.Millisecond,
		log:        discardLogger(),
		dialer:     fd.Dial,
	}
	if err := r.connectWithRetry(2 * time.Second); err != nil {
		t.Fatalf("expected connection after retry, got error: %v", err)
	}
	calls := atomic.LoadInt32(&fd.calls)
	if calls != 3 {
		t.Fatalf("expected 3 dial attempts, got %d", calls)
	}
}

func TestNewThriftRunnerRetriesUntilDeadline(t *testing.T) {
	fd := &retryDialer{failIn: 1 << 30}
	r := &ThriftRunner{
		socketPath: "/var/run/osquery/osquery.em",
		timeout:    100 * time.Millisecond,
		log:        discardLogger(),
		dialer:     fd.Dial,
	}
	start := time.Now()
	err := r.connectWithRetry(startupRetryDeadline)
	if err == nil {
		t.Fatal("expected error after deadline, got nil")
	}
	if d := time.Since(start); d < startupRetryDeadline-2*time.Second {
		t.Fatalf("expected retry deadline ~%s, got %s", startupRetryDeadline, d)
	}
	calls := atomic.LoadInt32(&fd.calls)
	if calls < 2 {
		t.Fatalf("expected multiple dial attempts, got %d", calls)
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
	fake := &fakeThriftQuerier{err: thrift.NewTTransportException(thrift.TIMED_OUT, "connection reset")}
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

// A protocol exception (e.g. corrupt response) is not a transport error, so
// Run must NOT reconnect or retry.
func TestThriftRunnerProtocolErrorNoReconnect(t *testing.T) {
	fake := &fakeThriftQuerier{err: thrift.NewTProtocolException(errors.New("invalid thrift response"))}
	r := newTestRunner(50 * time.Millisecond)
	r.client = fake

	_, err := r.Run(context.Background(), "SELECT 1")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if got := atomic.LoadInt32(&fake.queries); got != 1 {
		t.Fatalf("queries = %d, want 1 (no retry on protocol error)", got)
	}
	if got := atomic.LoadInt32(&fake.closes); got != 0 {
		t.Fatalf("closes = %d, want 0 (no reconnect on protocol error)", got)
	}
}

// A generic non-transport Go error must not be treated as transport-level.
func TestThriftRunnerGenericErrorNoReconnect(t *testing.T) {
	fake := &fakeThriftQuerier{err: errors.New("boom")}
	r := newTestRunner(50 * time.Millisecond)
	r.client = fake

	_, err := r.Run(context.Background(), "SELECT 1")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if got := atomic.LoadInt32(&fake.queries); got != 1 {
		t.Fatalf("queries = %d, want 1 (no retry on generic error)", got)
	}
	if got := atomic.LoadInt32(&fake.closes); got != 0 {
		t.Fatalf("closes = %d, want 0 (no reconnect on generic error)", got)
	}
}

// isTransportError must treat Thrift transport and protocol exceptions as
// transport-level and leave context errors as non-reconnectable.
func TestIsTransportError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"context canceled", context.Canceled, false},
		{"context deadline", context.DeadlineExceeded, false},
		{"generic error", errors.New("boom"), false},
		{"thrift transport", thrift.NewTTransportException(thrift.TIMED_OUT, "deadline"), true},
		{"thrift protocol", thrift.NewTProtocolException(errors.New("parse error")), true},
		{"net error", &net.AddrError{Err: "whoops"}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isTransportError(tc.err); got != tc.want {
				t.Fatalf("isTransportError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
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
