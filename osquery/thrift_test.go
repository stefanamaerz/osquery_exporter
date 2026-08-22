package osquery

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	osquerygen "github.com/osquery/osquery-go/gen/osquery"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

type fakeThriftQuerier struct {
	resp *osquerygen.ExtensionResponse
	err  error
}

func (f *fakeThriftQuerier) QueryContext(ctx context.Context, sql string) (*osquerygen.ExtensionResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return f.resp, f.err
}

func (f *fakeThriftQuerier) Close() {}

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
	r := &ThriftRunner{
		socketPath: "/tmp/osquery.em",
		timeout:    5 * time.Second,
		log:        discardLogger(),
	}
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

func TestThriftRunnerConnectionError(t *testing.T) {
	r := &ThriftRunner{
		socketPath: "/tmp/osquery.em",
		timeout:    5 * time.Second,
		log:        discardLogger(),
	}
	r.client = &fakeThriftQuerier{err: errors.New("connection refused")}

	_, err := r.Run(context.Background(), "SELECT 1")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestThriftRunnerNilStatus(t *testing.T) {
	r := &ThriftRunner{
		socketPath: "/tmp/osquery.em",
		timeout:    5 * time.Second,
		log:        discardLogger(),
	}
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

func TestThriftRunnerStatusError(t *testing.T) {
	r := &ThriftRunner{
		socketPath: "/tmp/osquery.em",
		timeout:    5 * time.Second,
		log:        discardLogger(),
	}
	r.client = &fakeThriftQuerier{
		resp: &osquerygen.ExtensionResponse{
			Status:   &osquerygen.ExtensionStatus{Code: 1, Message: "boom"},
			Response: []map[string]string{},
		},
	}

	_, err := r.Run(context.Background(), "SELECT 1")
	if err == nil {
		t.Fatal("expected error for non-zero status, got nil")
	}
}

func TestThriftRunnerContextTimeout(t *testing.T) {
	r := &ThriftRunner{
		socketPath: "/tmp/osquery.em",
		timeout:    5 * time.Second,
		log:        discardLogger(),
	}
	r.client = &fakeThriftQuerier{}

	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()

	_, err := r.Run(ctx, "SELECT 1")
	if err == nil {
		t.Fatal("expected context deadline error, got nil")
	}
}

func TestThriftRunnerReconnect(t *testing.T) {
	fake := &fakeThriftQuerier{}
	fake.err = errors.New("connection reset")

	r := &ThriftRunner{
		socketPath: "/tmp/osquery.em",
		timeout:    5 * time.Second,
		log:        discardLogger(),
		client:     fake,
	}

	_, err := r.Run(context.Background(), "SELECT 1")
	if err == nil {
		t.Fatal("expected error after reconnect failure, got nil")
	}
}
