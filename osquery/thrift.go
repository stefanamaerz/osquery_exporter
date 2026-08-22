package osquery

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	osquerygo "github.com/osquery/osquery-go"
	osquerygen "github.com/osquery/osquery-go/gen/osquery"
	"github.com/stefanamaerz/osquery_exporter/model"
)

// reconnectCooldown is the minimum interval between reconnect attempts when a
// previous attempt failed. It stops a down osqueryd from costing one blocking
// dial per query per scrape.
const reconnectCooldown = 5 * time.Second

// transportError marks an error as a connection/transport-level failure, as
// opposed to a well-formed osquery error response. Only transport errors
// justify a reconnect; a SQL error or a nil status means the connection
// itself is healthy.
type transportError struct{ err error }

func (e transportError) Error() string { return e.err.Error() }
func (e transportError) Unwrap() error { return e.err }

// thriftQuerier is the minimal interface ThriftRunner needs from the
// osquery-go ExtensionManagerClient. It makes the runner testable without a
// real osqueryd socket.
type thriftQuerier interface {
	QueryContext(ctx context.Context, sql string) (*osquerygen.ExtensionResponse, error)
	Close()
}

// ThriftRunner executes queries by connecting to a running osqueryd over its
// Thrift extension socket.
type ThriftRunner struct {
	socketPath string
	timeout    time.Duration
	log        *slog.Logger

	mu sync.Mutex
	// client is the current shared client. It is never closed while the lock
	// is held; a displaced client is closed after the swap so an in-flight
	// query holding a snapshot is not torn down.
	client thriftQuerier
	// gen increments each time client is replaced. A goroutine only triggers
	// a reconnect if the client it queried on has not already been replaced.
	gen int
	// lastReconnectFailure is the time of the most recent failed reconnect.
	// Reconnect attempts are suppressed until reconnectCooldown has elapsed.
	lastReconnectFailure time.Time
}

// NewThriftRunner creates a runner that connects to osqueryd's Thrift socket.
func NewThriftRunner(socketPath, timeout string, log *slog.Logger) (*ThriftRunner, error) {
	to, err := time.ParseDuration(timeout)
	if err != nil {
		return nil, fmt.Errorf("can't parse timeout for thrift runner: %w", err)
	}

	r := &ThriftRunner{
		socketPath: socketPath,
		timeout:    to,
		log:        log,
	}
	if err := r.reconnect(); err != nil {
		return nil, err
	}
	return r, nil
}

// dial creates a new client. It performs blocking network I/O and must never
// be called with r.mu held.
func (r *ThriftRunner) dial() (thriftQuerier, error) {
	return osquerygo.NewClient(r.socketPath, r.timeout,
		osquerygo.DefaultWaitTime(r.timeout),
		osquerygo.MaxWaitTime(r.timeout),
	)
}

// reconnect replaces the shared client with a freshly dialed one. The dial
// happens outside r.mu so concurrent queries are not blocked behind a slow
// connection attempt. The displaced client is closed only after the new one
// is installed, so an in-flight query holding the old snapshot keeps working.
func (r *ThriftRunner) reconnect() error {
	client, err := r.dial()
	if err != nil {
		r.mu.Lock()
		r.lastReconnectFailure = time.Now()
		r.mu.Unlock()
		return fmt.Errorf("failed to connect to osqueryd thrift socket %q: %w", r.socketPath, err)
	}

	r.mu.Lock()
	old := r.client
	r.client = client
	r.gen++
	r.lastReconnectFailure = time.Time{}
	r.mu.Unlock()

	if old != nil {
		old.Close()
	}
	return nil
}

// maybeReconnect reconnects only if the client that served gen is still
// current (so N concurrent failures trigger at most one reconnect) and the
// reconnect cooldown has elapsed (so a down osqueryd costs one dial per
// cooldown window, not one per query).
func (r *ThriftRunner) maybeReconnect(gen int) error {
	r.mu.Lock()
	if r.gen != gen {
		// Another goroutine already reconnected; reuse the fresh client.
		r.mu.Unlock()
		return nil
	}
	if !r.lastReconnectFailure.IsZero() && time.Since(r.lastReconnectFailure) < reconnectCooldown {
		r.mu.Unlock()
		return errors.New("reconnect suppressed: in cooldown after a recent reconnect failure")
	}
	r.mu.Unlock()

	return r.reconnect()
}

// Run executes the query over the Thrift extension socket.
func (r *ThriftRunner) Run(ctx context.Context, query string) (*model.OsqueryResult, error) {
	begin := time.Now()

	r.log.Debug("running osquery query via thrift", "query", query)

	res, gen, err := r.query(ctx, query)
	if err == nil {
		res.Runtime = time.Since(begin)
		return res, nil
	}

	// Only a transport-level failure justifies a reconnect. A well-formed
	// osquery error response (SQL error, nil status) or a context deadline
	// proves the connection is healthy, so reconnecting would just add load.
	var te transportError
	if !errors.As(err, &te) || errors.Is(err, context.DeadlineExceeded) {
		return nil, err
	}

	r.log.Warn("transport error, attempting reconnect", "query", query, "error", err)
	if cerr := r.maybeReconnect(gen); cerr != nil {
		return nil, fmt.Errorf("query failed and reconnect failed: %w", cerr)
	}
	res, _, err = r.query(ctx, query)
	if err != nil {
		return nil, err
	}
	res.Runtime = time.Since(begin)
	return res, nil
}

// query runs a single query on the current client and returns the result
// along with the client generation used, so callers can detect whether a
// reconnect has already occurred.
func (r *ThriftRunner) query(ctx context.Context, query string) (*model.OsqueryResult, int, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	r.mu.Lock()
	client := r.client
	gen := r.gen
	r.mu.Unlock()

	if client == nil {
		return nil, gen, transportError{err: errors.New("no osqueryd connection")}
	}

	response, err := client.QueryContext(ctx, query)
	if err != nil {
		return nil, gen, transportError{err: fmt.Errorf("osqueryd query failed: %w", err)}
	}
	if response.Status == nil {
		return nil, gen, fmt.Errorf("osqueryd query returned nil status")
	}
	if response.Status.Code != 0 {
		return nil, gen, fmt.Errorf("osqueryd query returned error (%d): %s", response.Status.Code, response.Status.Message)
	}

	items := make([]model.OsqueryItem, 0, len(response.Response))
	for _, row := range response.Response {
		item := make(model.OsqueryItem, len(row))
		for k, v := range row {
			item[k] = v
		}
		items = append(items, item)
	}

	return &model.OsqueryResult{Items: items}, gen, nil
}

// Close closes the underlying Thrift client connection.
func (r *ThriftRunner) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.client != nil {
		r.client.Close()
		r.client = nil
	}
}
