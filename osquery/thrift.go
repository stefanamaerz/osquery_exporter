package osquery

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	osquerygo "github.com/osquery/osquery-go"
	osquerygen "github.com/osquery/osquery-go/gen/osquery"
	"github.com/stefanamaerz/osquery_exporter/model"
)

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
	mu         sync.Mutex
	client     thriftQuerier
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
	if err := r.connect(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *ThriftRunner) connect() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.client != nil {
		r.client.Close()
	}
	client, err := osquerygo.NewClient(r.socketPath, r.timeout,
		osquerygo.DefaultWaitTime(r.timeout),
		osquerygo.MaxWaitTime(r.timeout),
	)
	if err != nil {
		return fmt.Errorf("failed to connect to osqueryd thrift socket %q: %w", r.socketPath, err)
	}
	r.client = client
	return nil
}

// Run executes the query over the Thrift extension socket.
func (r *ThriftRunner) Run(ctx context.Context, query string) (*model.OsqueryResult, error) {
	begin := time.Now()

	r.log.Debug("running osquery query via thrift", "query", query)

	res, err := r.query(ctx, query)
	if err == nil {
		duration := time.Since(begin)
		res.Runtime = duration
		return res, nil
	}

	// Connection may have gone stale (e.g. osqueryd restarted). Try once to
	// reconnect and rerun the query.
	r.log.Warn("query failed, attempting reconnect", "query", query, "error", err)
	if cerr := r.connect(); cerr != nil {
		return nil, fmt.Errorf("query failed and reconnect failed: %w", cerr)
	}
	res, err = r.query(ctx, query)
	if err != nil {
		return nil, err
	}
	duration := time.Since(begin)
	res.Runtime = duration
	return res, nil
}

func (r *ThriftRunner) query(ctx context.Context, query string) (*model.OsqueryResult, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	r.mu.Lock()
	client := r.client
	r.mu.Unlock()

	response, err := client.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("osqueryd query failed: %w", err)
	}
	if response.Status == nil {
		return nil, fmt.Errorf("osqueryd query returned nil status")
	}
	if response.Status.Code != 0 {
		return nil, fmt.Errorf("osqueryd query returned error (%d): %s", response.Status.Code, response.Status.Message)
	}

	items := make([]model.OsqueryItem, 0, len(response.Response))
	for _, row := range response.Response {
		item := make(model.OsqueryItem, len(row))
		for k, v := range row {
			item[k] = v
		}
		items = append(items, item)
	}

	return &model.OsqueryResult{
		Items: items,
	}, nil
}

// Close closes the underlying Thrift client connection.
func (r *ThriftRunner) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.client != nil {
		r.client.Close()
	}
}
