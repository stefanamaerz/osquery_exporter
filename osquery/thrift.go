package osquery

import (
	"fmt"
	"log/slog"
	"time"

	osquerygo "github.com/osquery/osquery-go"
	osquerygen "github.com/osquery/osquery-go/gen/osquery"
	"github.com/stefanamaerz/osquery_exporter/model"
)

// thriftQuerier is the minimal interface ThriftRunner needs from the
// osquery-go ExtensionManagerClient. It makes the runner testable without a
// real osqueryd socket.
type thriftQuerier interface {
	Query(sql string) (*osquerygen.ExtensionResponse, error)
	Close()
}

// ThriftRunner executes queries by connecting to a running osqueryd over its
// Thrift extension socket.
type ThriftRunner struct {
	socketPath string
	timeout    time.Duration
	log        *slog.Logger
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
	if r.client != nil {
		r.client.Close()
	}
	client, err := osquerygo.NewClient(r.socketPath, r.timeout)
	if err != nil {
		return fmt.Errorf("failed to connect to osqueryd thrift socket %q: %w", r.socketPath, err)
	}
	r.client = client
	return nil
}

// Run executes the query over the Thrift extension socket.
func (r *ThriftRunner) Run(query string) (*model.OsqueryResult, error) {
	begin := time.Now()

	r.log.Debug("running osquery query via thrift", "query", query)

	response, err := r.client.Query(query)
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

	duration := time.Since(begin)
	return &model.OsqueryResult{
		Items:   items,
		Runtime: duration,
	}, nil
}

// Close closes the underlying Thrift client connection.
func (r *ThriftRunner) Close() {
	if r.client != nil {
		r.client.Close()
	}
}
