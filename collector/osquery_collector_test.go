package collector

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stefanamaerz/osquery_exporter/model"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

type fakeRunner struct {
	results map[string]*model.OsqueryResult
	errs    map[string]error
}

func (f *fakeRunner) Run(ctx context.Context, query string) (*model.OsqueryResult, error) {
	if err, ok := f.errs[query]; ok {
		return nil, err
	}
	if res, ok := f.results[query]; ok {
		return res, nil
	}
	return &model.OsqueryResult{Items: []model.OsqueryItem{}}, nil
}

func TestEmitMetricsSuccess(t *testing.T) {
	m := model.Counter{Metric: model.Metric{Name: "test", Help: "help", Querystring: "SELECT 1", ValueIdentifier: "count"}}
	res := &model.OsqueryResult{
		Items: []model.OsqueryItem{{"count": "7"}},
	}
	metrics, err := emitMetrics(m, res)
	if err != nil {
		t.Fatalf("emitMetrics failed: %v", err)
	}
	if len(metrics) != 1 {
		t.Fatalf("expected 1 metric, got %d", len(metrics))
	}
}

func TestEmitMetricsMultiValueError(t *testing.T) {
	m := model.Counter{Metric: model.Metric{Name: "test", Help: "help", Querystring: "SELECT 1", ValueIdentifier: "count"}}
	res := &model.OsqueryResult{
		Items: []model.OsqueryItem{{"count": "1"}, {"count": "2"}},
	}
	if _, err := emitMetrics(m, res); err == nil {
		t.Fatal("expected error for multi-row scalar metric")
	}
}

func TestEmitMetricsMissingValueKey(t *testing.T) {
	m := model.Counter{Metric: model.Metric{Name: "test", Help: "help", Querystring: "SELECT 1", ValueIdentifier: "count"}}
	res := &model.OsqueryResult{
		Items: []model.OsqueryItem{{"wrong": "1"}},
	}
	if _, err := emitMetrics(m, res); err == nil {
		t.Fatal("expected error for missing value key")
	}
}

func TestEmitMetricsNonNumericValue(t *testing.T) {
	m := model.Counter{Metric: model.Metric{Name: "test", Help: "help", Querystring: "SELECT 1", ValueIdentifier: "count"}}
	res := &model.OsqueryResult{
		Items: []model.OsqueryItem{{"count": "abc"}},
	}
	if _, err := emitMetrics(m, res); err == nil {
		t.Fatal("expected error for non-numeric value")
	}
}

func TestEmitMetricsMissingLabel(t *testing.T) {
	m := model.CounterVec{MetricVec: model.MetricVec{
		Metric:          model.Metric{Name: "test", Help: "help", Querystring: "SELECT 1", ValueIdentifier: "count"},
		LabelIdentifier: []string{"label"},
	}}
	res := &model.OsqueryResult{
		Items: []model.OsqueryItem{{"count": "1"}},
	}
	if _, err := emitMetrics(m, res); err == nil {
		t.Fatal("expected error for missing label")
	}
}

func TestEmitMetricsVec(t *testing.T) {
	m := model.CounterVec{MetricVec: model.MetricVec{
		Metric:          model.Metric{Name: "test", Help: "help", Querystring: "SELECT 1", ValueIdentifier: "count"},
		LabelIdentifier: []string{"label"},
	}}
	res := &model.OsqueryResult{
		Items: []model.OsqueryItem{
			{"count": "1", "label": "a"},
			{"count": "2", "label": "b"},
		},
	}
	metrics, err := emitMetrics(m, res)
	if err != nil {
		t.Fatalf("emitMetrics failed: %v", err)
	}
	if len(metrics) != 2 {
		t.Fatalf("expected 2 metrics, got %d", len(metrics))
	}
}

func TestNewOsqueryCollectorDuplicateName(t *testing.T) {
	m := model.Metrics{
		Gauges: []model.Gauge{
			{Metric: model.Metric{Name: "dup", Help: "first", Querystring: "SELECT 1", ValueIdentifier: "v"}},
		},
		Counters: []model.Counter{
			{Metric: model.Metric{Name: "dup", Help: "second", Querystring: "SELECT 2", ValueIdentifier: "v"}},
		},
	}
	if _, err := NewOsqueryCollector(&fakeRunner{}, m, discardLogger()); err == nil {
		t.Fatal("expected error for duplicate metric name")
	}
}

func TestNewOsqueryCollectorInvalidDescriptor(t *testing.T) {
	m := model.Metrics{
		Gauges: []model.Gauge{
			{Metric: model.Metric{Name: "", Help: "empty", Querystring: "SELECT 1", ValueIdentifier: "v"}},
		},
	}
	if _, err := NewOsqueryCollector(&fakeRunner{}, m, discardLogger()); err == nil {
		t.Fatal("expected error for empty metric name")
	}
}

func TestCollectorCollectSuccess(t *testing.T) {
	fr := &fakeRunner{
		results: map[string]*model.OsqueryResult{
			"SELECT 1": {Items: []model.OsqueryItem{{"count": "42"}}, Runtime: 10 * time.Millisecond},
		},
	}
	m := model.Metrics{
		Counters: []model.Counter{
			{Metric: model.Metric{Name: "ones", Help: "ones", Querystring: "SELECT 1", ValueIdentifier: "count"}},
		},
	}
	c, err := NewOsqueryCollector(fr, m, discardLogger())
	if err != nil {
		t.Fatalf("NewOsqueryCollector failed: %v", err)
	}
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

func TestCollectorCollectQueryError(t *testing.T) {
	fr := &fakeRunner{
		errs: map[string]error{
			"SELECT boom": errors.New("boom"),
		},
	}
	m := model.Metrics{
		Counters: []model.Counter{
			{Metric: model.Metric{Name: "boom", Help: "boom", Querystring: "SELECT boom", ValueIdentifier: "count"}},
		},
	}
	c, err := NewOsqueryCollector(fr, m, discardLogger())
	if err != nil {
		t.Fatalf("NewOsqueryCollector failed: %v", err)
	}
	ch := make(chan prometheus.Metric, 10)
	go func() {
		c.Collect(ch)
		close(ch)
	}()

	count := 0
	for range ch {
		count++
	}
	// On failure, internal gauges (success=0, resultsets=0, duration) should still be emitted.
	if count < 1 {
		t.Fatalf("expected internal metrics, got %d", count)
	}
}

func TestCollectorDescribe(t *testing.T) {
	fr := &fakeRunner{}
	c, err := NewOsqueryCollector(fr, model.Metrics{}, discardLogger())
	if err != nil {
		t.Fatalf("NewOsqueryCollector failed: %v", err)
	}
	ch := make(chan *prometheus.Desc, 10)
	go func() {
		c.Describe(ch)
		close(ch)
	}()
	count := 0
	for range ch {
		count++
	}
	if count != 3 {
		t.Fatalf("expected 3 descriptors, got %d", count)
	}
}
