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

func TestNewOsqueryCollectorReservedName(t *testing.T) {
	for _, reserved := range []string{"query_duration_seconds", "query_success", "resultsets"} {
		m := model.Metrics{
			Gauges: []model.Gauge{
				{Metric: model.Metric{Name: reserved, Help: "h", Querystring: "SELECT 1 AS v", ValueIdentifier: "v"}},
			},
		}
		if _, err := NewOsqueryCollector(&fakeRunner{}, m, discardLogger()); err == nil {
			t.Fatalf("expected error for reserved metric name %q", reserved)
		}
	}
}

func TestEmitMetricsDuplicateLabelSet(t *testing.T) {
	m := model.GaugeVec{MetricVec: model.MetricVec{
		Metric:          model.Metric{Name: "by_shell", Help: "h", Querystring: "SELECT 1", ValueIdentifier: "count"},
		LabelIdentifier: []string{"shell"},
	}}
	res := &model.OsqueryResult{
		Items: []model.OsqueryItem{
			{"count": "1", "shell": "/bin/sh"},
			{"count": "2", "shell": "/bin/sh"}, // duplicate label set
		},
	}
	if _, err := emitMetrics(m, res); err == nil {
		t.Fatal("expected error for duplicate label set, got nil")
	}
}

// TestGatherPedantic exercises the collector through a real registry. Calling
// c.Collect directly never surfaces Describe/Collect inconsistency or
// duplicate-series errors; Gather on a pedantic registry does.
func TestGatherPedantic(t *testing.T) {
	fr := &fakeRunner{
		results: map[string]*model.OsqueryResult{
			"SELECT 1":       {Items: []model.OsqueryItem{{"count": "42"}}, Runtime: time.Millisecond},
			"SELECT byshell": {Items: []model.OsqueryItem{{"count": "1", "shell": "/bin/sh"}, {"count": "3", "shell": "/bin/bash"}}, Runtime: time.Millisecond},
		},
	}
	m := model.Metrics{
		Gauges: []model.Gauge{
			{Metric: model.Metric{Name: "ones", Help: "h", Querystring: "SELECT 1", ValueIdentifier: "count"}},
		},
		GaugeVecs: []model.GaugeVec{
			{MetricVec: model.MetricVec{
				Metric:          model.Metric{Name: "by_shell", Help: "h", Querystring: "SELECT byshell", ValueIdentifier: "count"},
				LabelIdentifier: []string{"shell"},
			}},
		},
	}
	c, err := NewOsqueryCollector(fr, m, discardLogger())
	if err != nil {
		t.Fatalf("NewOsqueryCollector failed: %v", err)
	}

	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(c)
	if _, err := reg.Gather(); err != nil {
		t.Fatalf("gather: %v", err)
	}
}

// TestGatherDuplicateLabelSetFailsSuccess asserts that a duplicate label set in
// a vector result drives query_success to 0 through a real registry gather.
func TestGatherDuplicateLabelSetFailsSuccess(t *testing.T) {
	fr := &fakeRunner{
		results: map[string]*model.OsqueryResult{
			"SELECT byshell": {Items: []model.OsqueryItem{
				{"count": "1", "shell": "/bin/sh"},
				{"count": "2", "shell": "/bin/sh"}, // duplicate
			}, Runtime: time.Millisecond},
		},
	}
	m := model.Metrics{
		GaugeVecs: []model.GaugeVec{
			{MetricVec: model.MetricVec{
				Metric:          model.Metric{Name: "by_shell", Help: "h", Querystring: "SELECT byshell", ValueIdentifier: "count"},
				LabelIdentifier: []string{"shell"},
			}},
		},
	}
	c, err := NewOsqueryCollector(fr, m, discardLogger())
	if err != nil {
		t.Fatalf("NewOsqueryCollector failed: %v", err)
	}

	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(c)
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}

	var successVal float64 = -1
	for _, mf := range mfs {
		if mf.GetName() != "osquery_exporter_query_success" {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "name" && l.GetValue() == "by_shell" {
					successVal = m.GetGauge().GetValue()
				}
			}
		}
	}
	if successVal != 0 {
		t.Fatalf("query_success for by_shell = %v, want 0 on duplicate label set", successVal)
	}
}
