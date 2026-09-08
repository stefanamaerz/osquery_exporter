package collector

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"slices"
	"sync"
	"sync/atomic"
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
	_ = ctx
	if err, ok := f.errs[query]; ok {
		return nil, err
	}
	if res, ok := f.results[query]; ok {
		return res, nil
	}
	return &model.OsqueryResult{Items: []model.OsqueryItem{}}, nil
}

func counterMetric() metricDefinition {
	return newMetricDefinition("counter", "test", "SELECT 1", "count", "help", "", nil, prometheus.CounterValue)
}

func vecMetric() metricDefinition {
	return newMetricDefinition("countervec", "test", "SELECT 1", "count", "help", "", []string{"label"}, prometheus.CounterValue)
}

func TestEmitMetricsSuccess(t *testing.T) {
	m := counterMetric()
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
	m := counterMetric()
	res := &model.OsqueryResult{
		Items: []model.OsqueryItem{{"count": "1"}, {"count": "2"}},
	}
	if _, err := emitMetrics(m, res); err == nil {
		t.Fatal("expected error for multi-row scalar metric")
	}
}

func TestEmitMetricsMissingValueKey(t *testing.T) {
	m := counterMetric()
	res := &model.OsqueryResult{
		Items: []model.OsqueryItem{{"wrong": "1"}},
	}
	if _, err := emitMetrics(m, res); err == nil {
		t.Fatal("expected error for missing value key")
	}
}

func TestEmitMetricsNonNumericValue(t *testing.T) {
	m := counterMetric()
	res := &model.OsqueryResult{
		Items: []model.OsqueryItem{{"count": "abc"}},
	}
	if _, err := emitMetrics(m, res); err == nil {
		t.Fatal("expected error for non-numeric value")
	}
}

func TestEmitMetricsMissingLabel(t *testing.T) {
	m := vecMetric()
	res := &model.OsqueryResult{
		Items: []model.OsqueryItem{{"count": "1"}},
	}
	if _, err := emitMetrics(m, res); err == nil {
		t.Fatal("expected error for missing label")
	}
}

func TestEmitMetricsVec(t *testing.T) {
	m := vecMetric()
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
	if _, err := NewOsqueryCollector(context.Background(), &fakeRunner{}, m, discardLogger(), 0, 60*time.Second, 0); err == nil {
		t.Fatal("expected error for duplicate metric name")
	}
}

func TestNewOsqueryCollectorInvalidDescriptor(t *testing.T) {
	m := model.Metrics{
		Gauges: []model.Gauge{
			{Metric: model.Metric{Name: "", Help: "empty", Querystring: "SELECT 1", ValueIdentifier: "v"}},
		},
	}
	if _, err := NewOsqueryCollector(context.Background(), &fakeRunner{}, m, discardLogger(), 0, 60*time.Second, 0); err == nil {
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
	c, err := NewOsqueryCollector(context.Background(), fr, m, discardLogger(), 0, 60*time.Second, 0)
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
	c, err := NewOsqueryCollector(context.Background(), fr, m, discardLogger(), 0, 60*time.Second, 0)
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
	c, err := NewOsqueryCollector(context.Background(), fr, model.Metrics{}, discardLogger(), 0, 60*time.Second, 0)
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
	if count != 6 {
		t.Fatalf("expected 6 descriptors, got %d", count)
	}
}

func TestNewOsqueryCollectorReservedName(t *testing.T) {
	for _, reserved := range []string{"query_duration_seconds", "query_success", "resultsets"} {
		m := model.Metrics{
			Gauges: []model.Gauge{
				{Metric: model.Metric{Name: reserved, Help: "h", Querystring: "SELECT 1 AS v", ValueIdentifier: "v"}},
			},
		}
		if _, err := NewOsqueryCollector(context.Background(), &fakeRunner{}, m, discardLogger(), 0, 60*time.Second, 0); err == nil {
			t.Fatalf("expected error for reserved metric name %q", reserved)
		}
	}
}

func TestEmitMetricsDuplicateLabelSet(t *testing.T) {
	m := newMetricDefinition("gaugevec", "by_shell", "SELECT 1", "count", "h", "", []string{"shell"}, prometheus.GaugeValue)
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
	c, err := NewOsqueryCollector(context.Background(), fr, m, discardLogger(), 0, 60*time.Second, 0)
	if err != nil {
		t.Fatalf("NewOsqueryCollector failed: %v", err)
	}

	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(c)
	if _, err := reg.Gather(); err != nil {
		t.Fatalf("gather: %v", err)
	}
}

type blockingRunner struct {
	started chan struct{}
}

func (b *blockingRunner) Run(ctx context.Context, query string) (*model.OsqueryResult, error) {
	close(b.started)
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestCollectorShutdownContextCancelsInFlightQuery(t *testing.T) {
	br := &blockingRunner{started: make(chan struct{})}
	m := model.Metrics{
		Counters: []model.Counter{
			{Metric: model.Metric{Name: "ones", Help: "ones", Querystring: "SELECT 1", ValueIdentifier: "count"}},
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	c, err := NewOsqueryCollector(ctx, br, m, discardLogger(), 0, 60*time.Second, 0)
	if err != nil {
		t.Fatalf("NewOsqueryCollector failed: %v", err)
	}

	ch := make(chan prometheus.Metric, 10)
	done := make(chan struct{})
	go func() {
		c.Collect(ch)
		close(done)
	}()

	select {
	case <-br.started:
	case <-time.After(2 * time.Second):
		t.Fatal("query did not start")
	}

	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("collect did not finish after shutdown context cancelled")
	}

	close(ch)
	count := 0
	for range ch {
		count++
	}
	if count == 0 {
		t.Fatal("expected internal metrics after cancellation")
	}
}

// TestCollectorScrapeTimeoutExpires verifies that a short scrape timeout
// cancels an in-flight query and consistently reports query_success=0 and
// resultsets=0 for the metric.
func TestCollectorScrapeTimeoutExpires(t *testing.T) {
	br := &blockingRunner{started: make(chan struct{})}
	m := model.Metrics{
		Counters: []model.Counter{
			{Metric: model.Metric{Name: "ones", Help: "ones", Querystring: "SELECT 1", ValueIdentifier: "count"}},
		},
	}
	c, err := NewOsqueryCollector(context.Background(), br, m, discardLogger(), 0, 50*time.Millisecond, 0)
	if err != nil {
		t.Fatalf("NewOsqueryCollector failed: %v", err)
	}

	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(c)

	start := time.Now()
	mfs, err := reg.Gather()
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("gather took too long (%v) to respect scrape timeout", elapsed)
	}

	var successVal, resultsetsVal float64 = -1, -1
	for _, mf := range mfs {
		if mf.GetName() != "osquery_exporter_query_success" && mf.GetName() != "osquery_exporter_resultsets" {
			continue
		}
		for _, metric := range mf.GetMetric() {
			for _, l := range metric.GetLabel() {
				if l.GetName() == "name" && l.GetValue() == "ones" {
					if mf.GetName() == "osquery_exporter_query_success" {
						successVal = metric.GetGauge().GetValue()
					} else {
						resultsetsVal = metric.GetGauge().GetValue()
					}
				}
			}
		}
	}
	if successVal != 0 {
		t.Fatalf("query_success = %v, want 0 after scrape timeout", successVal)
	}
	if resultsetsVal != 0 {
		t.Fatalf("resultsets = %v, want 0 after scrape timeout", resultsetsVal)
	}
}

type countingRunner struct {
	fakeRunner
	calls atomic.Int32
}

type recordingRunner struct {
	mu      sync.Mutex
	started []time.Time
	results map[string]*model.OsqueryResult
}

func (r *recordingRunner) Run(ctx context.Context, query string) (*model.OsqueryResult, error) {
	r.mu.Lock()
	r.started = append(r.started, time.Now())
	r.mu.Unlock()
	return r.results[query], nil
}

// TestCollectorQueryStagger spaces query group launches by the configured
// stagger duration.
func TestCollectorQueryStagger(t *testing.T) {
	fr := &recordingRunner{
		results: map[string]*model.OsqueryResult{
			"SELECT 1": {Items: []model.OsqueryItem{{"count": "1"}}, Runtime: time.Millisecond},
			"SELECT 2": {Items: []model.OsqueryItem{{"count": "2"}}, Runtime: time.Millisecond},
			"SELECT 3": {Items: []model.OsqueryItem{{"count": "3"}}, Runtime: time.Millisecond},
		},
	}
	m := model.Metrics{
		Counters: []model.Counter{
			{Metric: model.Metric{Name: "one", Help: "h", Querystring: "SELECT 1", ValueIdentifier: "count"}},
			{Metric: model.Metric{Name: "two", Help: "h", Querystring: "SELECT 2", ValueIdentifier: "count"}},
			{Metric: model.Metric{Name: "three", Help: "h", Querystring: "SELECT 3", ValueIdentifier: "count"}},
		},
	}
	stagger := 50 * time.Millisecond
	c, err := NewOsqueryCollector(context.Background(), fr, m, discardLogger(), 0, 60*time.Second, stagger)
	if err != nil {
		t.Fatalf("NewOsqueryCollector failed: %v", err)
	}

	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(c)
	if _, err := reg.Gather(); err != nil {
		t.Fatalf("gather: %v", err)
	}

	fr.mu.Lock()
	starts := append([]time.Time(nil), fr.started...)
	fr.mu.Unlock()

	if len(starts) != 3 {
		t.Fatalf("expected 3 query starts, got %d", len(starts))
	}
	slices.SortFunc(starts, func(a, b time.Time) int { return a.Compare(b) })
	for i := 1; i < len(starts); i++ {
		gap := starts[i].Sub(starts[i-1])
		if gap < stagger {
			t.Fatalf("gap %d (%d) < stagger %v", i, gap, stagger)
		}
	}
}

// TestCollectorNoStaggerWhenDisabled verifies that a zero stagger does not
// unnecessarily delay queries.
func TestCollectorNoStaggerWhenDisabled(t *testing.T) {
	fr := &recordingRunner{
		results: map[string]*model.OsqueryResult{
			"SELECT 1": {Items: []model.OsqueryItem{{"count": "1"}}, Runtime: time.Millisecond},
			"SELECT 2": {Items: []model.OsqueryItem{{"count": "2"}}, Runtime: time.Millisecond},
		},
	}
	m := model.Metrics{
		Counters: []model.Counter{
			{Metric: model.Metric{Name: "one", Help: "h", Querystring: "SELECT 1", ValueIdentifier: "count"}},
			{Metric: model.Metric{Name: "two", Help: "h", Querystring: "SELECT 2", ValueIdentifier: "count"}},
		},
	}
	c, err := NewOsqueryCollector(context.Background(), fr, m, discardLogger(), 0, 60*time.Second, 0)
	if err != nil {
		t.Fatalf("NewOsqueryCollector failed: %v", err)
	}

	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(c)
	start := time.Now()
	if _, err := reg.Gather(); err != nil {
		t.Fatalf("gather: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("gather took %v with stagger disabled", elapsed)
	}
}

func (c *countingRunner) Run(ctx context.Context, query string) (*model.OsqueryResult, error) {
	c.calls.Add(1)
	return c.fakeRunner.Run(ctx, query)
}

func TestCollectorDeduplicatesSharedQuery(t *testing.T) {
	fr := &countingRunner{
		fakeRunner: fakeRunner{
			results: map[string]*model.OsqueryResult{
				"SELECT shared": {Items: []model.OsqueryItem{
					{"executions": "10", "output_size": "100"},
				}, Runtime: time.Millisecond},
			},
		},
	}
	m := model.Metrics{
		CounterVecs: []model.CounterVec{
			{MetricVec: model.MetricVec{
				Metric:          model.Metric{Name: "executions", Help: "h", Querystring: "SELECT shared", ValueIdentifier: "executions"},
				LabelIdentifier: []string{},
			}},
			{MetricVec: model.MetricVec{
				Metric:          model.Metric{Name: "output_size", Help: "h", Querystring: "SELECT shared", ValueIdentifier: "output_size"},
				LabelIdentifier: []string{},
			}},
		},
	}
	c, err := NewOsqueryCollector(context.Background(), fr, m, discardLogger(), 0, 60*time.Second, 0)
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
	if fr.calls.Load() != 1 {
		t.Fatalf("expected shared query to run once, got %d calls", fr.calls.Load())
	}
	if count < 2 {
		t.Fatalf("expected at least 2 metrics, got %d", count)
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
	c, err := NewOsqueryCollector(context.Background(), fr, m, discardLogger(), 0, 60*time.Second, 0)
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
