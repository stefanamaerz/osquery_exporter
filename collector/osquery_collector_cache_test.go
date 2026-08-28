package collector

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stefanamaerz/osquery_exporter/model"
)

func strPtr(s string) *string { return &s }

func TestCollectorCacheHitsAndMisses(t *testing.T) {
	fr := &countingRunner{
		fakeRunner: fakeRunner{
			results: map[string]*model.OsqueryResult{
				"SELECT 1": {Items: []model.OsqueryItem{{"count": "1"}}, Runtime: time.Millisecond},
			},
		},
	}

	c, err := NewOsqueryCollector(fr, model.Metrics{
		Gauges: []model.Gauge{
			{Metric: model.Metric{Name: "ones", Help: "h", Querystring: "SELECT 1", ValueIdentifier: "count"}},
		},
	}, discardLogger(), NewOsqueryCollectorOptions{DefaultCacheTTL: 10 * time.Second})
	if err != nil {
		t.Fatalf("NewOsqueryCollector failed: %v", err)
	}

	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(c)

	// First scrape: miss.
	if _, err := reg.Gather(); err != nil {
		t.Fatalf("first gather: %v", err)
	}
	if fr.calls.Load() != 1 {
		t.Fatalf("expected 1 runner call after first scrape, got %d", fr.calls.Load())
	}

	// Second scrape within TTL: hit.
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("second gather: %v", err)
	}
	if fr.calls.Load() != 1 {
		t.Fatalf("expected still 1 runner call after cache hit, got %d", fr.calls.Load())
	}

	if got := cacheCounterValue(mfs, "osquery_exporter_query_cache_hits_total", "ones"); got != 1 {
		t.Fatalf("cache hits = %v, want 1", got)
	}
	if got := cacheCounterValue(mfs, "osquery_exporter_query_cache_misses_total", "ones"); got != 1 {
		t.Fatalf("cache misses = %v, want 1", got)
	}
	if got := cacheCounterValue(mfs, "osquery_exporter_query_executions_total", "ones"); got != 1 {
		t.Fatalf("query executions = %v, want 1", got)
	}
}

func TestCollectorCachePerQueryOverride(t *testing.T) {
	fr := &countingRunner{
		fakeRunner: fakeRunner{
			results: map[string]*model.OsqueryResult{
				"SELECT slow": {Items: []model.OsqueryItem{{"count": "1"}}, Runtime: time.Millisecond},
				"SELECT fast": {Items: []model.OsqueryItem{{"count": "2"}}, Runtime: time.Millisecond},
			},
		},
	}

	config := model.Config{
		Queries: []model.Query{
			// fast_query uses a long per-query TTL; slow has no cache (default TTL disabled).
			{Name: "fast_query", Query: "SELECT fast", CacheTTL: "1m"},
		},
		Metrics: model.Metrics{
			Gauges: []model.Gauge{
				{Metric: model.Metric{Name: "slow", Help: "h", Querystring: "SELECT slow", ValueIdentifier: "count"}},
				{Metric: model.Metric{Name: "fast", Help: "h", Queryref: strPtr("fast_query"), ValueIdentifier: "count"}},
			},
		},
	}
	if err := model.ResolveQueryRefs(&config); err != nil {
		t.Fatalf("ResolveQueryRefs failed: %v", err)
	}

	c, err := NewOsqueryCollector(fr, config.Metrics, discardLogger(), NewOsqueryCollectorOptions{DefaultCacheTTL: 0})
	if err != nil {
		t.Fatalf("NewOsqueryCollector failed: %v", err)
	}

	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(c)

	for i := 0; i < 2; i++ {
		if _, err := reg.Gather(); err != nil {
			t.Fatalf("gather %d: %v", i, err)
		}
	}

	if fr.calls.Load() != 3 {
		t.Fatalf("expected 3 runner calls (slow twice + fast_query once), got %d", fr.calls.Load())
	}
}

func TestCollectorCachePerQueryGroupOverride(t *testing.T) {
	fr := &countingRunner{
		fakeRunner: fakeRunner{
			results: map[string]*model.OsqueryResult{
				"SELECT shared": {Items: []model.OsqueryItem{{"a": "1"}}, Runtime: time.Millisecond},
			},
		},
	}

	config := model.Config{
		Queries: []model.Query{
			{Name: "shared", Query: "SELECT shared", CacheTTL: "50ms"},
		},
		Metrics: model.Metrics{
			Gauges: []model.Gauge{
				// First metric has no TTL override; second metric references the shared
				// query that defines a TTL. The override must still be honored.
				{Metric: model.Metric{Name: "metric_a", Help: "h", Querystring: "SELECT shared", ValueIdentifier: "a"}},
				{Metric: model.Metric{Name: "metric_b", Help: "h", Queryref: strPtr("shared"), ValueIdentifier: "a"}},
			},
		},
	}
	if err := model.ResolveQueryRefs(&config); err != nil {
		t.Fatalf("ResolveQueryRefs failed: %v", err)
	}

	c, err := NewOsqueryCollector(fr, config.Metrics, discardLogger(), NewOsqueryCollectorOptions{DefaultCacheTTL: 0})
	if err != nil {
		t.Fatalf("NewOsqueryCollector failed: %v", err)
	}

	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(c)

	if _, err := reg.Gather(); err != nil {
		t.Fatalf("first gather: %v", err)
	}
	time.Sleep(60 * time.Millisecond)
	if _, err := reg.Gather(); err != nil {
		t.Fatalf("second gather: %v", err)
	}

	if fr.calls.Load() != 2 {
		t.Fatalf("expected 2 runner calls after TTL expiry, got %d", fr.calls.Load())
	}
}

func TestCollectorCacheConflictingTTLInGroupFails(t *testing.T) {
	fr := &countingRunner{
		fakeRunner: fakeRunner{},
	}

	config := model.Config{
		Queries: []model.Query{
			// Two shared query aliases that both resolve to the same SQL text.
			{Name: "q1", Query: "SELECT shared", CacheTTL: "30s"},
			{Name: "q2", Query: "SELECT shared", CacheTTL: "1m"},
		},
		Metrics: model.Metrics{
			Gauges: []model.Gauge{
				{Metric: model.Metric{Name: "metric_a", Help: "h", Queryref: strPtr("q1"), ValueIdentifier: "a"}},
				{Metric: model.Metric{Name: "metric_b", Help: "h", Queryref: strPtr("q2"), ValueIdentifier: "a"}},
			},
		},
	}
	if err := model.ResolveQueryRefs(&config); err != nil {
		t.Fatalf("ResolveQueryRefs failed: %v", err)
	}

	_, err := NewOsqueryCollector(fr, config.Metrics, discardLogger(), NewOsqueryCollectorOptions{DefaultCacheTTL: 0})
	if err == nil {
		t.Fatal("expected error for conflicting cache_ttl in query group, got nil")
	}
}

func TestCollectorCacheCountsOncePerQueryGroup(t *testing.T) {
	fr := &countingRunner{
		fakeRunner: fakeRunner{
			results: map[string]*model.OsqueryResult{
				"SELECT shared": {Items: []model.OsqueryItem{{"a": "1", "b": "2"}}, Runtime: time.Millisecond},
			},
		},
	}

	c, err := NewOsqueryCollector(fr, model.Metrics{
		Gauges: []model.Gauge{
			{Metric: model.Metric{Name: "metric_a", Help: "h", Querystring: "SELECT shared", ValueIdentifier: "a"}},
			{Metric: model.Metric{Name: "metric_b", Help: "h", Querystring: "SELECT shared", ValueIdentifier: "b"}},
		},
	}, discardLogger(), NewOsqueryCollectorOptions{DefaultCacheTTL: 10 * time.Second})
	if err != nil {
		t.Fatalf("NewOsqueryCollector failed: %v", err)
	}

	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(c)

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}

	if fr.calls.Load() != 1 {
		t.Fatalf("expected 1 runner call for shared query, got %d", fr.calls.Load())
	}
	if got := cacheCounterValue(mfs, "osquery_exporter_query_cache_misses_total", "metric_a"); got != 1 {
		t.Fatalf("metric_a cache misses = %v, want 1", got)
	}
	if got := cacheCounterValue(mfs, "osquery_exporter_query_cache_misses_total", "metric_b"); got != 0 {
		t.Fatalf("metric_b cache misses = %v, want 0 (counted under metric_a)", got)
	}
	if got := cacheCounterValue(mfs, "osquery_exporter_query_executions_total", "metric_a"); got != 1 {
		t.Fatalf("metric_a executions = %v, want 1", got)
	}
}

func TestCollectorCacheDisabledByDefault(t *testing.T) {
	fr := &countingRunner{
		fakeRunner: fakeRunner{
			results: map[string]*model.OsqueryResult{
				"SELECT 1": {Items: []model.OsqueryItem{{"count": "1"}}, Runtime: time.Millisecond},
			},
		},
	}

	c, err := NewOsqueryCollector(fr, model.Metrics{
		Gauges: []model.Gauge{
			{Metric: model.Metric{Name: "ones", Help: "h", Querystring: "SELECT 1", ValueIdentifier: "count"}},
		},
	}, discardLogger())
	if err != nil {
		t.Fatalf("NewOsqueryCollector failed: %v", err)
	}

	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(c)

	if _, err := reg.Gather(); err != nil {
		t.Fatalf("first gather: %v", err)
	}
	if _, err := reg.Gather(); err != nil {
		t.Fatalf("second gather: %v", err)
	}

	if fr.calls.Load() != 2 {
		t.Fatalf("expected 2 runner calls with caching disabled, got %d", fr.calls.Load())
	}
}

func cacheCounterValue(mfs []*dto.MetricFamily, name, metricName string) float64 {
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "name" && l.GetValue() == metricName {
					return m.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
}
