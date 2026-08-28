package collector

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stefanamaerz/osquery_exporter/model"
)

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
	if fr.calls != 1 {
		t.Fatalf("expected 1 runner call after first scrape, got %d", fr.calls)
	}

	// Second scrape within TTL: hit.
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("second gather: %v", err)
	}
	if fr.calls != 1 {
		t.Fatalf("expected still 1 runner call after cache hit, got %d", fr.calls)
	}

	if got := cacheCounterValue(mfs, "osquery_exporter_query_cache_hits_total", "ones"); got != 1 {
		t.Fatalf("cache hits = %v, want 1", got)
	}
	if got := cacheCounterValue(mfs, "osquery_exporter_query_cache_misses_total", "ones"); got != 1 {
		t.Fatalf("cache misses = %v, want 1", got)
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

	if fr.calls != 2 {
		t.Fatalf("expected 2 runner calls with caching disabled, got %d", fr.calls)
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
