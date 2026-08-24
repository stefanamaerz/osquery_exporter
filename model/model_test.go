package model

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestMetricString(t *testing.T) {
	m := Metric{Name: "test_metric"}
	if got := m.String(); got != "test_metric" {
		t.Fatalf("String() = %q, want %q", got, "test_metric")
	}
}

func TestMetricQuery(t *testing.T) {
	m := Metric{Querystring: "SELECT 1"}
	if got := m.Query(); got != "SELECT 1" {
		t.Fatalf("Query() = %q, want %q", got, "SELECT 1")
	}
}

func TestMetricValue(t *testing.T) {
	m := Metric{ValueIdentifier: "count"}
	if got := m.Value(); got != "count" {
		t.Fatalf("Value() = %q, want %q", got, "count")
	}
}

func TestCounterValueType(t *testing.T) {
	var c Counter
	if got := c.ValueType(); got != prometheus.CounterValue {
		t.Fatalf("Counter ValueType() = %v, want CounterValue", got)
	}
}

func TestGaugeValueType(t *testing.T) {
	var g Gauge
	if got := g.ValueType(); got != prometheus.GaugeValue {
		t.Fatalf("Gauge ValueType() = %v, want GaugeValue", got)
	}
}

func TestCounterVecValueType(t *testing.T) {
	cv := CounterVec{MetricVec{LabelIdentifier: []string{"label"}}}
	if got := cv.ValueType(); got != prometheus.CounterValue {
		t.Fatalf("CounterVec ValueType() = %v, want CounterValue", got)
	}
}

func TestGaugeVecValueType(t *testing.T) {
	gv := GaugeVec{MetricVec{LabelIdentifier: []string{"label"}}}
	if got := gv.ValueType(); got != prometheus.GaugeValue {
		t.Fatalf("GaugeVec ValueType() = %v, want GaugeValue", got)
	}
}

func TestMetricVecLabels(t *testing.T) {
	mv := MetricVec{LabelIdentifier: []string{"a", "b"}}
	if got := mv.Labels(); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("Labels() = %v, want [a b]", got)
	}
}

func TestCounterGaugeLabelsEmpty(t *testing.T) {
	var c Counter
	if got := c.Labels(); len(got) != 0 {
		t.Fatalf("Counter Labels() = %v, want empty", got)
	}
	var g Gauge
	if got := g.Labels(); len(got) != 0 {
		t.Fatalf("Gauge Labels() = %v, want empty", got)
	}
}

func TestIdDeterministic(t *testing.T) {
	first := id("SELECT 1")
	second := id("SELECT 1")
	if first != second {
		t.Fatalf("id('SELECT 1') non-deterministic: %q vs %q", first, second)
	}
	if first == id("SELECT 2") {
		t.Fatalf("id('SELECT 1') collided with id('SELECT 2'): %q", first)
	}
}

func TestIdHexEncoded(t *testing.T) {
	got := id("SELECT 1")
	if len(got) != 32 {
		t.Fatalf("id length = %d, want 32 hex chars", len(got))
	}
	for _, r := range got {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			t.Fatalf("id %q contains non-hex character %q", got, r)
		}
	}
}

func TestResolveQueryRefs(t *testing.T) {
	ref := "shared"
	config := Config{
		Queries: []Query{
			{Name: "shared", Query: "SELECT 1"},
		},
		Metrics: Metrics{
			Gauges: []Gauge{
				{Metric: Metric{Name: "a", Help: "h", Queryref: &ref, ValueIdentifier: "v"}},
			},
		},
	}
	if err := ResolveQueryRefs(&config); err != nil {
		t.Fatalf("ResolveQueryRefs failed: %v", err)
	}
	if got := config.Metrics.Gauges[0].Querystring; got != "SELECT 1" {
		t.Fatalf("resolved query = %q, want %q", got, "SELECT 1")
	}
}

func TestResolveQueryRefsBackwardCompat(t *testing.T) {
	config := Config{
		Metrics: Metrics{
			Gauges: []Gauge{
				{Metric: Metric{Name: "a", Help: "h", Querystring: "SELECT 1", ValueIdentifier: "v"}},
			},
		},
	}
	if err := ResolveQueryRefs(&config); err != nil {
		t.Fatalf("ResolveQueryRefs failed: %v", err)
	}
	if got := config.Metrics.Gauges[0].Querystring; got != "SELECT 1" {
		t.Fatalf("query = %q, want %q", got, "SELECT 1")
	}
}

func TestResolveQueryRefsMutualExclusion(t *testing.T) {
	ref := "shared"
	config := Config{
		Queries: []Query{{Name: "shared", Query: "SELECT 1"}},
		Metrics: Metrics{
			Gauges: []Gauge{
				{Metric: Metric{Name: "a", Help: "h", Querystring: "SELECT 2", Queryref: &ref, ValueIdentifier: "v"}},
			},
		},
	}
	if err := ResolveQueryRefs(&config); err == nil {
		t.Fatal("expected error when query and queryref are both set")
	}
}

func TestResolveQueryRefsUnknownRef(t *testing.T) {
	ref := "missing"
	config := Config{
		Metrics: Metrics{
			Gauges: []Gauge{
				{Metric: Metric{Name: "a", Help: "h", Queryref: &ref, ValueIdentifier: "v"}},
			},
		},
	}
	if err := ResolveQueryRefs(&config); err == nil {
		t.Fatal("expected error for unknown queryref")
	}
}

func TestResolveQueryRefsDuplicateSharedName(t *testing.T) {
	config := Config{
		Queries: []Query{
			{Name: "shared", Query: "SELECT 1"},
			{Name: "shared", Query: "SELECT 2"},
		},
	}
	if err := ResolveQueryRefs(&config); err == nil {
		t.Fatal("expected error for duplicate shared query name")
	}
}

func TestResolveQueryRefsEmptySharedName(t *testing.T) {
	config := Config{
		Queries: []Query{{Name: "", Query: "SELECT 1"}},
	}
	if err := ResolveQueryRefs(&config); err == nil {
		t.Fatal("expected error for empty shared query name")
	}
}

func TestResolveQueryRefsEmptySharedQuery(t *testing.T) {
	config := Config{
		Queries: []Query{{Name: "shared", Query: ""}},
	}
	if err := ResolveQueryRefs(&config); err == nil {
		t.Fatal("expected error for empty shared query string")
	}
}
