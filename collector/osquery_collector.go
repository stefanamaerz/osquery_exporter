package collector

import (
	"fmt"
	"log/slog"
	"strconv"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stefanamaerz/osquery_exporter/model"
	"github.com/stefanamaerz/osquery_exporter/osquery"
)

// singleQueryCollector represents a metric/query definition for a single osquery call
type singleQueryCollector interface {
	String() string
	Id() string
	Query() string
	Desc() *prometheus.Desc
	ValueType() prometheus.ValueType
	Value() string
	Labels() []string
}

// update maps the osquery query result to the singleQueryCollector and updates the provided channel accordingly
func update(sqc singleQueryCollector, result *model.OsqueryResult, ch chan<- prometheus.Metric) error {
	// metrics with no labels can only accept one result set
	if len(sqc.Labels()) == 0 && len(result.Items) > 1 {
		return fmt.Errorf("metrics with no labels can only accept one result set")
	}
	for _, item := range result.Items {
		value, ok := item[sqc.Value()]
		if !ok {
			return fmt.Errorf("query %q doesn't contain value key %q", sqc.Query(), sqc.Value())
		}
		valueAsFloat, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return fmt.Errorf("query %q result %q can't be converted to float: %w", sqc.Query(), value, err)
		}
		labels := []string{}
		for _, labelIdentifier := range sqc.Labels() {
			if label, ok := item[labelIdentifier]; ok {
				labels = append(labels, label)
			} else {
				return fmt.Errorf("query %q doesn't contain a label key %q", sqc.Query(), labelIdentifier)
			}
		}
		ch <- prometheus.MustNewConstMetric(
			sqc.Desc(),
			sqc.ValueType(),
			valueAsFloat,
			labels...,
		)
	}
	return nil
}

// OsqueryCollector represents a collector that collects metrics from a set of osquery queries. It implements
// prometheus Collector
type OsqueryCollector struct {
	runner         *osquery.OsqueryRunner
	collectors     map[string]singleQueryCollector
	log            *slog.Logger
	queryDurations *prometheus.SummaryVec
	success        *prometheus.GaugeVec
	resultsets     *prometheus.GaugeVec
}

// NewOsqueryCollector creates an OsQueryCollector from a given osquery-runner and a set of metric definitions
func NewOsqueryCollector(r *osquery.OsqueryRunner, m model.Metrics, log *slog.Logger) *OsqueryCollector {
	collectors := make(map[string]singleQueryCollector)
	for _, c := range m.Counters {
		log.Info("adding collector", "name", c.String())
		collectors[c.Id()] = c
	}
	for _, cv := range m.CounterVecs {
		log.Info("adding collector", "name", cv.String())
		collectors[cv.Id()] = cv
	}
	for _, g := range m.Gauges {
		log.Info("adding collector", "name", g.String())
		collectors[g.Id()] = g
	}
	for _, gv := range m.GaugeVecs {
		log.Info("adding collector", "name", gv.String())
		collectors[gv.Id()] = gv
	}
	return &OsqueryCollector{
		runner:     r,
		collectors: collectors,
		log:        log,
		queryDurations: prometheus.NewSummaryVec(
			prometheus.SummaryOpts{
				Namespace: "osquery_exporter",
				Name:      "query_duration_seconds",
				Help:      "Duration of osquery query execution in seconds",
			},
			[]string{"name"}),
		success: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "osquery_exporter",
				Name:      "query_success",
				Help:      "Query execution status (1 = success, 0 = error)",
			},
			[]string{"name"},
		),
		resultsets: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "osquery_exporter",
				Name:      "resultsets",
				Help:      "Number of query result sets",
			},
			[]string{"name"},
		),
	}
}

// Describe implements prometheus.Collector
func (c *OsqueryCollector) Describe(ch chan<- *prometheus.Desc) {
	c.queryDurations.Describe(ch)
	c.success.Describe(ch)
	c.resultsets.Describe(ch)
}

// Collect implements prometheus.Collector
func (c *OsqueryCollector) Collect(ch chan<- prometheus.Metric) {
	wg := sync.WaitGroup{}
	wg.Add(len(c.collectors))
	for _, col := range c.collectors {
		go func(col singleQueryCollector) {
			defer wg.Done()
			result, err := c.runner.Run(col.Query())
			if err != nil {
				c.log.Error("failed to run query", "query", col.Query(), "error", err)
				c.success.WithLabelValues(col.String()).Set(0.0)
				return
			}
			c.resultsets.WithLabelValues(col.String()).Set(float64(len(result.Items)))
			if err := update(col, result, ch); err != nil {
				c.log.Warn("metric update error", "metric", col.String(), "error", err)
				c.success.WithLabelValues(col.String()).Set(0.0)
				return
			}
			c.log.Debug("query finished", "metric", col.String(), "duration", result.Runtime)
			c.queryDurations.WithLabelValues(col.String()).Observe(result.Runtime.Seconds())
			c.success.WithLabelValues(col.String()).Set(1.0)
		}(col)
	}
	c.queryDurations.Collect(ch)
	c.success.Collect(ch)
	c.resultsets.Collect(ch)
	wg.Wait()
}
