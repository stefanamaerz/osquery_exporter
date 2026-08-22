package collector

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stefanamaerz/osquery_exporter/model"
)

// Runner executes an osquery SQL query and returns the parsed result.
type Runner interface {
	Run(ctx context.Context, query string) (*model.OsqueryResult, error)
}

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

// newMetricError wraps errors that should be reported to the user through the
// metric's success gauge instead of crashing the collector.
type metricError struct {
	msg string
}

func (e metricError) Error() string { return e.msg }

func emitMetrics(sqc singleQueryCollector, result *model.OsqueryResult) ([]prometheus.Metric, error) {
	// metrics with no labels can only accept one result set
	if len(sqc.Labels()) == 0 && len(result.Items) > 1 {
		return nil, metricError{msg: "metrics with no labels can only accept one result set"}
	}

	desc := sqc.Desc()
	valueType := sqc.ValueType()
	metrics := make([]prometheus.Metric, 0, len(result.Items))

	for _, item := range result.Items {
		value, ok := item[sqc.Value()]
		if !ok {
			return nil, metricError{msg: fmt.Sprintf("query %q doesn't contain value key %q", sqc.Query(), sqc.Value())}
		}
		valueAsFloat, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return nil, metricError{msg: fmt.Sprintf("query %q result %q can't be converted to float: %v", sqc.Query(), value, err)}
		}
		labels := make([]string, 0, len(sqc.Labels()))
		for _, labelIdentifier := range sqc.Labels() {
			if label, ok := item[labelIdentifier]; ok {
				labels = append(labels, label)
			} else {
				return nil, metricError{msg: fmt.Sprintf("query %q doesn't contain a label key %q", sqc.Query(), labelIdentifier)}
			}
		}
		m, err := prometheus.NewConstMetric(desc, valueType, valueAsFloat, labels...)
		if err != nil {
			return nil, metricError{msg: fmt.Sprintf("cannot build metric for query %q: %v", sqc.Query(), err)}
		}
		metrics = append(metrics, m)
	}
	return metrics, nil
}

// OsqueryCollector represents a collector that collects metrics from a set of osquery queries. It implements
// prometheus Collector
type OsqueryCollector struct {
	runner         Runner
	collectors     map[string]singleQueryCollector
	log            *slog.Logger
	queryDurations *prometheus.SummaryVec
	success        *prometheus.GaugeVec
	resultsets     *prometheus.GaugeVec
}

// NewOsqueryCollector creates an OsQueryCollector from a given osquery-runner and a set of metric definitions.
// It fails fast if the config contains duplicate metric names or invalid metric descriptors.
func NewOsqueryCollector(r Runner, m model.Metrics, log *slog.Logger) (*OsqueryCollector, error) {
	collectors := make(map[string]singleQueryCollector)
	add := func(c singleQueryCollector) error {
		name := c.String()
		if name == "" {
			return fmt.Errorf("metric name cannot be empty")
		}
		if c.Query() == "" {
			return fmt.Errorf("metric %q: query cannot be empty", name)
		}
		if c.Value() == "" {
			return fmt.Errorf("metric %q: valueidentifier cannot be empty", name)
		}
		if _, dup := collectors[name]; dup {
			return fmt.Errorf("duplicate metric name %q in config", name)
		}
		if err := c.Desc().Err(); err != nil {
			return fmt.Errorf("metric %q: invalid descriptor: %w", name, err)
		}
		collectors[name] = c
		return nil
	}

	for _, c := range m.Counters {
		log.Info("adding collector", "name", c.String())
		if err := add(c); err != nil {
			return nil, err
		}
	}
	for _, cv := range m.CounterVecs {
		log.Info("adding collector", "name", cv.String())
		if err := add(cv); err != nil {
			return nil, err
		}
	}
	for _, g := range m.Gauges {
		log.Info("adding collector", "name", g.String())
		if err := add(g); err != nil {
			return nil, err
		}
	}
	for _, gv := range m.GaugeVecs {
		log.Info("adding collector", "name", gv.String())
		if err := add(gv); err != nil {
			return nil, err
		}
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
	}, nil
}

// Describe implements prometheus.Collector
func (c *OsqueryCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, col := range c.collectors {
		ch <- col.Desc()
	}
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
			defer func() {
				if r := recover(); r != nil {
					c.log.Error("collector panic", "metric", col.String(), "panic", r)
					c.success.WithLabelValues(col.String()).Set(0.0)
				}
				wg.Done()
			}()

			begin := time.Now()
			result, err := c.runner.Run(context.Background(), col.Query())
			if err != nil {
				c.log.Error("failed to run query", "query", col.Query(), "error", err)
				c.success.WithLabelValues(col.String()).Set(0.0)
				c.resultsets.WithLabelValues(col.String()).Set(0.0)
				c.queryDurations.WithLabelValues(col.String()).Observe(time.Since(begin).Seconds())
				return
			}

			metrics, err := emitMetrics(col, result)
			if err != nil {
				c.log.Warn("metric update error", "metric", col.String(), "error", err)
				c.success.WithLabelValues(col.String()).Set(0.0)
				c.resultsets.WithLabelValues(col.String()).Set(0.0)
				c.queryDurations.WithLabelValues(col.String()).Observe(time.Since(begin).Seconds())
				return
			}

			for _, m := range metrics {
				ch <- m
			}

			c.log.Debug("query finished", "metric", col.String(), "duration", result.Runtime)
			c.resultsets.WithLabelValues(col.String()).Set(float64(len(result.Items)))
			c.queryDurations.WithLabelValues(col.String()).Observe(result.Runtime.Seconds())
			c.success.WithLabelValues(col.String()).Set(1.0)
		}(col)
	}
	wg.Wait()
	c.queryDurations.Collect(ch)
	c.success.Collect(ch)
	c.resultsets.Collect(ch)
}
