package collector

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
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
	seen := make(map[string]struct{}, len(result.Items))

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
		// A duplicate label set would produce two series with identical labels.
		// Under promhttp.ContinueOnError that surfaces as a 200 with one row
		// silently dropped while query_success reports 1, so detect it here and
		// fail the metric instead.
		key := strings.Join(labels, "\x00")
		if _, dup := seen[key]; dup {
			return nil, metricError{msg: fmt.Sprintf("query %q returned duplicate label set %v; add the label columns to GROUP BY or widen labelidentifier", sqc.Query(), labels)}
		}
		seen[key] = struct{}{}

		m, err := prometheus.NewConstMetric(desc, valueType, valueAsFloat, labels...)
		if err != nil {
			return nil, metricError{msg: fmt.Sprintf("cannot build metric for query %q: %v", sqc.Query(), err)}
		}
		metrics = append(metrics, m)
	}
	return metrics, nil
}

// queryGroup is a set of metrics that share the same osquery SQL. Running the
// query once produces a result that is fed to every metric in the group.
type queryGroup struct {
	query   string
	metrics []singleQueryCollector
}

// OsqueryCollector represents a collector that collects metrics from a set of osquery queries. It implements
// prometheus Collector
type OsqueryCollector struct {
	runner          Runner
	collectors      map[string]singleQueryCollector
	groups          map[string]*queryGroup
	cache           *queryCache
	defaultCacheTTL time.Duration
	log             *slog.Logger
	queryDurations  *prometheus.SummaryVec
	success         *prometheus.GaugeVec
	resultsets      *prometheus.GaugeVec
	cacheHits       *prometheus.CounterVec
	cacheMisses     *prometheus.CounterVec
}

// reservedNames are the exporter's internal metric names. A config metric with
// one of these names would collide with the internal series and panic
// prometheus.MustRegister with an opaque message, so reject it at construction
// with a readable error instead.
var reservedNames = map[string]struct{}{
	"query_duration_seconds":   {},
	"query_success":            {},
	"resultsets":               {},
	"query_cache_hits_total":   {},
	"query_cache_misses_total": {},
}

// NewOsqueryCollectorOptions contains optional arguments for NewOsqueryCollector.
type NewOsqueryCollectorOptions struct {
	DefaultCacheTTL time.Duration
}

// NewOsqueryCollector creates an OsQueryCollector from a given osquery-runner and a set of metric definitions.
// It fails fast if the config contains duplicate metric names or invalid metric descriptors.
func NewOsqueryCollector(r Runner, m model.Metrics, log *slog.Logger, opts ...NewOsqueryCollectorOptions) (*OsqueryCollector, error) {
	collectors := make(map[string]singleQueryCollector)
	groups := make(map[string]*queryGroup)

	add := func(c singleQueryCollector) error {
		name := c.String()
		if name == "" {
			return fmt.Errorf("metric name cannot be empty")
		}
		if _, bad := reservedNames[name]; bad {
			return fmt.Errorf("metric name %q is reserved by the exporter", name)
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

		g, ok := groups[c.Query()]
		if !ok {
			g = &queryGroup{query: c.Query()}
			groups[c.Query()] = g
		}
		g.metrics = append(g.metrics, c)
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

	opt := NewOsqueryCollectorOptions{}
	if len(opts) > 0 {
		opt = opts[0]
	}

	return &OsqueryCollector{
		runner:          r,
		collectors:      collectors,
		groups:          groups,
		cache:           newQueryCache(),
		defaultCacheTTL: opt.DefaultCacheTTL,
		log:             log,
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
		cacheHits: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "osquery_exporter",
				Name:      "query_cache_hits_total",
				Help:      "Total number of query cache hits",
			},
			[]string{"name"},
		),
		cacheMisses: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "osquery_exporter",
				Name:      "query_cache_misses_total",
				Help:      "Total number of query cache misses",
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
	c.cacheHits.Describe(ch)
	c.cacheMisses.Describe(ch)
}

// queryCacheTTL returns the effective TTL for a query group. Only the global
// default is supported today. A zero or negative TTL disables caching.
func (c *OsqueryCollector) queryCacheTTL(g *queryGroup) (time.Duration, bool) {
	if c.defaultCacheTTL <= 0 {
		return 0, false
	}
	return c.defaultCacheTTL, true
}

// Collect implements prometheus.Collector
func (c *OsqueryCollector) Collect(ch chan<- prometheus.Metric) {
	wg := sync.WaitGroup{}
	wg.Add(len(c.groups))
	for _, g := range c.groups {
		go func(g *queryGroup) {
			defer wg.Done()

			begin := time.Now()
			ttl, useCache := c.queryCacheTTL(g)

			var result *model.OsqueryResult
			var err error
			var cacheHit bool
			if useCache {
				result, cacheHit, err = c.cache.runOrWait(context.Background(), g.query, ttl, func(ctx context.Context) (*model.OsqueryResult, error) {
					return c.runner.Run(ctx, g.query)
				})
			} else {
				result, err = c.runner.Run(context.Background(), g.query)
			}

			if err != nil {
				c.log.Error("failed to run query", "query", g.query, "error", err)
				for _, col := range g.metrics {
					c.success.WithLabelValues(col.String()).Set(0.0)
					c.resultsets.WithLabelValues(col.String()).Set(0.0)
					c.queryDurations.WithLabelValues(col.String()).Observe(time.Since(begin).Seconds())
				}
				return
			}

			for _, col := range g.metrics {
				if cacheHit {
					c.cacheHits.WithLabelValues(col.String()).Inc()
				} else {
					c.cacheMisses.WithLabelValues(col.String()).Inc()
				}
			}

			resultset := len(result.Items)
			for _, col := range g.metrics {
				c.collectFromResult(begin, col, result, resultset, ch)
			}
		}(g)
	}
	wg.Wait()
	c.queryDurations.Collect(ch)
	c.success.Collect(ch)
	c.resultsets.Collect(ch)
	c.cacheHits.Collect(ch)
	c.cacheMisses.Collect(ch)
}

func (c *OsqueryCollector) collectFromResult(begin time.Time, col singleQueryCollector, result *model.OsqueryResult, resultset int, ch chan<- prometheus.Metric) {
	defer func() {
		if r := recover(); r != nil {
			c.log.Error("collector panic", "metric", col.String(), "panic", r)
			c.success.WithLabelValues(col.String()).Set(0.0)
		}
	}()

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
	c.resultsets.WithLabelValues(col.String()).Set(float64(resultset))
	c.queryDurations.WithLabelValues(col.String()).Observe(result.Runtime.Seconds())
	c.success.WithLabelValues(col.String()).Set(1.0)
}
