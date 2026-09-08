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

// metricDefinition represents any configured metric once normalized into a
// common shape used by the collector.
type metricDefinition struct {
	name       string
	query      string
	valueKey   string
	labels     []string
	valueType  prometheus.ValueType
	desc       *prometheus.Desc
	cacheTTL   string
	sourceType string
}

func newMetricDefinition(sourceType string, name, query, valueKey, help, cacheTTL string, labels []string, valueType prometheus.ValueType) metricDefinition {
	labelNames := labels
	if labelNames == nil {
		labelNames = []string{}
	}
	return metricDefinition{
		name:       name,
		query:      query,
		valueKey:   valueKey,
		labels:     labelNames,
		valueType:  valueType,
		desc:       prometheus.NewDesc(prometheus.BuildFQName("osquery_exporter", "", name), help, labelNames, nil),
		cacheTTL:   cacheTTL,
		sourceType: sourceType,
	}
}

func emitMetrics(m metricDefinition, result *model.OsqueryResult) ([]prometheus.Metric, error) {
	// metrics with no labels can only accept one result set
	if len(m.labels) == 0 && len(result.Items) > 1 {
		return nil, metricError{msg: "metrics with no labels can only accept one result set"}
	}

	metrics := make([]prometheus.Metric, 0, len(result.Items))
	seen := make(map[string]struct{}, len(result.Items))

	for _, item := range result.Items {
		value, ok := item[m.valueKey]
		if !ok {
			return nil, metricError{msg: fmt.Sprintf("query %q doesn't contain value key %q", m.query, m.valueKey)}
		}
		valueAsFloat, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return nil, metricError{msg: fmt.Sprintf("query %q result %q can't be converted to float: %v", m.query, value, err)}
		}
		labels := make([]string, 0, len(m.labels))
		for _, labelKey := range m.labels {
			if label, ok := item[labelKey]; ok {
				labels = append(labels, label)
			} else {
				return nil, metricError{msg: fmt.Sprintf("query %q doesn't contain a label key %q", m.query, labelKey)}
			}
		}
		// A duplicate label set would produce two series with identical labels.
		// Under promhttp.ContinueOnError that surfaces as a 200 with one row
		// silently dropped while query_success reports 1, so detect it here and
		// fail the metric instead.
		key := strings.Join(labels, "\x00")
		if _, dup := seen[key]; dup {
			return nil, metricError{msg: fmt.Sprintf("query %q returned duplicate label set %v; add the label columns to GROUP BY or widen labelidentifier", m.query, labels)}
		}
		seen[key] = struct{}{}

		metric, err := prometheus.NewConstMetric(m.desc, m.valueType, valueAsFloat, labels...)
		if err != nil {
			return nil, metricError{msg: fmt.Sprintf("cannot build metric for query %q: %v", m.query, err)}
		}
		metrics = append(metrics, metric)
	}
	return metrics, nil
}

// queryGroup is a set of metrics that share the same osquery SQL. Running the
// query once produces a result that is fed to every metric in the group.
type queryGroup struct {
	query    string
	cacheTTL time.Duration
	metrics  []metricDefinition
}

// OsqueryCollector represents a collector that collects metrics from a set of osquery queries. It implements
// prometheus Collector
type OsqueryCollector struct {
	ctx             context.Context
	runner          Runner
	groups          map[string]*queryGroup
	cache           *queryCache
	defaultCacheTTL time.Duration
	scrapeTimeout   time.Duration
	log             *slog.Logger
	queryDurations   *prometheus.SummaryVec
	success          *prometheus.GaugeVec
	resultsets       *prometheus.GaugeVec
	executions       *prometheus.CounterVec
	cacheHits        *prometheus.CounterVec
	cacheMisses      *prometheus.CounterVec
}

// reservedNames are the exporter's internal metric names. A config metric with
// one of these names would collide with the internal series and panic
// prometheus.MustRegister with an opaque message, so reject it at construction
// with a readable error instead.
var reservedNames = map[string]struct{}{
	"query_duration_seconds":   {},
	"query_success":            {},
	"resultsets":               {},
	"query_executions_total":   {},
	"query_cache_hits_total":   {},
	"query_cache_misses_total": {},
}

// NewOsqueryCollector creates an OsQueryCollector from a given osquery-runner and a set of metric definitions.
// It fails fast if the config contains duplicate metric names or invalid metric descriptors.
func NewOsqueryCollector(ctx context.Context, r Runner, m model.Metrics, log *slog.Logger, defaultCacheTTL, scrapeTimeout time.Duration) (*OsqueryCollector, error) {
	groups := make(map[string]*queryGroup)
	names := make(map[string]struct{})

	add := func(def metricDefinition) error {
		if def.name == "" {
			return fmt.Errorf("metric name cannot be empty")
		}
		if _, bad := reservedNames[def.name]; bad {
			return fmt.Errorf("metric name %q is reserved by the exporter", def.name)
		}
		if def.query == "" {
			return fmt.Errorf("metric %q: query cannot be empty", def.name)
		}
		if def.valueKey == "" {
			return fmt.Errorf("metric %q: valueidentifier cannot be empty", def.name)
		}
		if _, dup := names[def.name]; dup {
			return fmt.Errorf("duplicate metric name %q in config", def.name)
		}
		if err := def.desc.Err(); err != nil {
			return fmt.Errorf("metric %q: invalid descriptor: %w", def.name, err)
		}
		names[def.name] = struct{}{}

		var metricTTL time.Duration
		if def.cacheTTL != "" {
			ttl, err := time.ParseDuration(def.cacheTTL)
			if err != nil {
				return fmt.Errorf("metric %q: invalid cache_ttl %q: %w", def.name, def.cacheTTL, err)
			}
			if ttl < 0 {
				return fmt.Errorf("metric %q: negative cache_ttl %v", def.name, ttl)
			}
			metricTTL = ttl
		}

		g, ok := groups[def.query]
		if !ok {
			g = &queryGroup{query: def.query, cacheTTL: metricTTL}
			groups[def.query] = g
		} else if metricTTL > 0 {
			if g.cacheTTL > 0 && g.cacheTTL != metricTTL {
				return fmt.Errorf("metric %q: conflicting cache_ttl for query %q", def.name, g.query)
			}
			g.cacheTTL = metricTTL
		}
		g.metrics = append(g.metrics, def)
		return nil
	}

	for _, c := range m.Counters {
		log.Info("adding collector", "name", c.String())
		if err := add(newMetricDefinition("counter", c.String(), c.Query(), c.Value(), c.Help, c.CacheTTLString(), c.Labels(), c.ValueType())); err != nil {
			return nil, err
		}
	}
	for _, cv := range m.CounterVecs {
		log.Info("adding collector", "name", cv.String())
		if err := add(newMetricDefinition("countervec", cv.String(), cv.Query(), cv.Value(), cv.Help, cv.CacheTTLString(), cv.Labels(), cv.ValueType())); err != nil {
			return nil, err
		}
	}
	for _, g := range m.Gauges {
		log.Info("adding collector", "name", g.String())
		if err := add(newMetricDefinition("gauge", g.String(), g.Query(), g.Value(), g.Help, g.CacheTTLString(), g.Labels(), g.ValueType())); err != nil {
			return nil, err
		}
	}
	for _, gv := range m.GaugeVecs {
		log.Info("adding collector", "name", gv.String())
		if err := add(newMetricDefinition("gaugevec", gv.String(), gv.Query(), gv.Value(), gv.Help, gv.CacheTTLString(), gv.Labels(), gv.ValueType())); err != nil {
			return nil, err
		}
	}

	return &OsqueryCollector{
		ctx:             ctx,
		runner:          r,
		groups:          groups,
		cache:           newQueryCache(),
		defaultCacheTTL: defaultCacheTTL,
		scrapeTimeout:   scrapeTimeout,
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
		executions: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "osquery_exporter",
				Name:      "query_executions_total",
				Help:      "Total number of actual osquery executions",
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
	for _, g := range c.groups {
		for _, m := range g.metrics {
			ch <- m.desc
		}
	}
	c.queryDurations.Describe(ch)
	c.success.Describe(ch)
	c.resultsets.Describe(ch)
	c.executions.Describe(ch)
	c.cacheHits.Describe(ch)
	c.cacheMisses.Describe(ch)
}

// Collect implements prometheus.Collector
func (c *OsqueryCollector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(c.ctx, c.scrapeTimeout)
	defer cancel()

	wg := sync.WaitGroup{}
	wg.Add(len(c.groups))
	for _, g := range c.groups {
		go func(g *queryGroup) {
			defer wg.Done()

			begin := time.Now()
			ttl, useCache := g.cacheTTL, g.cacheTTL > 0
			if !useCache {
				ttl, useCache = c.defaultCacheTTL, c.defaultCacheTTL > 0
			}

			var result *model.OsqueryResult
			var err error
			var cacheHit, executed bool
			if useCache {
				result, cacheHit, executed, err = c.cache.runOrWait(ctx, g.query, ttl, func(runCtx context.Context) (*model.OsqueryResult, error) {
					return c.runner.Run(runCtx, g.query)
				})
			} else {
				result, err = c.runner.Run(ctx, g.query)
				executed = true
			}

			// Account once per query group, using the first metric name as the
			// representative label. All metrics in the group share the same query.
			representative := ""
			if len(g.metrics) > 0 {
				representative = g.metrics[0].name
			}
			if representative != "" {
				if cacheHit {
					c.cacheHits.WithLabelValues(representative).Inc()
				} else {
					c.cacheMisses.WithLabelValues(representative).Inc()
					if executed {
						c.executions.WithLabelValues(representative).Inc()
					}
				}
			}

			if err != nil {
				c.log.Error("failed to run query", "query", g.query, "error", err)
				for _, col := range g.metrics {
					c.success.WithLabelValues(col.name).Set(0.0)
					c.resultsets.WithLabelValues(col.name).Set(0.0)
					c.queryDurations.WithLabelValues(col.name).Observe(time.Since(begin).Seconds())
				}
				return
			}

			resultset := len(result.Items)
			for _, col := range g.metrics {
				c.collectFromResult(begin, col, result, resultset, executed, ch)
			}
		}(g)
	}
	wg.Wait()
	c.queryDurations.Collect(ch)
	c.success.Collect(ch)
	c.resultsets.Collect(ch)
	c.executions.Collect(ch)
	c.cacheHits.Collect(ch)
	c.cacheMisses.Collect(ch)
}

func (c *OsqueryCollector) collectFromResult(begin time.Time, m metricDefinition, result *model.OsqueryResult, resultset int, executed bool, ch chan<- prometheus.Metric) {
	defer func() {
		if r := recover(); r != nil {
			c.log.Error("collector panic", "metric", m.name, "panic", r)
			c.success.WithLabelValues(m.name).Set(0.0)
		}
	}()

	metrics, err := emitMetrics(m, result)
	if err != nil {
		c.log.Warn("metric update error", "metric", m.name, "error", err)
		c.success.WithLabelValues(m.name).Set(0.0)
		c.resultsets.WithLabelValues(m.name).Set(0.0)
		if executed {
			c.queryDurations.WithLabelValues(m.name).Observe(time.Since(begin).Seconds())
		}
		return
	}

	for _, metric := range metrics {
		ch <- metric
	}

	c.log.Debug("query finished", "metric", m.name, "duration", result.Runtime)
	c.resultsets.WithLabelValues(m.name).Set(float64(resultset))
	if executed {
		c.queryDurations.WithLabelValues(m.name).Observe(result.Runtime.Seconds())
	}
	c.success.WithLabelValues(m.name).Set(1.0)
}

// newMetricError wraps errors that should be reported to the user through the
// metric's success gauge instead of crashing the collector.
type metricError struct {
	msg string
}

func (e metricError) Error() string { return e.msg }
