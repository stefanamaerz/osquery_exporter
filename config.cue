// config.cue is the authoritative schema for osquery_exporter YAML config.
//
// It is validated in CI via `tools/validate-cue.sh` (GitHub Actions) and in
// `model/cue_test.go`. Runtime validation is intentionally kept in Go code
// (model/ResolveQueryRefs, osquery.NewThriftRunner, etc.) so startup does not
// depend on the CUE toolchain.
package config

import "time"

#Config: {
	runtime: #Runtime
	queries?: [...#NamedQuery]
	metrics: #Metrics
}

#Runtime: {
	// Absolute path to the osqueryd Thrift extension socket.
	socket_path: string & !=""

	// Query timeout. This bounds both socket wait time and query execution.
	timeout: #Duration

	// Optional: cache query results for this duration. A value of 0 disables
	// caching.
	cache_ttl?: #Duration
}

#NamedQuery: {
	name: string & !=""
	query: string & !=""
	cache_ttl?: #Duration
}

#Metrics: {
	counters?: [...#Metric]
	countervecs?: [...#MetricVec]
	gauges?: [...#Metric]
	gaugevecs?: [...#MetricVec]
}

#BaseMetric: {
	name: string & !=""
	help: string & !=""
	valueidentifier: string & !=""
	cache_ttl?: #Duration
}

#InlineMetric: {
	#BaseMetric
	query: string & !=""
}

#RefMetric: {
	#BaseMetric
	queryref: string & !=""
}

#Metric: #InlineMetric | #RefMetric

#MetricVec: {
	#Metric
	labelidentifier: [...string] & !=[]
}

// #Duration is a Go time.Duration string such as "10s" or "5m".
#Duration: string & time.Duration
