package model

import (
	"strings"
	"testing"
)

func TestValidateReadOnlyQueryValid(t *testing.T) {
	valid := []string{
		"SELECT 1",
		"  select count(*) from t  ",
		"SELECT a, b FROM t WHERE x = 'delete'",
		"WITH cte AS (SELECT 1) SELECT * FROM cte",
		"-- leading comment\nSELECT 1",
		"/* block comment */ SELECT 1",
		"SELECT /* inline */ 1",
	}
	for _, q := range valid {
		t.Run(q, func(t *testing.T) {
			if err := validateReadOnlyQuery(q); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidateReadOnlyQueryInvalid(t *testing.T) {
	cases := []struct {
		name  string
		query string
		want  string
	}{
		{"empty", "", "query is empty"},
		{"insert", "INSERT INTO t VALUES (1)", "mutating keyword"},
		{"update", "UPDATE t SET x = 1", "mutating keyword"},
		{"delete", "DELETE FROM t", "mutating keyword"},
		{"drop", "DROP TABLE t", "mutating keyword"},
		{"create", "CREATE TABLE t (x INT)", "mutating keyword"},
		{"alter", "ALTER TABLE t ADD COLUMN x INT", "mutating keyword"},
		{"truncate", "TRUNCATE TABLE t", "mutating keyword"},
		{"attach", "ATTACH DATABASE 'x' AS y", "mutating keyword"},
		{"detach", "DETACH DATABASE x", "mutating keyword"},
		{"pragma", "PRAGMA journal_mode", "mutating keyword"},
		{"multistatement", "SELECT 1; DROP TABLE t", "semicolon"},
		{"not select", "SHOW TABLES", "must be a SELECT"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateReadOnlyQuery(tc.query)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}

func TestResolveQueryRefsValidatesQueries(t *testing.T) {
	cfg := &Config{
		OsQueryRuntime: OsQueryRuntime{SocketPath: "/var/run/osquery/osquery.em", Timeout: "10s"},
		Queries: []Query{
			{Name: "bad", Query: "DROP TABLE foo"},
		},
	}
	if err := ResolveQueryRefs(cfg); err == nil {
		t.Fatal("expected error for mutating shared query")
	}
}

func TestResolveQueryRefsValidatesMetricQueries(t *testing.T) {
	cfg := &Config{
		OsQueryRuntime: OsQueryRuntime{SocketPath: "/var/run/osquery/osquery.em", Timeout: "10s"},
		Metrics: Metrics{
			Gauges: []Gauge{
				{Metric: Metric{Name: "bad", Help: "h", Querystring: "DELETE FROM foo", ValueIdentifier: "x"}},
			},
		},
	}
	if err := ResolveQueryRefs(cfg); err == nil {
		t.Fatal("expected error for mutating metric query")
	}
}
